/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "codel_queue.h"

#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <collections/linked_list.h>

#include <math.h>

typedef struct private_codel_queue_t private_codel_queue_t;

/**
 * Timestamp with "good" resolution
 */
typedef uint64_t timestamp_t;

/**
 * Entry for an packet
 */
typedef struct {
	void *packet;
	timestamp_t stamp;
	u_int len;
} entry_t;

/**
 * Private data of an codel_queue_t object.
 */
struct private_codel_queue_t {

	/**
	 * Public codel_queue_t interface.
	 */
	codel_queue_t public;

	/**
	 * Linked list containing all items in the queue
	 */
	linked_list_t *list;

	/**
	 * Offset of object destructor for queued entry packets
	 */
	int destroy_offset;

	/**
	 * Mutex used to synchronize access to the queue
	 */
	mutex_t *mutex;

	/**
	 * Condvar used to wait for items
	 */
	condvar_t *condvar;

	/**
	 * Time when we'll declare we're above target (0 if below)
	 */
	timestamp_t first_above;

	/**
	 * Time to drop next packet
	 */
	timestamp_t drop_next;

	/**
	 * Packets dropped since going into drop state
	 */
	u_int count;

	/**
	 * Size of queue, in bytes
	 */
	u_int len;

	/**
	 * TRUE if in drop state
	 */
	bool dropping;

	/**
	 * Target queue delay
	 */
	timestamp_t target;

	/**
	 * Sliding minimum time window width
	 */
	timestamp_t interval;

	/**
	 * Maximum packet size in bytes (should use interface MTU)
	 */
	u_int maxpacket;
};

/**
 * Create a timestamp for now
 */
static timestamp_t timestamp_now()
{
	timeval_t tv;

	time_monotonic(&tv);

	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

/**
 * Convert miliseconds to timestamp_now() resolution
 */
static timestamp_t timestamp_from_ms(u_int ms)
{
	return ms * 1000;
}

/**
 * Calculate frequency for dropping
 */
static timestamp_t control_law(private_codel_queue_t *this, timestamp_t t)
{
	return t + this->interval / (timestamp_t)sqrt(this->count);
}

/**
 * Destroy a packet with the destructor offset
 */
static void destroy_packet(private_codel_queue_t *this, void *packet)
{
	void (**method)(void*);

	method = packet + this->destroy_offset;
	(*method)(packet);
}

METHOD(codel_queue_t, enqueue, void,
	private_codel_queue_t *this, void *packet, u_int len)
{
	entry_t *entry;

	INIT(entry,
		.packet = packet,
		.len = len,
		.stamp = timestamp_now(),
	);

	this->mutex->lock(this->mutex);

	this->list->insert_first(this->list, entry);
	this->len += len;

	this->mutex->unlock(this->mutex);

	this->condvar->signal(this->condvar);
}

/**
 * Dequeue an entry
 */
static entry_t* dequeue_entry(private_codel_queue_t *this)
{
	entry_t *entry;
	bool oldstate;

	thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);

	/* ensure that a canceled thread does not dequeue any items */
	thread_cancellation_point();

	while (this->list->remove_last(this->list, (void**)&entry) != SUCCESS)
	{
		/* queue empty, get out of dropping state */
		this->first_above = 0;
		this->dropping = FALSE;

		oldstate = thread_cancelability(TRUE);
		this->condvar->wait(this->condvar, this->mutex);
		thread_cancelability(oldstate);
	}

	thread_cleanup_pop(FALSE);

	return entry;
}

/**
 * CoDelized dequeue of a packet
 */
static void* dequeue_packet(private_codel_queue_t *this, timestamp_t now,
							bool *ok_to_drop)
{
	entry_t *entry;
	timestamp_t sojourn;
	void *packet;

	*ok_to_drop = FALSE;

	entry = dequeue_entry(this);

	this->len -= entry->len;
	sojourn = now - entry->stamp;
	if (sojourn < this->target || this->len < this->maxpacket)
	{
		/* below target delay */
		this->first_above = 0;
	}
	else
	{
		if (this->first_above == 0)
		{
			/* first time above target delay */
			this->first_above = now + this->interval;
		}
		else if (now >= this->first_above)
		{
			/* have been obove target delay for interval */
			*ok_to_drop = TRUE;
		}
	}

	packet = entry->packet;
	free(entry);

	return packet;
}

METHOD(codel_queue_t, dequeue, void*,
	private_codel_queue_t *this)
{
	timestamp_t now;
	bool ok_to_drop;
	void *packet;

	now = timestamp_now();

	this->mutex->lock(this->mutex);

	packet = dequeue_packet(this, now, &ok_to_drop);
	if (this->dropping)
	{
		if (!ok_to_drop)
		{
			/* stop dropping after queue delay got acceptable */
			this->dropping = FALSE;
		}
		else if (now >= this->drop_next)
		{
			/* continue dropping dropping packets more and more aggressively,
			 * until queue delay gets acceptable */
			while (now >= this->drop_next && this->dropping)
			{
				this->count++;
				destroy_packet(this, packet);
				packet = dequeue_packet(this, now, &ok_to_drop);
				if (!ok_to_drop)
				{
					this->dropping = FALSE;
				}
				else
				{
					this->drop_next = control_law(this, this->drop_next);
				}
			}
		}
	}
	else if (ok_to_drop)
	{
		if (now < this->drop_next + this->interval ||
			now >= this->first_above + this->interval)
		{
			/* start dropping packets */
			destroy_packet(this, packet);
			packet = dequeue_packet(this, now, &ok_to_drop);
			this->dropping = TRUE;

			if (now < this->drop_next + this->interval)
			{
				if (this->count > 2)
				{
					this->count -= 2;
				}
				else
				{
					 this->count = 1;
				}
			}
			else
			{
				this->count = 1;
				this->drop_next = control_law(this, now);
			}
		}
	}

	this->mutex->unlock(this->mutex);

	return packet;
}

METHOD(codel_queue_t, destroy, void,
	private_codel_queue_t *this)
{
	entry_t *entry;

	while (this->list->remove_last(this->list, (void**)&entry) == SUCCESS)
	{
		destroy_packet(this, entry->packet);
		free(entry);
	}
	this->list->destroy(this->list);
	this->condvar->destroy(this->condvar);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
codel_queue_t *codel_queue_create(int destroy_offset, u_int mtu)
{
	private_codel_queue_t *this;

	INIT(this,
		.public = {
			.enqueue = _enqueue,
			.dequeue = _dequeue,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.destroy_offset = destroy_offset,
		.maxpacket = mtu,
		.target = timestamp_from_ms(5),
		.interval = timestamp_from_ms(100),
	);

	return &this->public;
}
