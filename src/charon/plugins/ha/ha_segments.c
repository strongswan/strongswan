/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "ha_segments.h"

#include <pthread.h>

#include <utils/mutex.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>

#define HEARTBEAT_DELAY 1000
#define HEARTBEAT_TIMEOUT 2100

typedef struct private_ha_segments_t private_ha_segments_t;

/**
 * Private data of an ha_segments_t object.
 */
struct private_ha_segments_t {

	/**
	 * Public ha_segments_t interface.
	 */
	ha_segments_t public;

	/**
	 * communication socket
	 */
	ha_socket_t *socket;

	/**
	 * Sync tunnel, if any
	 */
	ha_tunnel_t *tunnel;

	/**
	 * Interface to control segments at kernel level
	 */
	ha_kernel_t *kernel;

	/**
	 * Mutex to lock segment manipulation
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for heartbeats
	 */
	condvar_t *condvar;

	/**
	 * Job checking for heartbeats
	 */
	callback_job_t *job;

	/**
	 * Total number of ClusterIP segments
	 */
	u_int count;

	/**
	 * mask of active segments
	 */
	segment_mask_t active;

	/**
	 * Are we the master node handling segment assignement?
	 */
	bool master;
};

/**
 * Log currently active segments
 */
static void log_segments(private_ha_segments_t *this, bool activated,
						 u_int segment)
{
	char buf[64] = "none", *pos = buf;
	int i;
	bool first = TRUE;

	for (i = 1; i <= this->count; i++)
	{
		if (this->active & SEGMENTS_BIT(i))
		{
			if (first)
			{
				first = FALSE;
			}
			else
			{
				pos += snprintf(pos, buf + sizeof(buf) - pos, ",");
			}
			pos += snprintf(pos, buf + sizeof(buf) - pos, "%d", i);
		}
	}
	DBG1(DBG_CFG, "HA segment %d %sactivated, now active: %s",
		 segment, activated ? "" : "de", buf);
}

/**
 * Enable/Disable a specific segment
 */
static void enable_disable(private_ha_segments_t *this, u_int segment,
						   bool enable, bool notify)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	ike_sa_state_t old, new;
	ha_message_t *message = NULL;
	ha_message_type_t type;
	bool changes = FALSE;

	if (segment > this->count)
	{
		return;
	}

	if (enable)
	{
		old = IKE_PASSIVE;
		new = IKE_ESTABLISHED;
		type = HA_SEGMENT_TAKE;
		if (!(this->active & SEGMENTS_BIT(segment)))
		{
			this->active |= SEGMENTS_BIT(segment);
			this->kernel->activate(this->kernel, segment);
			changes = TRUE;
		}
	}
	else
	{
		old = IKE_ESTABLISHED;
		new = IKE_PASSIVE;
		type = HA_SEGMENT_DROP;
		if (this->active & SEGMENTS_BIT(segment))
		{
			this->active &= ~SEGMENTS_BIT(segment);
			this->kernel->deactivate(this->kernel, segment);
			changes = TRUE;
		}
	}

	if (changes)
	{
		enumerator = charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) != old)
			{
				continue;
			}
			if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
			{
				continue;
			}
			if (this->kernel->in_segment(this->kernel,
									ike_sa->get_other_host(ike_sa), segment))
			{
				ike_sa->set_state(ike_sa, new);
			}
		}
		enumerator->destroy(enumerator);
		log_segments(this, enable, segment);
	}

	if (notify)
	{
		message = ha_message_create(type);
		message->add_attribute(message, HA_SEGMENT, segment);
		this->socket->push(this->socket, message);
	}
}

/**
 * Enable/Disable all or a specific segment, do locking
 */
static void enable_disable_all(private_ha_segments_t *this, u_int segment,
							   bool enable, bool notify)
{
	int i;

	this->mutex->lock(this->mutex);
	if (segment == 0)
	{
		for (i = 1; i <= this->count; i++)
		{
			enable_disable(this, i, enable, notify);
		}
	}
	else
	{
		enable_disable(this, segment, enable, notify);
	}
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of ha_segments_t.activate
 */
static void activate(private_ha_segments_t *this, u_int segment, bool notify)
{
	enable_disable_all(this, segment, TRUE, notify);
}

/**
 * Implementation of ha_segments_t.deactivate
 */
static void deactivate(private_ha_segments_t *this, u_int segment, bool notify)
{
	enable_disable_all(this, segment, FALSE, notify);
}

/**
 * Rekey all children of an IKE_SA
 */
static status_t rekey_children(ike_sa_t *ike_sa)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	status_t status = SUCCESS;

	iterator = ike_sa->create_child_sa_iterator(ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		DBG1(DBG_CFG, "resyncing CHILD_SA");
		status = ike_sa->rekey_child_sa(ike_sa, child_sa->get_protocol(child_sa),
										child_sa->get_spi(child_sa, TRUE));
		if (status == DESTROY_ME)
		{
			break;
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of ha_segments_t.resync
 */
static void resync(private_ha_segments_t *this, u_int segment)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	linked_list_t *list;
	ike_sa_id_t *id;
	u_int16_t mask = SEGMENTS_BIT(segment);

	list = linked_list_create();
	this->mutex->lock(this->mutex);

	if (segment > 0 && segment <= this->count && (this->active & mask))
	{
		this->active &= ~mask;

		DBG1(DBG_CFG, "resyncing HA segment %d", segment);

		/* we do the actual rekeying in a seperate loop to avoid rekeying
		 * an SA twice. */
		enumerator = charon->ike_sa_manager->create_enumerator(
													charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
				this->kernel->in_segment(this->kernel,
									ike_sa->get_other_host(ike_sa), segment))
			{
				id = ike_sa->get_id(ike_sa);
				list->insert_last(list, id->clone(id));
			}
		}
		enumerator->destroy(enumerator);
	}
	this->mutex->unlock(this->mutex);

	while (list->remove_last(list, (void**)&id) == SUCCESS)
	{
		ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, id);
		id->destroy(id);
		if (ike_sa)
		{
			DBG1(DBG_CFG, "resyncing IKE_SA");
			if (ike_sa->rekey(ike_sa) != DESTROY_ME)
			{
				if (rekey_children(ike_sa) != DESTROY_ME)
				{
					charon->ike_sa_manager->checkin(
										charon->ike_sa_manager, ike_sa);
					continue;
				}
			}
			charon->ike_sa_manager->checkin_and_destroy(
										charon->ike_sa_manager, ike_sa);
		}
	}
	list->destroy(list);
}

/**
 * Implementation of listener_t.alert
 */
static bool alert_hook(private_ha_segments_t *this, ike_sa_t *ike_sa,
					   alert_t alert, va_list args)
{
	if (alert == ALERT_SHUTDOWN_SIGNAL)
	{
		deactivate(this, 0, TRUE);
	}
	return TRUE;
}

/**
 * Monitor heartbeat activity of remote node
 */
static job_requeue_t watchdog(private_ha_segments_t *this)
{
	int oldstate;
	bool timeout;

	this->mutex->lock(this->mutex);
	pthread_cleanup_push((void*)this->mutex->unlock, this->mutex);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	timeout = this->condvar->timed_wait(this->condvar, this->mutex,
										HEARTBEAT_TIMEOUT);
	pthread_setcancelstate(oldstate, NULL);
	pthread_cleanup_pop(TRUE);
	if (timeout)
	{
		DBG1(DBG_CFG, "no heartbeat received, taking all segments");
		activate(this, 0, TRUE);
		/* disable heartbeat detection util we get one */
		this->job = NULL;
		return JOB_REQUEUE_NONE;
	}
	return JOB_REQUEUE_DIRECT;
}

/**
 * Start the heartbeat detection thread
 */
static void start_watchdog(private_ha_segments_t *this)
{
	this->job = callback_job_create((callback_job_cb_t)watchdog,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
}

/**
 * Implementation of ha_segments_t.handle_status
 */
static void handle_status(private_ha_segments_t *this, segment_mask_t mask)
{
	segment_mask_t missing;
	int i;

	this->mutex->lock(this->mutex);

	missing = ~(this->active | mask);

	for (i = 1; i <= this->count; i++)
	{
		if (missing & SEGMENTS_BIT(i))
		{
			if (this->master != i % 2)
			{
				DBG1(DBG_CFG, "HA segment %d was not handled, taking", i);
				enable_disable(this, i, TRUE, TRUE);
			}
			else
			{
				DBG1(DBG_CFG, "HA segment %d was not handled, dropping", i);
				enable_disable(this, i, FALSE, TRUE);
			}
		}
	}

	this->mutex->unlock(this->mutex);
	this->condvar->signal(this->condvar);

	if (!this->job)
	{
		DBG1(DBG_CFG, "received heartbeat, reenabling watchdog");
		start_watchdog(this);
	}
}

/**
 * Send a status message with our active segments
 */
static job_requeue_t send_status(private_ha_segments_t *this)
{
	ha_message_t *message;
	int i;

	message = ha_message_create(HA_STATUS);

	for (i = 1; i <= this->count; i++)
	{
		if (this->active & SEGMENTS_BIT(i))
		{
			message->add_attribute(message, HA_SEGMENT, i);
		}
	}

	this->socket->push(this->socket, message);

	/* schedule next invocation */
	charon->scheduler->schedule_job_ms(charon->scheduler, (job_t*)
									callback_job_create((callback_job_cb_t)
										send_status, this, NULL, NULL),
									HEARTBEAT_DELAY);

	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of ha_segments_t.destroy.
 */
static void destroy(private_ha_segments_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	free(this);
}

/**
 * See header
 */
ha_segments_t *ha_segments_create(ha_socket_t *socket, ha_kernel_t *kernel,
					ha_tunnel_t *tunnel, char *local, char *remote, u_int count)
{
	private_ha_segments_t *this = malloc_thing(private_ha_segments_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.alert = (bool(*)(listener_t*, ike_sa_t *, alert_t, va_list))alert_hook;
	this->public.activate = (void(*)(ha_segments_t*, u_int segment,bool))activate;
	this->public.deactivate = (void(*)(ha_segments_t*, u_int segment,bool))deactivate;
	this->public.resync = (void(*)(ha_segments_t*, u_int segment))resync;
	this->public.handle_status = (void(*)(ha_segments_t*, segment_mask_t mask))handle_status;
	this->public.destroy = (void(*)(ha_segments_t*))destroy;

	this->socket = socket;
	this->tunnel = tunnel;
	this->kernel = kernel;
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	this->count = count;
	this->master = strcmp(local, remote) > 0;

	/* initially all segments are deactivated */
	this->active = 0;

	send_status(this);

	start_watchdog(this);

	return &this->public;
}

