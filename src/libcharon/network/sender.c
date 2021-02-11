/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * HSR Hochschule fuer Technik Rapperswil
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

/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <unistd.h>
#include <stdlib.h>

#include "sender.h"

#include <daemon.h>
#include <network/socket.h>
#include <processing/jobs/callback_job.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>


typedef struct private_sender_t private_sender_t;

/**
 * Private data of a sender_t object.
 */
struct private_sender_t {
	/**
	 * Public part of a sender_t object.
	 */
	sender_t public;

	/**
	 * The packets are stored in a linked list
	 */
	linked_list_t *list;

	/**
	 * mutex to synchronize access to list
	 */
	mutex_t *mutex;
	
	mutex_t *wakeup_mutex;
	
	int	sender_thread_count;

	/**
	 * condvar to signal for packets added to list
	 */
	condvar_t *got;

	/**
	 * condvar to signal for packets sent
	 */
	condvar_t *sent;

	/**
	 * Delay for sending outgoing packets, to simulate larger RTT
	 */
	int send_delay;

	/**
	 * Specific message type to delay, 0 for any
	 */
	int send_delay_type;

	/**
	 * Delay request messages?
	 */
	bool send_delay_request;

	/**
	 * Delay response messages?
	 */
	bool send_delay_response;
};

METHOD(sender_t, send_no_marker, void,
	private_sender_t *this, packet_t *packet)
{
	this->mutex->lock(this->mutex);
	this->list->insert_last(this->list, packet);
	this->got->signal(this->got);
	this->mutex->unlock(this->mutex);
}

METHOD(sender_t, send_, void,
	private_sender_t *this, packet_t *packet)
{
	host_t *src, *dst;

	src = packet->get_source(packet);
	dst = packet->get_destination(packet);

	DBG1(DBG_NET, "sending packet: from %#H to %#H (%zu bytes)", src, dst,
		 packet->get_data(packet).len);

	if (this->send_delay)
	{
		message_t *message;

		message = message_create_from_packet(packet->clone(packet));
		if (message->parse_header(message) == SUCCESS)
		{
			if (this->send_delay_type == 0 ||
				this->send_delay_type == message->get_exchange_type(message))
			{
				if ((message->get_request(message) && this->send_delay_request) ||
					(!message->get_request(message) && this->send_delay_response))
				{
					DBG1(DBG_NET, "using send delay: %dms", this->send_delay);
					usleep(this->send_delay * 1000);
				}
			}
		}
		message->destroy(message);
	}

	/* if neither source nor destination port is 500 we add a Non-ESP marker */
	if (dst->get_port(dst) != IKEV2_UDP_PORT &&
		src->get_port(src) != IKEV2_UDP_PORT)
	{
		chunk_t data, marker = chunk_from_chars(0x00, 0x00, 0x00, 0x00);

		data = chunk_cat("cc", marker, packet->get_data(packet));
		packet->set_data(packet, data);
	}

	send_no_marker(this, packet);
}

/**
 * Job callback function to send packets
 */
static job_requeue_t send_packets(private_sender_t *this)
{
	packet_t *packet;
	bool oldstate;
	bool got_wakeup_mutex = false;

	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list) == 0)
	{
		/* add cleanup handler, wait for packet, remove cleanup handler */
		thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
		oldstate = thread_cancelability(TRUE);

		this->got->wait(this->got, this->mutex);
		this->wakeup_mutex->lock (this->wakeup_mutex);
		got_wakeup_mutex = true;

		thread_cancelability(oldstate);
		thread_cleanup_pop(FALSE);
		
		// If there is a spurious wakeup and we are the second ones to be awoken,
		// there may be no send to service.  So double check after we get the wakeup lock
		// that there is still something to be serviced
		if (this->list->get_count(this->list) == 0)
		{
			this->wakeup_mutex->unlock (this->wakeup_mutex);
			got_wakeup_mutex = false;
			this->mutex->unlock(this->mutex);
			continue;
		}
	}
	this->list->remove_first(this->list, (void**)&packet);
	this->sent->signal(this->sent);
	if (got_wakeup_mutex)
	{
		this->wakeup_mutex->unlock (this->wakeup_mutex);
	}
	this->mutex->unlock(this->mutex);

	charon->socket->send(charon->socket, packet);
	packet->destroy(packet);
	return JOB_REQUEUE_DIRECT;
}

METHOD(sender_t, flush, void,
	private_sender_t *this)
{
	/* send all packets in the queue */
	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list))
	{
		this->sent->wait(this->sent, this->mutex);
	}
	this->mutex->unlock(this->mutex);
}

METHOD(sender_t, destroy, void,
	private_sender_t *this)
{
	this->list->destroy_offset(this->list, offsetof(packet_t, destroy));
	this->got->destroy(this->got);
	this->sent->destroy(this->sent);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
sender_t * sender_create()
{
	private_sender_t *this;
	int i;

	INIT(this,
		.public = {
			.send = _send_,
			.send_no_marker = _send_no_marker,
			.flush = _flush,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.wakeup_mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.sender_thread_count = lib->settings->get_int(lib->settings,
									"%s.sender_thread_count", 1, lib->ns),
		.got = condvar_create(CONDVAR_TYPE_DEFAULT),
		.sent = condvar_create(CONDVAR_TYPE_DEFAULT),
		.send_delay = lib->settings->get_int(lib->settings,
									"%s.send_delay", 0, lib->ns),
		.send_delay_type = lib->settings->get_int(lib->settings,
									"%s.send_delay_type", 0, lib->ns),
		.send_delay_request = lib->settings->get_bool(lib->settings,
									"%s.send_delay_request", TRUE, lib->ns),
		.send_delay_response = lib->settings->get_bool(lib->settings,
									"%s.send_delay_response", TRUE, lib->ns),
	);

	for (i = 0; i < this->sender_thread_count; i++)
	{
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio((callback_job_cb_t)send_packets,
				this, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	}
	
	return &this->public;
}

