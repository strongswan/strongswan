/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stdlib.h>
#include <pthread.h>

#include "sender.h"

#include <daemon.h>
#include <network/socket.h>
#include <processing/jobs/callback_job.h>
#include <utils/mutex.h>


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
	 * Sender threads job.
	 */
	callback_job_t *job;
	 
	/**
	 * The packets are stored in a linked list
	 */
	linked_list_t *list;

	/**
	 * mutex to synchronize access to list
	 */
	mutex_t *mutex;

	/**
	 * condvar to signal for packets added to list
	 */
	condvar_t *got;
	
	/**
	 * condvar to signal for packets sent
	 */
	condvar_t *sent;
};

/**
 * implements sender_t.send
 */
static void send_(private_sender_t *this, packet_t *packet)
{
	host_t *src, *dst;
	
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	DBG1(DBG_NET, "sending packet: from %#H to %#H", src, dst);
	
	this->mutex->lock(this->mutex);
	this->list->insert_last(this->list, packet);
	this->got->signal(this->got);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of private_sender_t.send_packets.
 */
static job_requeue_t send_packets(private_sender_t * this)
{
	packet_t *packet;
	int oldstate;
	
	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list) == 0)
	{
		/* add cleanup handler, wait for packet, remove cleanup handler */
		pthread_cleanup_push((void(*)(void*))this->mutex->unlock, this->mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		
		this->got->wait(this->got, this->mutex);
		
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
	}
	this->list->remove_first(this->list, (void**)&packet);
	this->sent->signal(this->sent);
	this->mutex->unlock(this->mutex);
	
	charon->socket->send(charon->socket, packet);
	packet->destroy(packet);
	return JOB_REQUEUE_DIRECT;
}

/**
 * Implementation of sender_t.destroy.
 */
static void destroy(private_sender_t *this)
{
	/* send all packets in the queue */
	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list))
	{
		this->sent->wait(this->sent, this->mutex);
	}
	this->mutex->unlock(this->mutex);
	this->job->cancel(this->job);
	this->list->destroy(this->list);
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
	private_sender_t *this = malloc_thing(private_sender_t);
	
	this->public.send = (void(*)(sender_t*,packet_t*))send_;
	this->public.destroy = (void(*)(sender_t*)) destroy;
	
	this->list = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	this->got = condvar_create(CONDVAR_DEFAULT);
	this->sent = condvar_create(CONDVAR_DEFAULT);
	
	this->job = callback_job_create((callback_job_cb_t)send_packets,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}

