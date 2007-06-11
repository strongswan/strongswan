/**
 * @file sender.c
 *
 * @brief Implementation of sender_t.
 *
 */

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
	pthread_mutex_t mutex;

	/**
	 * condvar to signal for packets in list
	 */
	pthread_cond_t condvar;
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
	
	pthread_mutex_lock(&this->mutex);
	this->list->insert_last(this->list, packet);
	pthread_mutex_unlock(&this->mutex);
	pthread_cond_signal(&this->condvar);
}

/**
 * Implementation of private_sender_t.send_packets.
 */
static job_requeue_t send_packets(private_sender_t * this)
{
	packet_t *packet;
	int oldstate;
	
	pthread_mutex_lock(&this->mutex);
	while (this->list->get_count(this->list) == 0)
	{
		/* add cleanup handler, wait for packet, remove cleanup handler */
		pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&this->mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		
		pthread_cond_wait(&this->condvar, &this->mutex);
		
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
	}
	this->list->remove_first(this->list, (void**)&packet);
	pthread_mutex_unlock(&this->mutex);
	
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
	while (this->list->get_count(this->list))
	{
		sched_yield();
	}
	this->job->cancel(this->job);
	this->list->destroy(this->list);
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
	pthread_mutex_init(&this->mutex, NULL);
	pthread_cond_init(&this->condvar, NULL);

	this->job = callback_job_create((callback_job_cb_t)send_packets,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}

