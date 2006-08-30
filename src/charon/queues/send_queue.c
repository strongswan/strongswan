/**
 * @file send_queue.c
 *
 * @brief Implementation of send_queue_t.
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

#include <pthread.h>

#include "send_queue.h"

#include <utils/linked_list.h>
#include <utils/logger_manager.h>


typedef struct private_send_queue_t private_send_queue_t;

/**
 * @brief Private Variables and Functions of send_queue class
 *
 */
struct private_send_queue_t {
	/**
	 * Public part of the send_queue_t object
	 */
 	send_queue_t public;

	/**
	 * The packets are stored in a linked list
	 */
	linked_list_t *list;

	/**
	 * access to linked_list is locked through this mutex
	 */
	pthread_mutex_t mutex;

	/**
	 * If the queue is empty a thread has to wait
	 * This condvar is used to wake up such a thread
	 */
	pthread_cond_t condvar;

	/**
	 * Logger reference
	 */
	logger_t *logger;
};

/**
 * implements send_queue_t.get_count
 */
static int get_count(private_send_queue_t *this)
{
	int count;
	pthread_mutex_lock(&this->mutex);
	count = this->list->get_count(this->list);
	pthread_mutex_unlock(&this->mutex);
	return count;
}

/**
 * implements send_queue_t.get
 */
static packet_t *get(private_send_queue_t *this)
{
	int oldstate;
	packet_t *packet;
	
	pthread_mutex_lock(&this->mutex);
	
	/* go to wait while no packets available */
	while(this->list->get_count(this->list) == 0)
	{
		/* add mutex unlock handler for cancellation, enable cancellation */
		pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&this->mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		pthread_cond_wait(&this->condvar, &this->mutex);
		
		/* reset cancellation, remove mutex-unlock handler (without executing) */
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
	}
	this->list->remove_first(this->list, (void**)&packet);
	pthread_mutex_unlock(&this->mutex);
	return packet;
}

/**
 * implements send_queue_t.add
 */
static void add(private_send_queue_t *this, packet_t *packet)
{
	host_t *src, *dst;
	
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	this->logger->log(this->logger, CONTROL, "sending packet: from %s[%d] to %s[%d]",
					  src->get_string(src), src->get_port(src),
					  dst->get_string(dst), dst->get_port(dst));
	
	pthread_mutex_lock(&this->mutex);
	this->list->insert_last(this->list, packet);
	pthread_cond_signal(&this->condvar);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * implements send_queue_t.destroy
 */
static void destroy (private_send_queue_t *this)
{
	packet_t *packet;
	while (this->list->remove_last(this->list, (void**)&packet) == SUCCESS)
	{
		packet->destroy(packet);
	}
	this->list->destroy(this->list);
	pthread_mutex_destroy(&(this->mutex));
	pthread_cond_destroy(&(this->condvar));
	free(this);
}

/*
 *
 * Documented in header
 */
send_queue_t *send_queue_create(void)
{
	private_send_queue_t *this = malloc_thing(private_send_queue_t);
	
	this->public.get_count = (int(*)(send_queue_t*)) get_count;
	this->public.get = (packet_t*(*)(send_queue_t*)) get;
	this->public.add = (void(*)(send_queue_t*, packet_t*)) add;
	this->public.destroy = (void(*)(send_queue_t*)) destroy;

	this->list = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	pthread_cond_init(&this->condvar, NULL);
	this->logger = logger_manager->get_logger(logger_manager, SOCKET);
	
	return (&this->public);
}
