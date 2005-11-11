/**
 * @file send_queue.c
 *
 * @brief Send-Queue based on linked_list_t
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "../utils/allocator.h"
#include "../utils/linked_list.h"

 /**
 * @brief Private Variables and Functions of send_queue class
 *
 */
typedef struct private_send_queue_s private_send_queue_t;


struct private_send_queue_s {
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
};


/**
 * @brief implements function get_count of send_queue_t
 */
static int get_count(private_send_queue_t *this)
{
	int count;
	pthread_mutex_lock(&(this->mutex));
	count = this->list->get_count(this->list);
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

 /**
 * @brief implements function get of send_queue_t
 */
static status_t get(private_send_queue_t *this, packet_t **packet)
{
	int oldstate;
	pthread_mutex_lock(&(this->mutex));
	/* go to wait while no packets available */
	
	while(this->list->get_count(this->list) == 0)
	{
		/* add mutex unlock handler for cancellation, enable cancellation */
		pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		pthread_cond_wait( &(this->condvar), &(this->mutex));

		/* reset cancellation, remove mutex-unlock handler (without executing) */
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
	}
	this->list->remove_first(this->list,(void **) packet);
	pthread_mutex_unlock(&(this->mutex));
	return SUCCESS;
}

 /**
 * @brief implements function add of send_queue_t
 */
static status_t add(private_send_queue_t *this, packet_t *packet)
{
	pthread_mutex_lock(&(this->mutex));
	this->list->insert_last(this->list,packet);
	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));
	return SUCCESS;
}

 /**
 * @brief implements function destroy of send_queue_t
 *
 */
static status_t destroy (private_send_queue_t *this)
{

	/* destroy all packets in list before destroying list */
	while (this->list->get_count(this->list) > 0)
	{
		packet_t *packet;
		if (this->list->remove_first(this->list,(void *) &packet) != SUCCESS)
		{
			this->list->destroy(this->list);
			break;
		}
		packet->destroy(packet);
	}
	this->list->destroy(this->list);

	pthread_mutex_destroy(&(this->mutex));

	pthread_cond_destroy(&(this->condvar));

	allocator_free(this);
	return SUCCESS;
}

 /*
 *
 * Documented in header
 */
send_queue_t *send_queue_create()
{
	linked_list_t *linked_list = linked_list_create();
	if (linked_list == NULL)
	{
		return NULL;
	}

	private_send_queue_t *this = allocator_alloc_thing(private_send_queue_t);
	if (this == NULL)
	{
		linked_list->destroy(linked_list);
		return NULL;
	}

	this->public.get_count = (int(*)(send_queue_t*)) get_count;
	this->public.get = (status_t(*)(send_queue_t*, packet_t**)) get;
	this->public.add = (status_t(*)(send_queue_t*, packet_t*)) add;
	this->public.destroy = (status_t(*)(send_queue_t*)) destroy;

	this->list = linked_list;
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);

	return (&this->public);
}
