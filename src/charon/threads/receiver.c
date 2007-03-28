/**
 * @file receiver.c
 *
 * @brief Implementation of receiver_t.
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

#include "receiver.h"

#include <daemon.h>
#include <network/socket.h>
#include <network/packet.h>
#include <queues/job_queue.h>
#include <queues/jobs/job.h>
#include <queues/jobs/incoming_packet_job.h>

typedef struct block_t block_t;

/**
 * entry for a blocked IP
 */
struct block_t {

	/**
	 * IP address to block
	 */
	host_t *ip;
	
	/**
	 * lifetime for this block
	 */
	u_int32_t timeout;
};

/**
 * destroy a block_t
 */
static void block_destroy(block_t *block)
{
	block->ip->destroy(block->ip);
	free(block);
}

typedef struct private_receiver_t private_receiver_t;

/**
 * Private data of a receiver_t object.
 */
struct private_receiver_t {
	/**
	 * Public part of a receiver_t object.
	 */
	 receiver_t public;

	 /**
	  * Assigned thread.
	  */
	 pthread_t assigned_thread;
	 
	 /**
	  * List of blocked IPs
	  */
	 linked_list_t *blocks;
	 
	 /**
	  * mutex to exclusively access block list
	  */
	 pthread_mutex_t mutex;
};

/**
 * Implementation of receiver_t.receive_packets.
 */
static void receive_packets(private_receiver_t * this)
{
	packet_t *packet;
	job_t *job;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	DBG1(DBG_NET, "receiver thread running, thread_ID: %06u", 
		 (int)pthread_self());
	
	while (TRUE)
	{
		if (charon->socket->receive(charon->socket, &packet) != SUCCESS)
		{
			DBG1(DBG_NET, "receiving from socket failed!");
			continue;
		}
		
		if (this->blocks->get_count(this->blocks))
		{
			iterator_t *iterator;
			block_t *blocked;
			bool found = FALSE;
			u_int32_t now = time(NULL);
			
			pthread_mutex_lock(&this->mutex);
			iterator = this->blocks->create_iterator(this->blocks, TRUE);
			while (iterator->iterate(iterator, (void**)&blocked))
			{
				if (now > blocked->timeout)
				{
					/* block expired, remove */
					iterator->remove(iterator);
					block_destroy(blocked);
					continue;
				}
			
				if (!blocked->ip->ip_equals(blocked->ip, 
											packet->get_source(packet)))
				{
					/* no match, get next */
					continue;
				}
				
				/* IP is blocked */
				DBG2(DBG_NET, "received packets source address %H blocked", 
					 blocked->ip);
				packet->destroy(packet);
				found = TRUE;
				break;
			}
			iterator->destroy(iterator);
			pthread_mutex_unlock(&this->mutex);
			if (found)
			{
				/* get next packet */
				continue;
			}
		}
		
		DBG2(DBG_NET, "creating job from packet");
		job = (job_t *) incoming_packet_job_create(packet);
		charon->job_queue->add(charon->job_queue, job);
	}
}

/**
 * Implementation of receiver_t.block
 */
static void block(private_receiver_t *this, host_t *ip, u_int32_t seconds)
{
	block_t *blocked = malloc_thing(block_t);
	
	blocked->ip = ip->clone(ip);
	blocked->timeout = time(NULL) + seconds;
	DBG1(DBG_NET, "blocking %H for %ds", ip, seconds);
	
	pthread_mutex_lock(&this->mutex);
	this->blocks->insert_last(this->blocks, blocked);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of receiver_t.destroy.
 */
static void destroy(private_receiver_t *this)
{
	pthread_cancel(this->assigned_thread);
	pthread_join(this->assigned_thread, NULL);
	this->blocks->destroy_function(this->blocks, (void*)block_destroy);
	free(this);
}

/*
 * Described in header.
 */
receiver_t *receiver_create()
{
	private_receiver_t *this = malloc_thing(private_receiver_t);

	this->public.block = (void(*)(receiver_t*,host_t*,u_int32_t)) block;
	this->public.destroy = (void(*)(receiver_t*)) destroy;
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))receive_packets, this) != 0)
	{
		free(this);
		charon->kill(charon, "unable to create receiver thread");
	}

	pthread_mutex_init(&this->mutex, NULL);
	this->blocks = linked_list_create();

	return &(this->public);
}
