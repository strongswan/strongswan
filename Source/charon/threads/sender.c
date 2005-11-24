/**
 * @file sender.c
 *
 * @brief Implements the Sender Thread encapsulated in the sender_t object
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

#include <stdlib.h>
#include <pthread.h>

#include "sender.h"

#include <globals.h>
#include <network/socket.h>
#include <network/packet.h>
#include <queues/send_queue.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>

typedef struct private_sender_t private_sender_t;

/**
 * Private data of a sender object
 */
struct private_sender_t {
	/**
	 * Public part of a sender object
	 */
	 sender_t public;

	 /**
	  * Assigned thread to the sender_t object
	  */
	 pthread_t assigned_thread;
	 
	 /**
	  * logger for this sender
	  */
	 logger_t *logger;

};

/**
 * Thread function started at creation of the sender object
 *
 * @param this assigned sender object
 * @return SUCCESS if thread_function ended successfully, FAILED otherwise
 */
static void sender_thread_function(private_sender_t * this)
{
	packet_t * current_packet;
	status_t status;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	while (1)
	{
		while (global_send_queue->get(global_send_queue,&current_packet) == SUCCESS)
		{
			this->logger->log(this->logger, CONTROL|MORE, "got a packet, sending it");
			status = global_socket->send(global_socket,current_packet);
			if (status != SUCCESS)
			{
				this->logger->log(this->logger, ERROR, "sending failed, socket returned %s", 
									mapping_find(status_m, status));
			}
			current_packet->destroy(current_packet);
		}
	}
}

/**
 * Implementation of sender_t's destroy function
 */
static status_t destroy(private_sender_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to terminate sender thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | MORE, "Sender thread terminated");	
	
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);

	allocator_free(this);
	return SUCCESS;
}


sender_t * sender_create()
{
	private_sender_t *this = allocator_alloc_thing(private_sender_t);

	this->public.destroy = (status_t(*)(sender_t*)) destroy;
	
	this->logger = global_logger_manager->create_logger(global_logger_manager, SENDER, NULL);
	if (this->logger == NULL)
	{
		allocator_free(this);
		return NULL;	
	}
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))sender_thread_function, this) != 0)
	{
		/* thread could not be created  */
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
