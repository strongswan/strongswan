/**
 * @file sender.c
 *
 * @brief Implementation of sender_t.
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

#include <daemon.h>
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
	  * @brief The threads function, sends out packets.
	  * 
	  * @param this 	assigned sender object
	  */
	 void (*send_packets) (private_sender_t * this);
	 
	 /**
	  * logger for this sender
	  */
	 logger_t *logger;

};

/**
 * implements private_sender_t.send_packets
 */
static void send_packets(private_sender_t * this)
{
	packet_t * current_packet;
	status_t status;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	this->logger->log(this->logger, CONTROL, "sender thread running, thread_id %u", (int)pthread_self());

	while (1)
	{
		current_packet = charon->send_queue->get(charon->send_queue);
		this->logger->log(this->logger, CONTROL|MORE, "got a packet, sending it");
		status = charon->socket->send(charon->socket,current_packet);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "sending failed, socket returned %s", 
								mapping_find(status_m, status));
		}
		current_packet->destroy(current_packet);
	}
}

/**
 * implements sender_t.destroy
 */
static void destroy(private_sender_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to terminate sender thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | MORE, "Sender thread terminated");	
	
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);

	allocator_free(this);
}

/*
 * see header
 */
sender_t * sender_create()
{
	private_sender_t *this = allocator_alloc_thing(private_sender_t);

	this->send_packets = send_packets;
	this->public.destroy = (void(*)(sender_t*)) destroy;
	
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, SENDER, NULL);

	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))this->send_packets, this) != 0)
	{
		this->logger->log(this->logger, ERROR, "Sender thread could not be created");
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
