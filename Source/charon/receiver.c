/**
 * @file receiver.c
 *
 * @brief Implements the Receiver Thread encapsulated in the receiver_t object
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

#include "receiver.h"

#include "jobs/job.h"
#include "socket.h"
#include "packet.h"
#include "globals.h"
#include "queues/job_queue.h"
#include "utils/allocator.h"
#include "utils/logger_manager.h"

/**
 * Private data of a receiver object
 */
typedef struct private_receiver_s private_receiver_t;

struct private_receiver_s {
	/**
	 * Public part of a receiver object
	 */
	 receiver_t public;

	 /**
	  * Assigned thread to the receiver_t object
	  */
	 pthread_t assigned_thread;
	 /**
	  * logger for the receiver
	  */
	 logger_t *logger;
	 

};

/**
 * Thread function started at creation of the receiver object
 *
 * @param this assigned receiver object
 * @return SUCCESS if thread_function ended successfully, FAILED otherwise
 */
static void receiver_thread_function(private_receiver_t * this)
{
	packet_t * current_packet;
	job_t *current_job;
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	while (1)
	{
		while (global_socket->receive(global_socket,&current_packet) == SUCCESS)
		{
			this->logger->log(this->logger, CONTROL, "creating job from packet");
			current_job = (job_t *) incoming_packet_job_create(current_packet);
			if (current_job == NULL)
			{
				this->logger->log(this->logger, ERROR, "job creation failed");
			}

			if (global_job_queue->add(global_job_queue,current_job) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR, "job queueing failed");
			}

		}
		/* bad bad, rebuild the socket ? */
		this->logger->log(this->logger, ERROR, "receiving from socket failed!");
	}
}

/**
 * Implementation of receiver_t's destroy function
 */
static status_t destroy(private_receiver_t *this)
{
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);

	allocator_free(this);
	return SUCCESS;
}


receiver_t * receiver_create()
{
	private_receiver_t *this = allocator_alloc_thing(private_receiver_t);

	this->public.destroy = (status_t(*)(receiver_t*)) destroy;
	
	this->logger = global_logger_manager->create_logger(global_logger_manager, RECEIVER, NULL);
	if (this->logger == NULL)
	{
		allocator_free(this);
	}
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))receiver_thread_function, this) != 0)
	{
		/* thread could not be created  */
		global_logger_manager->destroy_logger(global_logger_manager, this->logger);
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
