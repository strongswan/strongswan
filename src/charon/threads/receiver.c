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
#include <utils/logger_manager.h>


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
	  * A logger for the receiver_t object.
	  */
	 logger_t *logger;
};

/**
 * Implementation of receiver_t.receive_packets.
 */
static void receive_packets(private_receiver_t * this)
{
	packet_t * current_packet;
	job_t *current_job;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->logger->log(this->logger, CONTROL, "receiver thread running,  thread_ID: %06u", (int)pthread_self());
	
	while (1)
	{
		while (charon->socket->receive(charon->socket,&current_packet) == SUCCESS)
		{
			this->logger->log(this->logger, CONTROL | LEVEL1, "Creating job from packet");
			current_job = (job_t *) incoming_packet_job_create(current_packet);

			charon->job_queue->add(charon->job_queue,current_job);

		}
		/* bad bad, rebuild the socket ? */
		this->logger->log(this->logger, ERROR, "Receiving from socket failed!");
	}
}

/**
 * Implementation of receiver_t.destroy.
 */
static void destroy(private_receiver_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to terminate receiver thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | LEVEL1, "Receiver thread terminated");

	free(this);
}

/*
 * Described in header.
 */
receiver_t * receiver_create()
{
	private_receiver_t *this = malloc_thing(private_receiver_t);

	this->public.destroy = (void(*)(receiver_t*)) destroy;
	
	this->logger = logger_manager->get_logger(logger_manager, RECEIVER);
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))receive_packets, this) != 0)
	{
		this->logger->log(this->logger, ERROR, "Receiver thread could not be started");
		free(this);
		charon->kill(charon, "Unable to create receiver thread");
	}

	return &(this->public);
}
