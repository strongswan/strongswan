/**
 * @file thread_pool.c
 * 
 * @brief Thread pool with some threads processing the job_queue.
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
#include <string.h>
#include <errno.h>

#include "thread_pool.h"
 
#include "globals.h"
#include "queues/job_queue.h"
#include "utils/allocator.h"
#include "utils/logger.h"

/**
 * @brief structure with private members for thread_pool_t
 */
typedef struct private_thread_pool_s private_thread_pool_t;

struct private_thread_pool_s {
	/**
	 * inclusion of public members
	 */
	thread_pool_t public;
	/**
	 * @brief Processing function of a worker thread
	 * 
	 * @param this	private_thread_pool_t-Object
	 */
	void (*function) (private_thread_pool_t *this);
	/**
	 * number of running threads
	 */
	 size_t pool_size;
	/**
	 * array of thread ids
	 */
	pthread_t *threads;
	/**
	 * logger of the threadpool
	 */
	logger_t *logger;
} ;



/**
 * implements private_thread_pool_t.function
 */
static void job_processing(private_thread_pool_t *this)
{

	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	this->logger->log(this->logger, CONTROL_MORE, "thread %u started working", pthread_self());

	for (;;) {
		job_t *job;
		job_type_t job_type;
		
		global_job_queue->get(global_job_queue, &job);
		job_type = job->get_type(job);
		this->logger->log(this->logger, CONTROL_MORE, "thread %u got a job of type %s", pthread_self(),mapping_find(job_type_m,job_type));
		
		/* process them here */
		switch (job_type)
		{
			case INCOMING_PACKET:
			{
				packet_t *packet;
				message_t *message;
				ike_sa_t *ike_sa;
				ike_sa_id_t *ike_sa_id;
				status_t status;
				incoming_packet_job_t *incoming_packet_job = (incoming_packet_job_t *)job;
				
				if (incoming_packet_job->get_packet(incoming_packet_job,&packet) != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: Packet in job of type %s could not be retrieved!", pthread_self(),mapping_find(job_type_m,job_type));				
					break;
				}
				message = message_create_from_packet(packet);
				if (message == NULL)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: Message could not be created from packet!", pthread_self(),mapping_find(job_type_m,job_type));				
					packet->destroy(packet);
					break;					
				}

				status = message->parse_header(message);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: Message header could not be verified!", pthread_self());				
					message->destroy(message);
					break;										
				}
				
				if ((message->get_major_version(message) != IKE_MAJOR_VERSION) || (message->get_minor_version(message) != IKE_MINOR_VERSION))
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: IKE Version %d.%d not supported", pthread_self(),message->get_major_version(message),message->get_minor_version(message));	
					/* Todo send notify */
				}
				
				status = message->get_ike_sa_id(message,&ike_sa_id);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: IKE SA ID of message could not be created!", pthread_self());
					message->destroy(message);
					break;
				}
				
				status = global_ike_sa_manager->checkout(global_ike_sa_manager,ike_sa_id, &ike_sa);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: IKE SA could not be checked out", pthread_self());
					message->destroy(message);
					break;
				}
				
				{
					/* only for logging */
					ike_sa_id_t *checked_out_ike_sa_id;
					checked_out_ike_sa_id = ike_sa->get_id(ike_sa);
					u_int64_t initiator;
					u_int64_t responder;
					bool is_initiator;
					checked_out_ike_sa_id->get_values(checked_out_ike_sa_id,&initiator,&responder,&is_initiator);
					this->logger->log(this->logger, CONTROL_MORE, "IKE SA with SPI's I:%d, R:%d checked out", initiator,responder);
				}
				
				status = ike_sa->process_message (ike_sa,message);				
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: Message could not be processed by IKE SA", pthread_self());
				}
				
				status = global_ike_sa_manager->checkin(global_ike_sa_manager,ike_sa);
				if (status != SUCCESS){
					this->logger->log(this->logger, CONTROL_MORE, "thread %u: Checkin of IKE SA return errors", pthread_self());
				}
				message->destroy(message);
				ike_sa_id->destroy(ike_sa_id);				
				
				break;
			}
			case INITIATE_IKE_SA:
			{
				/*
				 * Initiatie an IKE_SA:
				 * - is defined by a name of a configuration
				 * - create an empty IKE_SA via manager
				 * - call initiate_connection on this sa
				 */
				initiate_ike_sa_job_t *initiate_job;
				ike_sa_id_t *ike_sa_id;
				ike_sa_t *ike_sa;
				status_t status;
				
				initiate_job = (initiate_ike_sa_job_t *)job;
				this->logger->log(this->logger, CONTROL, "thread %u: Initiating an IKE_SA for config \"%s\"", 
									pthread_self(), initiate_job->get_configuration_name(initiate_job));				
				
				ike_sa_id = ike_sa_id_create(0, 0, TRUE);
				if (ike_sa_id == NULL)
				{
					this->logger->log(this->logger, ERROR, "thread %u: %s by creating ike_sa_id_t, job rejected.", 
										pthread_self(), mapping_find(status_m, status));
					break;
				}
				
				status = global_ike_sa_manager->checkout(global_ike_sa_manager, ike_sa_id, &ike_sa);
				ike_sa_id->destroy(ike_sa_id);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "thread %u: %s by checking out new IKE_SA, job rejected.", 
										pthread_self(), mapping_find(status_m, status));
					break;
				}
				
				status = ike_sa->initialize_connection(ike_sa, initiate_job->get_configuration_name(initiate_job));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "thread %u: %s by initialize_conection, job and rejected, IKE_SA deleted.", 
										pthread_self(), mapping_find(status_m, status));
					global_ike_sa_manager->checkin_and_delete(global_ike_sa_manager, ike_sa);
					break;
				}
				
				status = global_ike_sa_manager->checkin(global_ike_sa_manager, ike_sa);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "thread %u: %s  could not checkin IKE_SA.", 
										pthread_self(), mapping_find(status_m, status));
				}
				break;
			}
			case RETRANSMIT_REQUEST:
			{
				this->logger->log(this->logger, CONTROL_MORE, "thread %u: Job of type %s not supported!", pthread_self(),mapping_find(job_type_m,job_type));				
				break;
			}
		}
		job->destroy(job);
	}

}

/**
 * implementation of thread_pool_t.get_pool_size
 */
static size_t get_pool_size(private_thread_pool_t *this)
{
	return this->pool_size;
}

/**
 * Implementation of thread_pool_t.destroy
 */
static status_t destroy(private_thread_pool_t *this)
{	
	int current;
	/* flag thread for termination */
	for (current = 0; current < this->pool_size; current++) {
		this->logger->log(this->logger, CONTROL, "cancelling thread %u", this->threads[current]);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		pthread_join(this->threads[current], NULL);
		this->logger->log(this->logger, CONTROL, "thread %u terminated", this->threads[current]);
	}	

	/* free mem */
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);
	allocator_free(this->threads);
	allocator_free(this);
	return SUCCESS;
}

#include <stdio.h>

/*
 * see header
 */
thread_pool_t *thread_pool_create(size_t pool_size)
{
	int current;
	
	private_thread_pool_t *this = allocator_alloc_thing(private_thread_pool_t);
	
	/* fill in public fields */
	this->public.destroy = (status_t(*)(thread_pool_t*))destroy;
	this->public.get_pool_size = (size_t(*)(thread_pool_t*))get_pool_size;
	
	this->function = job_processing;
	this->pool_size = pool_size;
	
	this->threads = allocator_alloc(sizeof(pthread_t) * pool_size);
	if (this->threads == NULL)
	{
		allocator_free(this);
		return NULL;
	}	
	this->logger = global_logger_manager->create_logger(global_logger_manager,THREAD_POOL,NULL);
	if (this->threads == NULL)
	{
		allocator_free(this);
		allocator_free(this->threads);
		return NULL;
	}	
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))this->function, this) == 0) 
		{
			this->logger->log(this->logger, CONTROL, "thread %u created", this->threads[current]);
		}
		else 
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->logger->log(this->logger, CONTROL, "could not create any thread: %s\n", strerror(errno));
				allocator_free(this->threads);
				allocator_free(this->logger);
				allocator_free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->logger->log(this->logger, CONTROL, "could only create %d from requested %d threads: %s\n", current, pool_size, strerror(errno));
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}	
	return (thread_pool_t*)this;
}
