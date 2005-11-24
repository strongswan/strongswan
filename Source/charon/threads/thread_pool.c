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
 
#include <globals.h>
#include <queues/job_queue.h>
#include <queues/jobs/delete_ike_sa_job.h>
#include <queues/jobs/incoming_packet_job.h>
#include <queues/jobs/initiate_ike_sa_job.h>
#include <utils/allocator.h>
#include <utils/logger.h>

typedef struct private_thread_pool_t private_thread_pool_t;

/**
 * @brief structure with private members for thread_pool_t
 */
struct private_thread_pool_t {
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
	logger_t *pool_logger;
	/**
	 * logger of the threadpool
	 */
	logger_t *worker_logger;
} ;



/**
 * implements private_thread_pool_t.function
 */
static void job_processing(private_thread_pool_t *this)
{

	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	this->worker_logger->log(this->worker_logger, CONTROL, "started working");

	for (;;) {
		job_t *job;
		job_type_t job_type;
		
		global_job_queue->get(global_job_queue, &job);
		job_type = job->get_type(job);
		this->worker_logger->log(this->worker_logger, CONTROL|MORE, "got a job of type %s", mapping_find(job_type_m,job_type));
		
		/* process them here */
		switch (job_type)
		{
			case INCOMING_PACKET:
			{
				packet_t 	*packet;
				message_t 	*message;
				ike_sa_t 	*ike_sa;
				ike_sa_id_t *ike_sa_id;
				status_t 	status;
				incoming_packet_job_t *incoming_packet_job = (incoming_packet_job_t *)job;
				
				
				if (incoming_packet_job->get_packet(incoming_packet_job,&packet) != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "packet in job %s could not be retrieved!",
										mapping_find(job_type_m,job_type));				
					break;
				}
				
				message = message_create_from_packet(packet);
				if (message == NULL)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "message could not be created from packet!", 
										mapping_find(job_type_m,job_type));				
					packet->destroy(packet);
					break;					
				}

				status = message->parse_header(message);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "message header could not be verified!");				
					message->destroy(message);
					break;										
				}
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "message is a %s %s", 
									mapping_find(exchange_type_m, message->get_exchange_type(message)),
									message->get_request(message) ? "request" : "reply");
				
				if ((message->get_major_version(message) != IKE_MAJOR_VERSION) || 
					(message->get_minor_version(message) != IKE_MINOR_VERSION))
				{
					this->worker_logger->log(this->worker_logger, ERROR, "IKE version %d.%d not supported", 
												message->get_major_version(message),
												message->get_minor_version(message));	
					/* Todo send notify */
				}
				
				status = message->get_ike_sa_id(message, &ike_sa_id);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "IKE SA ID of message could not be created!");
					message->destroy(message);
					break;
				}
			
				ike_sa_id->switch_initiator(ike_sa_id);
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking out IKE SA %lld:%lld, role %s", 
									ike_sa_id->get_initiator_spi(ike_sa_id),
									ike_sa_id->get_responder_spi(ike_sa_id),
									ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				
				status = global_ike_sa_manager->checkout(global_ike_sa_manager,ike_sa_id, &ike_sa);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "IKE SA could not be checked out");
					ike_sa_id->destroy(ike_sa_id);	
					message->destroy(message);
					break;
				}
				
				status = ike_sa->process_message(ike_sa, message);				
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "message could not be processed by IKE SA");
				}
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking in IKE SA %lld:%lld, role %s", 
									ike_sa_id->get_initiator_spi(ike_sa_id),
									ike_sa_id->get_responder_spi(ike_sa_id),
									ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				ike_sa_id->destroy(ike_sa_id);
									
				status = global_ike_sa_manager->checkin(global_ike_sa_manager, ike_sa);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "checkin of IKE SA failed");
				}
				message->destroy(message);
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
				ike_sa_t *ike_sa;
				status_t status;
				
				initiate_job = (initiate_ike_sa_job_t *)job;			
					
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "create and checking out IKE SA");
				
				status = global_ike_sa_manager->create_and_checkout(global_ike_sa_manager, &ike_sa);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "%s by checking out new IKE_SA, job rejected.", 
										mapping_find(status_m, status));
					break;
				}
				
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "initializing connection \"%s\"", 
									initiate_job->get_configuration_name(initiate_job));
				status = ike_sa->initialize_connection(ike_sa, initiate_job->get_configuration_name(initiate_job));
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "%s by initialize_conection, job and rejected, IKE_SA deleted.", 
										mapping_find(status_m, status));
					global_ike_sa_manager->checkin_and_delete(global_ike_sa_manager, ike_sa);
					break;
				}
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking in IKE SA");
				status = global_ike_sa_manager->checkin(global_ike_sa_manager, ike_sa);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "%s could not checkin IKE_SA.", 
										mapping_find(status_m, status));
				}
				break;
			}
			case RETRANSMIT_REQUEST:
			{
				this->worker_logger->log(this->worker_logger, ERROR, "job of type %s not supported!", mapping_find(job_type_m,job_type));				
				break;
			}
			
			case DELETE_IKE_SA:
			{
				delete_ike_sa_job_t *delete_ike_sa_job = (delete_ike_sa_job_t*) job;
				ike_sa_id_t *ike_sa_id = delete_ike_sa_job->get_ike_sa_id(delete_ike_sa_job);
				status_t status;
								
				
				this->worker_logger->log(this->worker_logger, CONTROL|MOST, "deleting IKE SA %lld:%lld, role %s", 
									ike_sa_id->get_initiator_spi(ike_sa_id),
									ike_sa_id->get_responder_spi(ike_sa_id),
									ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
									
				status = global_ike_sa_manager->delete(global_ike_sa_manager, ike_sa_id);
				if (status != SUCCESS)
				{
					this->worker_logger->log(this->worker_logger, ERROR, "could not delete IKE_SA (%s)", 
										mapping_find(status_m, status));
				}
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
		this->pool_logger->log(this->pool_logger, CONTROL, "cancelling thread %u", this->threads[current]);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		pthread_join(this->threads[current], NULL);
		this->pool_logger->log(this->pool_logger, CONTROL, "thread %u terminated", this->threads[current]);
	}	

	/* free mem */
	global_logger_manager->destroy_logger(global_logger_manager, this->pool_logger);
	global_logger_manager->destroy_logger(global_logger_manager, this->worker_logger);
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
	this->pool_logger = global_logger_manager->create_logger(global_logger_manager,THREAD_POOL,NULL);
	if (this->threads == NULL)
	{
		allocator_free(this);
		allocator_free(this->threads);
		return NULL;
	}	
	this->worker_logger = global_logger_manager->create_logger(global_logger_manager,WORKER,NULL);
	if (this->threads == NULL)
	{
		global_logger_manager->destroy_logger(global_logger_manager, this->pool_logger);
		allocator_free(this);
		allocator_free(this->threads);
		return NULL;
	}	
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))this->function, this) == 0) 
		{
			this->pool_logger->log(this->pool_logger, CONTROL, "thread %u created", this->threads[current]);
		}
		else 
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->pool_logger->log(this->pool_logger, ERROR, "could not create any thread: %s\n", strerror(errno));
				global_logger_manager->destroy_logger(global_logger_manager, this->pool_logger);
				global_logger_manager->destroy_logger(global_logger_manager, this->worker_logger);
				allocator_free(this->threads);
				allocator_free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->pool_logger->log(this->pool_logger, CONTROL, "could only create %d from requested %d threads: %s\n", current, pool_size, strerror(errno));
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}	
	return (thread_pool_t*)this;
}
