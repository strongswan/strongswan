/**
 * @file thread_pool.c
 * 
 * @brief Implementation of thread_pool_t.
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
#include <unistd.h>

#include "thread_pool.h"
 
#include <daemon.h>
#include <queues/job_queue.h>
#include <queues/jobs/delete_ike_sa_job.h>
#include <queues/jobs/incoming_packet_job.h>
#include <queues/jobs/initiate_ike_sa_job.h>
#include <queues/jobs/retransmit_request_job.h>
#include <utils/allocator.h>
#include <utils/logger.h>

typedef struct private_thread_pool_t private_thread_pool_t;

/**
 * @brief Structure with private members for thread_pool_t.
 */
struct private_thread_pool_t {
	/**
	 * inclusion of public members
	 */
	thread_pool_t public;
	
	/**
	 * @brief Main processing functino for worker threads.
	 *
	 * Gets a job from the job queue and calls corresponding
	 * function for processing.
	 * 
	 * @param this	private_thread_pool_t-Object
	 */
	void (*process_jobs) (private_thread_pool_t *this);

	/**
	 * @brief Process a INCOMING_PACKET job.
	 * 
	 * @param this	private_thread_pool_t object
	 * @param job	incoming_packet_job_t object
	 */
	void (*process_incoming_packet_job) (private_thread_pool_t *this, incoming_packet_job_t *job);

	/**
	 * @brief Process a INITIATE_IKE_SA job.
	 * 
	 * @param this	private_thread_pool_t object
	 * @param job	initiate_ike_sa_job_t object
	 */
	void (*process_initiate_ike_sa_job) (private_thread_pool_t *this, initiate_ike_sa_job_t *job);

	/**
	 * @brief Process a DELETE_IKE_SA job.
	 * 
	 * @param this	private_thread_pool_t object
	 * @param job	delete_ike_sa_job_t object
	 */
	void (*process_delete_ike_sa_job) (private_thread_pool_t *this, delete_ike_sa_job_t *job);
	
	/**
	 * @brief Process a RETRANSMIT_REQUEST job.
	 * 
	 * @param this	private_thread_pool_t object
	 * @param job	retransmit_request_job_t object
	 */
	void (*process_retransmit_request_job) (private_thread_pool_t *this, retransmit_request_job_t *job);
	
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
	 * logger of the worker threads
	 */
	logger_t *worker_logger;
} ;

/**
 * Implementation of private_thread_pool_t.process_jobs.
 */
static void process_jobs(private_thread_pool_t *this)
{
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->worker_logger->log(this->worker_logger, CONTROL, "worker thread running, pid: %d", getpid());

	for (;;) {
		job_t *job;
		job_type_t job_type;
		
		job = charon->job_queue->get(charon->job_queue);
		job_type = job->get_type(job);
		this->worker_logger->log(this->worker_logger, CONTROL|MORE, "Process job of type %s", 
								 mapping_find(job_type_m,job_type));
		
		switch (job_type)
		{
			case INCOMING_PACKET:
			{
				this->process_incoming_packet_job(this, (incoming_packet_job_t*)job);
				job->destroy(job);
				break;
			}
			case INITIATE_IKE_SA:
			{
				this->process_initiate_ike_sa_job(this, (initiate_ike_sa_job_t*)job);
				job->destroy(job);
				break;
			}
			case DELETE_IKE_SA:
			{
				this->process_delete_ike_sa_job(this, (delete_ike_sa_job_t*)job);
				job->destroy(job);
				break;
			}
			case RETRANSMIT_REQUEST:
			{
				this->process_retransmit_request_job(this, (retransmit_request_job_t*)job);
				job->destroy(job);
				break;
			}
			default:
			{
				this->worker_logger->log(this->worker_logger, ERROR, "job of type %s not supported!", 
										 mapping_find(job_type_m,job_type));				
				job->destroy(job);
				break;
			}
		}

		this->worker_logger->log(this->worker_logger, CONTROL|MORE, "Processing of job finished");


	}
}

/**
 * Implementation of private_thread_pool_t.process_incoming_packet_job.
 */
static void process_incoming_packet_job(private_thread_pool_t *this, incoming_packet_job_t *job)
{
	packet_t 	*packet;
	message_t 	*message;
	ike_sa_t 	*ike_sa;
	ike_sa_id_t *ike_sa_id;
	status_t 	status;
	
	
	packet = job->get_packet(job);
				
	message = message_create_from_packet(packet);

	status = message->parse_header(message);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "message header could not be verified!");				
		message->destroy(message);
		return;										
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
		/*
		 * TODO send notify reply of type INVALID_MAJOR_VERSION
		 */
	}
				
	message->get_ike_sa_id(message, &ike_sa_id);
			
	ike_sa_id->switch_initiator(ike_sa_id);
				
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking out IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "IKE SA could not be checked out");
		ike_sa_id->destroy(ike_sa_id);	
		message->destroy(message);

		/*
		 * TODO send notify reply of type INVALID_IKE_SPI if SPI could not be found
		 */

		return;
	}
				
	status = ike_sa->process_message(ike_sa, message);				
	if ((status != SUCCESS) && (status != DELETE_ME))
	{
		this->worker_logger->log(this->worker_logger, ERROR, "message could not be processed by IKE SA");
	}
				
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "%s IKE SA %lld:%lld, role %s", 
							 (status == DELETE_ME) ? "Checkin and delete" : "Checkin",
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	ike_sa_id->destroy(ike_sa_id);
		
	if (status == DELETE_ME)
	{
		status = charon->ike_sa_manager->checkin_and_delete(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
					
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "checkin of IKE SA failed!");
	}
	message->destroy(message);
}

/**
 * Implementation of private_thread_pool_t.process_initiate_ike_sa_job.
 */
static void process_initiate_ike_sa_job(private_thread_pool_t *this, initiate_ike_sa_job_t *job)
{
	/*
	 * Initiatie an IKE_SA:
	 * - is defined by a name of a configuration
	 * - create an empty IKE_SA via manager
	 * - call initiate_connection on this sa
	 */
	ike_sa_t *ike_sa;
	status_t status;
	
	
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "create and checking out IKE SA");
	
	charon->ike_sa_manager->create_and_checkout(charon->ike_sa_manager, &ike_sa);
	
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "initializing connection \"%s\"", 
							 job->get_configuration_name(job));
	status = ike_sa->initialize_connection(ike_sa, job->get_configuration_name(job));
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "%s by initialize_conection, going to delete IKE_SA.", 
								 mapping_find(status_m, status));
		charon->ike_sa_manager->checkin_and_delete(charon->ike_sa_manager, ike_sa);
		return;
	}
	
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking in IKE SA");
	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "%s could not checkin IKE_SA.", 
								 mapping_find(status_m, status));
	}
}

/**
 * Implementation of private_thread_pool_t.process_delete_ike_sa_job.
 */
static void process_delete_ike_sa_job(private_thread_pool_t *this, delete_ike_sa_job_t *job)
{
	status_t status;
	ike_sa_id_t *ike_sa_id = job->get_ike_sa_id(job);
										
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "deleting IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	
	status = charon->ike_sa_manager->delete(charon->ike_sa_manager, ike_sa_id);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "could not delete IKE_SA (%s)", 
								 mapping_find(status_m, status));
	}	
}

/**
 * Implementation of private_thread_pool_t.process_retransmit_request_job.
 */
static void process_retransmit_request_job(private_thread_pool_t *this, retransmit_request_job_t *job)
{
	status_t status;
	ike_sa_id_t *ike_sa_id = job->get_ike_sa_id(job);
	u_int32_t message_id = job->get_message_id(job);
	ike_sa_t *ike_sa;
										
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "checking out IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "IKE SA could not be checked out. Allready deleted?");
		return;
	}
				
	status = ike_sa->retransmit_request(ike_sa, message_id);
				
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, CONTROL | MOST, "Message does'nt have to be retransmitted");
	}
				
	this->worker_logger->log(this->worker_logger, CONTROL|MOST, "Checkin IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");

	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "Checkin of IKE SA failed!");
	}
/*
	u_int32_t message_id = message->get_message_id(message);
	retransmit_request_job_t *new_job = retransmit_request_job_create(message_id,ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue,(job_t *) new_job,5000);*/

}

/**
 * Implementation of thread_pool_t.get_pool_size.
 */
static size_t get_pool_size(private_thread_pool_t *this)
{
	return this->pool_size;
}

/**
 * Implementation of thread_pool_t.destroy.
 */
static void destroy(private_thread_pool_t *this)
{	
	int current;
	/* flag thread for termination */
	for (current = 0; current < this->pool_size; current++) {
		this->pool_logger->log(this->pool_logger, CONTROL, "cancelling worker a thread #%d", current+1);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		pthread_join(this->threads[current], NULL);
		this->pool_logger->log(this->pool_logger, CONTROL, "worker thread #%d terminated", current+1);
	}	

	/* free mem */
	charon->logger_manager->destroy_logger(charon->logger_manager, this->pool_logger);
	charon->logger_manager->destroy_logger(charon->logger_manager, this->worker_logger);
	allocator_free(this->threads);
	allocator_free(this);
}

/*
 * Described in header.
 */
thread_pool_t *thread_pool_create(size_t pool_size)
{
	int current;
	
	private_thread_pool_t *this = allocator_alloc_thing(private_thread_pool_t);
	
	/* fill in public fields */
	this->public.destroy = (void(*)(thread_pool_t*))destroy;
	this->public.get_pool_size = (size_t(*)(thread_pool_t*))get_pool_size;
	
	this->process_jobs = process_jobs;
	this->process_initiate_ike_sa_job = process_initiate_ike_sa_job;
	this->process_delete_ike_sa_job = process_delete_ike_sa_job;
	this->process_incoming_packet_job = process_incoming_packet_job;
	this->process_retransmit_request_job = process_retransmit_request_job;
	this->pool_size = pool_size;
	
	this->threads = allocator_alloc(sizeof(pthread_t) * pool_size);

	this->pool_logger = charon->logger_manager->create_logger(charon->logger_manager,THREAD_POOL,NULL);

	this->worker_logger = charon->logger_manager->create_logger(charon->logger_manager,WORKER,NULL);
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))this->process_jobs, this) == 0) 
		{
			this->pool_logger->log(this->pool_logger, CONTROL, "created worker thread #%d", current+1);
		}
		else
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->pool_logger->log(this->pool_logger, ERROR, "could not create any thread");
				charon->logger_manager->destroy_logger(charon->logger_manager, this->pool_logger);
				charon->logger_manager->destroy_logger(charon->logger_manager, this->worker_logger);
				allocator_free(this->threads);
				allocator_free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->pool_logger->log(this->pool_logger, ERROR, "could only create %d from requested %d threads!", current, pool_size);
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}	
	return (thread_pool_t*)this;
}
