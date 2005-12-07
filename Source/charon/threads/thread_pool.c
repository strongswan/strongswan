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

#include "thread_pool.h"
 
#include <daemon.h>
#include <queues/job_queue.h>
#include <queues/jobs/delete_half_open_ike_sa_job.h>
#include <queues/jobs/delete_established_ike_sa_job.h>
#include <queues/jobs/incoming_packet_job.h>
#include <queues/jobs/initiate_ike_sa_job.h>
#include <queues/jobs/retransmit_request_job.h>
#include <encoding/payloads/notify_payload.h>
#include <utils/allocator.h>
#include <utils/logger.h>


typedef struct private_thread_pool_t private_thread_pool_t;

/**
 * @brief Private data of thread_pool_t class.
 */
struct private_thread_pool_t {
	/**
	 * Public thread_pool_t interface.
	 */
	thread_pool_t public;
	
	/**
	 * @brief Main processing function for worker threads.
	 *
	 * Gets a job from the job queue and calls corresponding
	 * function for processing.
	 * 
	 * @param this	calling object
	 */
	void (*process_jobs) (private_thread_pool_t *this);

	/**
	 * @brief Process a INCOMING_PACKET job.
	 * 
	 * @param this	calling object
	 * @param job	incoming_packet_job_t object
	 */
	void (*process_incoming_packet_job) (private_thread_pool_t *this, incoming_packet_job_t *job);

	/**
	 * @brief Process a INITIATE_IKE_SA job.
	 * 
	 * @param this	calling object
	 * @param job	initiate_ike_sa_job_t object
	 */
	void (*process_initiate_ike_sa_job) (private_thread_pool_t *this, initiate_ike_sa_job_t *job);

	/**
	 * @brief Process a DELETE_HALF_OPEN_IKE_SA job.
	 * 
	 * @param this	calling object
	 * @param job	delete__half_open_ike_sa_job_t object
	 */
	void (*process_delete_half_open_ike_sa_job) (private_thread_pool_t *this, delete_half_open_ike_sa_job_t *job);
	
	/**
	 * @brief Process a DELETE_ESTABLISHED_IKE_SA job.
	 * 
	 * @param this	calling object
	 * @param job	delete_established_ike_sa_job_t object
	 */
	void (*process_delete_established_ike_sa_job) (private_thread_pool_t *this, delete_established_ike_sa_job_t *job);

	/**
	 * @brief Process a RETRANSMIT_REQUEST job.
	 * 
	 * @param this	calling object
	 * @param job	retransmit_request_job_t object
	 */
	void (*process_retransmit_request_job) (private_thread_pool_t *this, retransmit_request_job_t *job);
	
	/**
	 * Creates a job of type DELETE_HALF_OPEN_IKE_SA.
	 * 
	 * This job is used to delete IKE_SA's which are still in state INITIATOR_INIT,
	 * RESPONDER_INIT, IKE_AUTH_REQUESTED, IKE_INIT_REQUESTED or IKE_INIT_RESPONDED.
	 * 
	 * @param ike_sa_id		ID of IKE_SA to delete
	 * @param delay			Delay in ms after a half open IKE_SA gets deleted!
	 */
	void (*create_delete_half_open_ike_sa_job) (private_thread_pool_t *this,ike_sa_id_t *ike_sa_id, u_int32_t delay);
	
	/**
	 * Number of running threads.
	 */
	size_t pool_size;
	
	/**
	 * Array of thread ids.
	 */
	pthread_t *threads;
	
	/**
	 * Logger of the thread pool.
	 */
	logger_t *pool_logger;
	
	/**
	 * Logger of the worker threads.
	 */
	logger_t *worker_logger;
} ;

/**
 * Implementation of private_thread_pool_t.process_jobs.
 */
static void process_jobs(private_thread_pool_t *this)
{
	job_t *job;
	job_type_t job_type;
	timeval_t start_time;
	timeval_t end_time;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->worker_logger->log(this->worker_logger, CONTROL, "Worker thread running, thread_id: %u", (int)pthread_self());

	for (;;) {
		
		job = charon->job_queue->get(charon->job_queue);
		job_type = job->get_type(job);
		this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Process job of type %s", 
								 mapping_find(job_type_m,job_type));
		gettimeofday(&start_time,NULL);
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
			case DELETE_HALF_OPEN_IKE_SA:
			{
				this->process_delete_half_open_ike_sa_job(this, (delete_half_open_ike_sa_job_t*)job);
				job->destroy(job);
				break;
			}
			case DELETE_ESTABLISHED_IKE_SA:
			{
				this->process_delete_established_ike_sa_job(this, (delete_established_ike_sa_job_t*)job);
				job->destroy(job);
				break;
			}
			case RETRANSMIT_REQUEST:
			{
				this->process_retransmit_request_job(this, (retransmit_request_job_t*)job);
				break;
			}
			default:
			{
				this->worker_logger->log(this->worker_logger, ERROR, "Job of type %s not supported!", 
										 mapping_find(job_type_m,job_type));				
				job->destroy(job);
				break;
			}
		}
		gettimeofday(&end_time,NULL);
		
		this->worker_logger->log(this->worker_logger, CONTROL | LEVEL2, "Processed job of type %s in %d us",
									mapping_find(job_type_m,job_type),
									(((end_time.tv_sec - start_time.tv_sec) * 1000000) + (end_time.tv_usec - start_time.tv_usec)));


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
		this->worker_logger->log(this->worker_logger, ERROR, "Message header could not be verified!");				
		message->destroy(message);
		return;										
	}
				
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Message is a %s %s", 
							 mapping_find(exchange_type_m, message->get_exchange_type(message)),
							 message->get_request(message) ? "request" : "reply");
				
	if ((message->get_major_version(message) != IKE_MAJOR_VERSION) || 
			(message->get_minor_version(message) != IKE_MINOR_VERSION))

	{
		this->worker_logger->log(this->worker_logger, ERROR | LEVEL2, "IKE version %d.%d not supported", 
								 message->get_major_version(message),
								 message->get_minor_version(message));	
		/*
		 * TODO send notify reply of type INVALID_MAJOR_VERSION for requests of type IKE_SA_INIT.
		 * 
		 * This check is not handled in state_t object of IKE_SA to increase speed.
		 */
		 if ((message->get_exchange_type(message) == IKE_SA_INIT) && (message->get_request(message)))
		 {
		 	message_t *response;
	 		message->get_ike_sa_id(message, &ike_sa_id);
	 		ike_sa_id->switch_initiator(ike_sa_id);
		 	response = message_create_notify_reply(message->get_destination(message),
		 										   message->get_source(message),
		 										   IKE_SA_INIT,
		 										   FALSE,ike_sa_id,INVALID_MAJOR_VERSION);

			message->destroy(message);
			ike_sa_id->destroy(ike_sa_id);
			status = response->generate(response, NULL, NULL, &packet);
			if (status != SUCCESS)
			{
				this->worker_logger->log(this->worker_logger, ERROR, "Could not generate packet from message");
				response->destroy(response);
				return;
			}
			this->worker_logger->log(this->worker_logger, ERROR, "Send notify reply of type INVALID_MAJOR_VERSION"); 
			charon->send_queue->add(charon->send_queue, packet);
			response->destroy(response);
			return;
		 }
 		message->destroy(message);
		
		 return;
	}
				
	message->get_ike_sa_id(message, &ike_sa_id);
			
	ike_sa_id->switch_initiator(ike_sa_id);
				
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL3, "Checking out IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		this->worker_logger->log(this->worker_logger, ERROR, "IKE SA could not be checked out");
		ike_sa_id->destroy(ike_sa_id);	
		message->destroy(message);

		/*
		 * TODO send notify reply of type INVALID_IKE_SPI if SPI could not be found ?
		 */

		return;
	}

	if (status == CREATED)
	{
		this->worker_logger->log(this->worker_logger, CONTROL|LEVEL3, "Create Job to delete half open IKE_SA.");
		this->create_delete_half_open_ike_sa_job(this,ike_sa_id,charon->configuration_manager->get_half_open_ike_sa_timeout(charon->configuration_manager));
	}

	status = ike_sa->process_message(ike_sa, message);				
	if ((status != SUCCESS) && (status != DELETE_ME))
	{
		this->worker_logger->log(this->worker_logger, ERROR, "Message could not be processed by IKE SA");
	}
				
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL3, "%s IKE SA %lld:%lld, role %s", 
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
		this->worker_logger->log(this->worker_logger, ERROR, "Checkin of IKE SA failed!");
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
	
	
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Create and checking out IKE SA");
	
	charon->ike_sa_manager->create_and_checkout(charon->ike_sa_manager, &ike_sa);
	
	this->worker_logger->log(this->worker_logger, CONTROL, "Initializing connection \"%s\"", 
							 job->get_configuration_name(job));
	status = ike_sa->initialize_connection(ike_sa, job->get_configuration_name(job));
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "%s: By initialize_conection, going to delete IKE_SA.", 
								 mapping_find(status_m, status));
		charon->ike_sa_manager->checkin_and_delete(charon->ike_sa_manager, ike_sa);
		return;
	}

	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL3, "Create Job to delete half open IKE_SA.");
	this->create_delete_half_open_ike_sa_job(this,ike_sa->get_id(ike_sa),charon->configuration_manager->get_half_open_ike_sa_timeout(charon->configuration_manager));
	
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Checking in IKE SA");
	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "%s: Could not checkin IKE_SA.", 
								 mapping_find(status_m, status));
	}
}

/**
 * Implementation of private_thread_pool_t.process_delete_ike_sa_job.
 */
static void process_delete_half_open_ike_sa_job(private_thread_pool_t *this, delete_half_open_ike_sa_job_t *job)
{
	ike_sa_id_t *ike_sa_id = job->get_ike_sa_id(job);
	ike_sa_t *ike_sa;
	status_t status;	
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		this->worker_logger->log(this->worker_logger, CONTROL | LEVEL3, "IKE SA seems to be allready deleted and so doesn't have to be deleted");
		return;
	}
	

	switch (ike_sa->get_state(ike_sa))
	{
		case INITIATOR_INIT:
		case RESPONDER_INIT:
		case IKE_SA_INIT_REQUESTED:
		case IKE_SA_INIT_RESPONDED:
		case IKE_AUTH_REQUESTED:
		{
			/* IKE_SA is half open and gets deleted! */
			status = charon->ike_sa_manager->checkin_and_delete(charon->ike_sa_manager, ike_sa);
			if (status != SUCCESS)
			{
				this->worker_logger->log(this->worker_logger, ERROR, "Could not checkin and delete checked out IKE_SA!");
			}
			break;
		}
		default:
		{
			/* IKE_SA is established and so is not getting deleted! */
			status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			if (status != SUCCESS)
			{
				this->worker_logger->log(this->worker_logger, ERROR, "Could not checkin a checked out IKE_SA!");
			}
			break;
		}
	}
}

/**
 * Implementation of private_thread_pool_t.process_delete_established_ike_sa_job.
 */
static void process_delete_established_ike_sa_job(private_thread_pool_t *this, delete_established_ike_sa_job_t *job)
{
	ike_sa_id_t *ike_sa_id = job->get_ike_sa_id(job);
	ike_sa_t *ike_sa;
	status_t status;	
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		this->worker_logger->log(this->worker_logger, CONTROL | LEVEL3, "IKE SA seems to be allready deleted and so doesn't have to be deleted");
		return;
	}

	switch (ike_sa->get_state(ike_sa))
	{
		case INITIATOR_INIT:
		case RESPONDER_INIT:
		case IKE_SA_INIT_REQUESTED:
		case IKE_SA_INIT_RESPONDED:
		case IKE_AUTH_REQUESTED:
		{
			break;
		}
		default:
		{
			/*
			 * TODO Send delete notify
			 */
			break;
		}
	}
	this->worker_logger->log(this->worker_logger, CONTROL, "Delete established IKE_SA.");	
	status = charon->ike_sa_manager->checkin_and_delete(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "Could not checkin and delete checked out IKE_SA!");
	}
}


/**
 * Implementation of private_thread_pool_t.process_retransmit_request_job.
 */
static void process_retransmit_request_job(private_thread_pool_t *this, retransmit_request_job_t *job)
{

	ike_sa_id_t *ike_sa_id = job->get_ike_sa_id(job);
	u_int32_t message_id = job->get_message_id(job);
	bool stop_retransmitting = FALSE;
	u_int32_t timeout;
	ike_sa_t *ike_sa;
	status_t status;
										
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Checking out IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
				
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager,ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		job->destroy(job);
		this->worker_logger->log(this->worker_logger, ERROR, "IKE SA could not be checked out. Allready deleted?");
		return;
	}
				
	status = ike_sa->retransmit_request(ike_sa, message_id);
				
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, CONTROL | LEVEL3, "Message doesn't have to be retransmitted");
		stop_retransmitting = TRUE;
	}
				
	this->worker_logger->log(this->worker_logger, CONTROL|LEVEL2, "Checkin IKE SA %lld:%lld, role %s", 
							 ike_sa_id->get_initiator_spi(ike_sa_id),
							 ike_sa_id->get_responder_spi(ike_sa_id),
							 ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");

	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, ERROR, "Checkin of IKE SA failed!");
	}

	if (stop_retransmitting)
	{
		job->destroy(job);
		return;
	}
	
	job->increase_retransmit_count(job);
	status = charon->configuration_manager->get_retransmit_timeout (charon->configuration_manager,job->get_retransmit_count(job),&timeout);
	if (status != SUCCESS)
	{
		this->worker_logger->log(this->worker_logger, CONTROL | LEVEL2, "Message will not be anymore retransmitted");
		job->destroy(job);
		/*
		 * TODO delete IKE_SA ? 
		 */
		return;
	}
	charon->event_queue->add_relative(charon->event_queue,(job_t *) job,timeout);
}



/**
 * Implementation of private_thread_pool_t.create_delete_half_open_ike_sa_job.
 */
static void create_delete_half_open_ike_sa_job(private_thread_pool_t *this,ike_sa_id_t *ike_sa_id, u_int32_t delay)
{
	job_t *delete_job;

	this->worker_logger->log(this->worker_logger, CONTROL | LEVEL2, "Going to create job to delete half open IKE_SA in %d ms", delay);

	delete_job = (job_t *) delete_half_open_ike_sa_job_create(ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue,delete_job, delay);
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
	this->process_delete_half_open_ike_sa_job = process_delete_half_open_ike_sa_job;
	this->process_delete_established_ike_sa_job = process_delete_established_ike_sa_job;
	this->process_incoming_packet_job = process_incoming_packet_job;
	this->process_retransmit_request_job = process_retransmit_request_job;
	this->create_delete_half_open_ike_sa_job = create_delete_half_open_ike_sa_job;
	
	this->pool_size = pool_size;
	
	this->threads = allocator_alloc(sizeof(pthread_t) * pool_size);

	this->pool_logger = charon->logger_manager->create_logger(charon->logger_manager,THREAD_POOL,NULL);

	this->worker_logger = charon->logger_manager->create_logger(charon->logger_manager,WORKER,NULL);
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))this->process_jobs, this) == 0) 
		{
			this->pool_logger->log(this->pool_logger, CONTROL, "Created worker thread #%d", current+1);
		}
		else
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->pool_logger->log(this->pool_logger, ERROR, "Could not create any thread");
				charon->logger_manager->destroy_logger(charon->logger_manager, this->pool_logger);
				charon->logger_manager->destroy_logger(charon->logger_manager, this->worker_logger);
				allocator_free(this->threads);
				allocator_free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->pool_logger->log(this->pool_logger, ERROR, "Could only create %d from requested %d threads!", current, pool_size);
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}	
	return (thread_pool_t*)this;
}
