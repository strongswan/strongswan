/*
 * Copyright (C) 2007-2011 Tobias Brunner
 * Copyright (C) 2007-2011 Martin Willi
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

#include "task_manager_v1.h"

#include <math.h>

#include <daemon.h>
#include <sa/ikev1/tasks/main_mode.h>
#include <sa/ikev1/tasks/quick_mode.h>
#include <sa/ikev1/tasks/quick_delete.h>
#include <sa/ikev1/tasks/xauth.h>
#include <sa/ikev1/tasks/mode_config.h>
#include <sa/ikev1/tasks/informational.h>
#include <sa/ikev1/tasks/isakmp_natd.h>
#include <sa/ikev1/tasks/isakmp_vendor.h>
#include <sa/ikev1/tasks/isakmp_cert_pre.h>
#include <sa/ikev1/tasks/isakmp_cert_post.h>
#include <sa/ikev1/tasks/isakmp_delete.h>
#include <processing/jobs/retransmit_job.h>
#include <processing/jobs/delete_ike_sa_job.h>

/**
 * Number of old messages hashes we keep for retransmission.
 *
 * In Main Mode, we must ignore messages from a previous message pair if
 * we already continued to the next. Otherwise a late retransmission
 * could be considered as a reply to the newer request.
 */
#define MAX_OLD_HASHES 2

typedef struct exchange_t exchange_t;

/**
 * An exchange in the air, used do detect and handle retransmission
 */
struct exchange_t {

	/**
	 * Message ID used for this transaction
	 */
	u_int32_t mid;

	/**
	 * generated packet for retransmission
	 */
	packet_t *packet;
};

typedef struct private_task_manager_t private_task_manager_t;

/**
 * private data of the task manager
 */
struct private_task_manager_t {

	/**
	 * public functions
	 */
	task_manager_v1_t public;

	/**
	 * associated IKE_SA we are serving
	 */
	ike_sa_t *ike_sa;

	/**
	 * RNG to create message IDs
	 */
	rng_t *rng;

	/**
	 * Exchange we are currently handling as responder
	 */
	struct {
		/**
		 * Hash of a previously received message
		 */
		u_int32_t hash;

		/**
		 * packet for retransmission
		 */
		packet_t *packet;

	} responding;

	/**
	 * Exchange we are currently handling as initiator
	 */
	struct {
		/**
		 * Message ID of the exchange
		 */
		u_int32_t mid;

		/**
		 * Hashes of old responses we can ignore
		 */
		u_int32_t old_hashes[MAX_OLD_HASHES];

		/**
		 * Position in old hash array
		 */
		int old_hash_pos;

		/**
		 * Sequence number of the last sent message
		 */
		u_int32_t seqnr;

		/**
		 * how many times we have retransmitted so far
		 */
		u_int retransmitted;

		/**
		 * packet for retransmission
		 */
		packet_t *packet;

		/**
		 * type of the initated exchange
		 */
		exchange_type_t type;

	} initiating;

	/**
	 * List of queued tasks not yet in action
	 */
	linked_list_t *queued_tasks;

	/**
	 * List of active tasks, initiated by ourselve
	 */
	linked_list_t *active_tasks;

	/**
	 * List of tasks initiated by peer
	 */
	linked_list_t *passive_tasks;

	/**
	 * Queued messages not yet ready to process
	 */
	message_t *queued;

	/**
	 * Number of times we retransmit messages before giving up
	 */
	u_int retransmit_tries;

	/**
	 * Retransmission timeout
	 */
	double retransmit_timeout;

	/**
	 * Base to calculate retransmission timeout
	 */
	double retransmit_base;
};

/**
 * Flush a single task queue
 */
static void flush_queue(private_task_manager_t *this, linked_list_t *list)
{
	task_t *task;

	if (this->queued)
	{
		this->queued->destroy(this->queued);
		this->queued = NULL;
	}
	while (list->remove_last(list, (void**)&task) == SUCCESS)
	{
		task->destroy(task);
	}
}

/**
 * flush all tasks in the task manager
 */
static void flush(private_task_manager_t *this)
{
	flush_queue(this, this->queued_tasks);
	flush_queue(this, this->passive_tasks);
	flush_queue(this, this->active_tasks);
}

/**
 * move a task of a specific type from the queue to the active list
 */
static bool activate_task(private_task_manager_t *this, task_type_t type)
{
	enumerator_t *enumerator;
	task_t *task;
	bool found = FALSE;

	enumerator = this->queued_tasks->create_enumerator(this->queued_tasks);
	while (enumerator->enumerate(enumerator, (void**)&task))
	{
		if (task->get_type(task) == type)
		{
			DBG2(DBG_IKE, "  activating %N task", task_type_names, type);
			this->queued_tasks->remove_at(this->queued_tasks, enumerator);
			this->active_tasks->insert_last(this->active_tasks, task);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(task_manager_t, retransmit, status_t,
	private_task_manager_t *this, u_int32_t message_seqnr)
{
	/* this.initiating packet used as marker for received response */
	if (message_seqnr == this->initiating.seqnr && this->initiating.packet )
	{
		u_int32_t timeout;
		packet_t *packet;
		job_t *job;

		if (this->initiating.retransmitted <= this->retransmit_tries)
		{
			timeout = (u_int32_t)(this->retransmit_timeout * 1000.0 *
				pow(this->retransmit_base, this->initiating.retransmitted));
		}
		else
		{
			DBG1(DBG_IKE, "giving up after %d retransmits",
				 this->initiating.retransmitted - 1);
			if (this->ike_sa->get_state(this->ike_sa) != IKE_CONNECTING)
			{
				charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
			}
			return DESTROY_ME;
		}

		if (this->initiating.retransmitted)
		{
			DBG1(DBG_IKE, "retransmit %d of request with message ID %u seqnr (%d)",
				 this->initiating.retransmitted, this->initiating.mid, message_seqnr);
		}
		packet = this->initiating.packet->clone(this->initiating.packet);
		charon->sender->send(charon->sender, packet);

		this->initiating.retransmitted++;
		job = (job_t*)retransmit_job_create(this->initiating.seqnr,
											this->ike_sa->get_id(this->ike_sa));
		lib->scheduler->schedule_job_ms(lib->scheduler, job, timeout);
	}
	return SUCCESS;
}

METHOD(task_manager_t, initiate, status_t,
	private_task_manager_t *this)
{
	enumerator_t *enumerator;
	task_t *task;
	message_t *message;
	host_t *me, *other;
	status_t status;
	exchange_type_t exchange = EXCHANGE_TYPE_UNDEFINED;
	bool new_mid = FALSE, expect_response = FALSE, flushed = FALSE;

	if (!this->rng)
	{
		DBG1(DBG_IKE, "no RNG supported");
		return FAILED;
	}

	if (this->initiating.type != EXCHANGE_TYPE_UNDEFINED)
	{
		DBG2(DBG_IKE, "delaying task initiation, %N exchange in progress",
				exchange_type_names, this->initiating.type);
		/* do not initiate if we already have a message in the air */
		return SUCCESS;
	}

	if (this->active_tasks->get_count(this->active_tasks) == 0)
	{
		DBG2(DBG_IKE, "activating new tasks");
		switch (this->ike_sa->get_state(this->ike_sa))
		{
			case IKE_CREATED:
				activate_task(this, TASK_ISAKMP_VENDOR);
				activate_task(this, TASK_ISAKMP_CERT_PRE);
				if (activate_task(this, TASK_MAIN_MODE))
				{
					exchange = ID_PROT;
					activate_task(this, TASK_ISAKMP_CERT_POST);
					activate_task(this, TASK_ISAKMP_NATD);
				}
				break;
			case IKE_CONNECTING:
				if (activate_task(this, TASK_ISAKMP_DELETE))
				{
					exchange = INFORMATIONAL_V1;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_XAUTH))
				{
					exchange = TRANSACTION;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_INFORMATIONAL))
				{
					exchange = INFORMATIONAL_V1;
					new_mid = TRUE;
					break;
				}
				break;
			case IKE_ESTABLISHED:
				if (activate_task(this, TASK_MODE_CONFIG))
				{
					exchange = TRANSACTION;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_QUICK_MODE))
				{
					exchange = QUICK_MODE;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_INFORMATIONAL))
				{
					exchange = INFORMATIONAL_V1;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_QUICK_DELETE))
				{
					exchange = INFORMATIONAL_V1;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_ISAKMP_DELETE))
				{
					exchange = INFORMATIONAL_V1;
					new_mid = TRUE;
					break;
				}
				break;
			default:
				break;
		}
	}
	else
	{
		DBG2(DBG_IKE, "reinitiating already active tasks");
		enumerator = this->active_tasks->create_enumerator(this->active_tasks);
		while (enumerator->enumerate(enumerator, (void**)&task))
		{
			DBG2(DBG_IKE, "  %N task", task_type_names, task->get_type(task));
			switch (task->get_type(task))
			{
				case TASK_MAIN_MODE:
					exchange = ID_PROT;
					break;
				case TASK_QUICK_MODE:
					exchange = QUICK_MODE;
					break;
				case TASK_XAUTH:
					exchange = TRANSACTION;
					new_mid = TRUE;
					break;
				default:
					continue;
			}
			break;
		}
		enumerator->destroy(enumerator);
	}

	if (exchange == EXCHANGE_TYPE_UNDEFINED)
	{
		DBG2(DBG_IKE, "nothing to initiate");
		/* nothing to do yet... */
		return SUCCESS;
	}

	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);

	message = message_create(IKEV1_MAJOR_VERSION, IKEV1_MINOR_VERSION);
	if (new_mid)
	{
		this->rng->get_bytes(this->rng, sizeof(this->initiating.mid),
							 (void*)&this->initiating.mid);
	}
	message->set_message_id(message, this->initiating.mid);
	message->set_source(message, me->clone(me));
	message->set_destination(message, other->clone(other));
	message->set_exchange_type(message, exchange);
	this->initiating.type = exchange;
	this->initiating.retransmitted = 0;

	enumerator = this->active_tasks->create_enumerator(this->active_tasks);
	while (enumerator->enumerate(enumerator, (void*)&task))
	{
		switch (task->build(task, message))
		{
			case SUCCESS:
				/* task completed, remove it */
				this->active_tasks->remove_at(this->active_tasks, enumerator);
				task->destroy(task);
				continue;
			case NEED_MORE:
				expect_response = TRUE;
				/* processed, but task needs another exchange */
				continue;
			case ALREADY_DONE:
				flush_queue(this, this->active_tasks);
				flushed = TRUE;
				break;
			case FAILED:
			default:
				if (this->ike_sa->get_state(this->ike_sa) != IKE_CONNECTING)
				{
					charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
				}
				/* FALL */
			case DESTROY_ME:
				/* critical failure, destroy IKE_SA */
				enumerator->destroy(enumerator);
				message->destroy(message);
				flush(this);
				return DESTROY_ME;
		}
		break;
	}
	enumerator->destroy(enumerator);

	if (this->active_tasks->get_count(this->active_tasks) == 0)
	{	/* tasks completed, no exchange active anymore */
		this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	}
	if (flushed)
	{
		message->destroy(message);
		return initiate(this);
	}
	this->initiating.seqnr++;

	status = this->ike_sa->generate_message(this->ike_sa, message,
											&this->initiating.packet);
	if (status != SUCCESS)
	{
		/* message generation failed. There is nothing more to do than to
		 * close the SA */
		message->destroy(message);
		flush(this);
		charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
		return DESTROY_ME;
	}
	message->destroy(message);

	if (expect_response)
	{
		return retransmit(this, this->initiating.seqnr);
	}
	charon->sender->send(charon->sender,
				this->initiating.packet->clone(this->initiating.packet));
	this->initiating.packet->destroy(this->initiating.packet);
	this->initiating.packet = NULL;

	if (exchange == INFORMATIONAL_V1)
	{
		switch (this->ike_sa->get_state(this->ike_sa))
		{
			case IKE_CONNECTING:
				/* close after sending an INFORMATIONAL when unestablished */
				return FAILED;
			case IKE_DELETING:
				/* close after sending a DELETE */
				return DESTROY_ME;
			default:
				break;
		}
	}
	return initiate(this);
}

/**
 * handle exchange collisions
 */
static bool handle_collisions(private_task_manager_t *this, task_t *task)
{
	return FALSE;
}

/**
 * build a response depending on the "passive" task list
 */
static status_t build_response(private_task_manager_t *this, message_t *request)
{
	enumerator_t *enumerator;
	task_t *task;
	message_t *message;
	host_t *me, *other;
	bool delete = FALSE, flushed = FALSE;
	status_t status;

	me = request->get_destination(request);
	other = request->get_source(request);

	message = message_create(IKEV1_MAJOR_VERSION, IKEV1_MINOR_VERSION);
	message->set_exchange_type(message, request->get_exchange_type(request));
	/* send response along the path the request came in */
	message->set_source(message, me->clone(me));
	message->set_destination(message, other->clone(other));
	message->set_message_id(message, request->get_message_id(request));
	message->set_request(message, FALSE);

	enumerator = this->passive_tasks->create_enumerator(this->passive_tasks);
	while (enumerator->enumerate(enumerator, (void*)&task))
	{
		switch (task->build(task, message))
		{
			case SUCCESS:
				/* task completed, remove it */
				this->passive_tasks->remove_at(this->passive_tasks, enumerator);
				if (!handle_collisions(this, task))
				{
					task->destroy(task);
				}
				continue;
			case NEED_MORE:
				/* processed, but task needs another exchange */
				if (handle_collisions(this, task))
				{
					this->passive_tasks->remove_at(this->passive_tasks,
												   enumerator);
				}
				continue;
			case ALREADY_DONE:
				flush_queue(this, this->passive_tasks);
				flushed = TRUE;
				break;
			case FAILED:
			default:
				charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
				/* FALL */
			case DESTROY_ME:
				/* destroy IKE_SA, but SEND response first */
				delete = TRUE;
				break;
		}
		break;
	}
	enumerator->destroy(enumerator);

	DESTROY_IF(this->responding.packet);
	this->responding.packet = NULL;
	if (flushed)
	{
		message->destroy(message);
		return initiate(this);
	}
	status = this->ike_sa->generate_message(this->ike_sa, message,
											&this->responding.packet);
	message->destroy(message);
	if (status != SUCCESS)
	{
		charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
		return DESTROY_ME;
	}

	charon->sender->send(charon->sender,
						 this->responding.packet->clone(this->responding.packet));
	if (delete)
	{
		return DESTROY_ME;
	}
	return SUCCESS;
}

/**
 * Send a notify in a separate INFORMATIONAL exchange back to the sender.
 * The notify protocol_id is set to ISAKMP
 */
static void send_notify(private_task_manager_t *this, message_t *request,
						notify_type_t type)
{
	message_t *response;
	packet_t *packet;
	host_t *me, *other;
	u_int32_t mid;

	if (request && request->get_exchange_type(request) == INFORMATIONAL_V1)
	{	/* don't respond to INFORMATIONAL requests to avoid a notify war */
		DBG1(DBG_IKE, "ignore malformed INFORMATIONAL request");
		return;
	}

	response = message_create(IKEV1_MAJOR_VERSION, IKEV1_MINOR_VERSION);
	response->set_exchange_type(response, INFORMATIONAL_V1);
	response->set_request(response, TRUE);
	this->rng->get_bytes(this->rng, sizeof(mid), (void*)&mid);
	response->set_message_id(response, mid);
	response->add_payload(response, (payload_t*)
				notify_payload_create_from_protocol_and_type(NOTIFY_V1,
													PROTO_IKE, type));

	me = this->ike_sa->get_my_host(this->ike_sa);
	if (me->is_anyaddr(me))
	{
		me = request->get_destination(request);
		this->ike_sa->set_my_host(this->ike_sa, me->clone(me));
	}
	other = this->ike_sa->get_other_host(this->ike_sa);
	if (other->is_anyaddr(other))
	{
		other = request->get_source(request);
		this->ike_sa->set_other_host(this->ike_sa, other->clone(other));
	}
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	if (this->ike_sa->generate_message(this->ike_sa, response,
									   &packet) == SUCCESS)
	{
		charon->sender->send(charon->sender, packet);
	}
	response->destroy(response);
}

/**
 * handle an incoming request message
 */
static status_t process_request(private_task_manager_t *this,
								message_t *message)
{
	enumerator_t *enumerator;
	task_t *task = NULL;
	bool send_response = FALSE;

	if (this->passive_tasks->get_count(this->passive_tasks) == 0)
	{	/* create tasks depending on request type, if not already some queued */
		switch (message->get_exchange_type(message))
		{
			case ID_PROT:
				task = (task_t *)isakmp_vendor_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)isakmp_cert_pre_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t *)main_mode_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)isakmp_cert_post_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t *)isakmp_natd_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case AGGRESSIVE:
				/* TODO-IKEv1: agressive mode */
				return FAILED;
			case QUICK_MODE:
				if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
				{
					DBG1(DBG_IKE, "received quick mode request for "
						 "unestablished IKE_SA, ignored");
					return FAILED;
				}
				task = (task_t *)quick_mode_create(this->ike_sa, NULL,
												   NULL, NULL);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case INFORMATIONAL_V1:
				task = (task_t *)informational_create(this->ike_sa, NULL);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case TRANSACTION:
				if (this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
				{
					task = (task_t *)mode_config_create(this->ike_sa, FALSE);
				}
				else
				{
					task = (task_t *)xauth_create(this->ike_sa, FALSE);
				}
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			default:
				return FAILED;
		}
	}
	/* let the tasks process the message */
	enumerator = this->passive_tasks->create_enumerator(this->passive_tasks);
	while (enumerator->enumerate(enumerator, (void*)&task))
	{
		switch (task->process(task, message))
		{
			case SUCCESS:
				/* task completed, remove it */
				this->passive_tasks->remove_at(this->passive_tasks, enumerator);
				task->destroy(task);
				continue;
			case NEED_MORE:
				/* processed, but task needs at least another call to build() */
				send_response = TRUE;
				continue;
			case ALREADY_DONE:
				send_response = FALSE;
				flush_queue(this, this->passive_tasks);
				break;
			case FAILED:
			default:
				charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
				/* FALL */
			case DESTROY_ME:
				/* critical failure, destroy IKE_SA */
				this->passive_tasks->remove_at(this->passive_tasks, enumerator);
				enumerator->destroy(enumerator);
				task->destroy(task);
				return DESTROY_ME;
		}
		break;
	}
	enumerator->destroy(enumerator);

	if (send_response)
	{
		if (build_response(this, message) != SUCCESS)
		{
			return DESTROY_ME;
		}
	}
	else
	{	/* We don't send a response, so don't retransmit one if we get
		 * the same message again. */
		DESTROY_IF(this->responding.packet);
		this->responding.packet = NULL;
	}
	if (this->passive_tasks->get_count(this->passive_tasks) == 0 &&
		this->queued_tasks->get_count(this->queued_tasks) > 0)
	{
		/* passive tasks completed, check if an active task has been queued,
		 * such as XAUTH or modeconfig push */
		return initiate(this);
	}
	return SUCCESS;
}

/**
 * handle an incoming response message
 */
static status_t process_response(private_task_manager_t *this,
								 message_t *message)
{
	enumerator_t *enumerator;
	status_t status;
	task_t *task;

	if (message->get_exchange_type(message) != this->initiating.type)
	{
		DBG1(DBG_IKE, "received %N response, but expected %N",
			 exchange_type_names, message->get_exchange_type(message),
			 exchange_type_names, this->initiating.type);
		charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
		return DESTROY_ME;
	}

	enumerator = this->active_tasks->create_enumerator(this->active_tasks);
	while (enumerator->enumerate(enumerator, (void*)&task))
	{
		switch (task->process(task, message))
		{
			case SUCCESS:
				/* task completed, remove it */
				this->active_tasks->remove_at(this->active_tasks, enumerator);
				task->destroy(task);
				continue;
			case NEED_MORE:
				/* processed, but task needs another exchange */
				continue;
			case ALREADY_DONE:
				flush_queue(this, this->active_tasks);
				break;
			case FAILED:
			default:
				charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
				/* FALL */
			case DESTROY_ME:
				/* critical failure, destroy IKE_SA */
				this->active_tasks->remove_at(this->active_tasks, enumerator);
				enumerator->destroy(enumerator);
				task->destroy(task);
				return DESTROY_ME;
		}
		break;
	}
	enumerator->destroy(enumerator);

	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	this->initiating.packet->destroy(this->initiating.packet);
	this->initiating.packet = NULL;

	if (this->queued && this->active_tasks->get_count(this->active_tasks) == 0)
	{
		status = this->public.task_manager.process_message(
									&this->public.task_manager, this->queued);
		this->queued->destroy(this->queued);
		this->queued = NULL;
		if (status == DESTROY_ME)
		{
			return status;
		}
	}

	return initiate(this);
}

/**
 * Parse the given message and verify that it is valid.
 */
static status_t parse_message(private_task_manager_t *this, message_t *msg)
{
	status_t status;

	status = msg->parse_body(msg, this->ike_sa->get_keymat(this->ike_sa));

	if (status != SUCCESS)
	{
		switch (status)
		{
			case NOT_SUPPORTED:
				DBG1(DBG_IKE, "unsupported exchange type");
				send_notify(this, msg, INVALID_EXCHANGE_TYPE);
				break;
			case PARSE_ERROR:
				DBG1(DBG_IKE, "message parsing failed");
				send_notify(this, msg, PAYLOAD_MALFORMED);
				break;
			case VERIFY_ERROR:
				DBG1(DBG_IKE, "message verification failed");
				send_notify(this, msg, PAYLOAD_MALFORMED);
				break;
			case FAILED:
				DBG1(DBG_IKE, "integrity check failed");
				send_notify(this, msg, INVALID_HASH_INFORMATION);
				break;
			case INVALID_STATE:
				DBG1(DBG_IKE, "found encrypted message, but no keys available");
				send_notify(this, msg, PAYLOAD_MALFORMED);
			default:
				break;
		}
		DBG1(DBG_IKE, "%N %s with message ID %u processing failed",
			 exchange_type_names, msg->get_exchange_type(msg),
			 msg->get_request(msg) ? "request" : "response",
			 msg->get_message_id(msg));

		if (this->ike_sa->get_state(this->ike_sa) == IKE_CREATED)
		{	/* invalid initiation attempt, close SA */
			return DESTROY_ME;
		}
	}
	return status;
}

METHOD(task_manager_t, process_message, status_t,
	private_task_manager_t *this, message_t *msg)
{
	u_int32_t hash, mid, i;
	host_t *me, *other;
	status_t status;

	/* TODO-IKEv1: update hosts more selectively */
	me = msg->get_destination(msg);
	other = msg->get_source(msg);
	mid = msg->get_message_id(msg);
	hash = chunk_hash(msg->get_packet_data(msg));
	for (i = 0; i < MAX_OLD_HASHES; i++)
	{
		if (this->initiating.old_hashes[i] == hash)
		{
			DBG1(DBG_IKE, "received retransmit of response with ID %u, "
				 "but next request already sent", mid);
			return SUCCESS;
		}
	}

	if ((mid && mid == this->initiating.mid) ||
		(this->initiating.mid == 0 &&
		 msg->get_exchange_type(msg) == this->initiating.type &&
		this->active_tasks->get_count(this->active_tasks)))
	{
		msg->set_request(msg, FALSE);
		status = parse_message(this, msg);
		if (status != SUCCESS)
		{
			return status;
		}
		this->ike_sa->set_statistic(this->ike_sa, STAT_INBOUND,
									time_monotonic(NULL));
		this->ike_sa->update_hosts(this->ike_sa, me, other, TRUE);
		charon->bus->message(charon->bus, msg, FALSE);
		if (process_response(this, msg) != SUCCESS)
		{
			flush(this);
			return DESTROY_ME;
		}
		this->initiating.old_hashes[(this->initiating.old_hash_pos++) %
									MAX_OLD_HASHES] = hash;
	}
	else
	{
		if (hash == this->responding.hash)
		{
			if (this->responding.packet)
			{
				DBG1(DBG_IKE, "received retransmit of request with ID %u, "
					 "retransmitting response", mid);
				charon->sender->send(charon->sender,
						this->responding.packet->clone(this->responding.packet));
			}
			else
			{
				DBG1(DBG_IKE, "received retransmit of request with ID %u, "
					 "but no response to retransmit", mid);
			}
			return SUCCESS;
		}
		if (msg->get_exchange_type(msg) == TRANSACTION &&
			this->active_tasks->get_count(this->active_tasks))
		{	/* main mode not yet complete, queue XAuth/Mode config tasks */
			if (this->queued)
			{
				DBG1(DBG_IKE, "ignoring additional %N request, queue full",
					 exchange_type_names, TRANSACTION);
				return SUCCESS;
			}
			this->queued = message_create_from_packet(msg->get_packet(msg));
			if (this->queued->parse_header(this->queued) != SUCCESS)
			{
				this->queued->destroy(this->queued);
				this->queued = NULL;
				return FAILED;
			}
			DBG1(DBG_IKE, "queueing %N request as tasks still active",
				 exchange_type_names, TRANSACTION);
			return SUCCESS;
		}

		msg->set_request(msg, TRUE);
		status = parse_message(this, msg);
		if (status != SUCCESS)
		{
			return status;
		}
		/* if this IKE_SA is virgin, we check for a config */
		if (this->ike_sa->get_ike_cfg(this->ike_sa) == NULL)
		{
			ike_sa_id_t *ike_sa_id;
			ike_cfg_t *ike_cfg;
			job_t *job;
			ike_cfg = charon->backends->get_ike_cfg(charon->backends, me, other);
			if (ike_cfg == NULL)
			{
				/* no config found for these hosts, destroy */
				DBG1(DBG_IKE, "no IKE config found for %H...%H, sending %N",
					 me, other, notify_type_names, NO_PROPOSAL_CHOSEN);
				send_notify(this, msg, NO_PROPOSAL_CHOSEN);
				return DESTROY_ME;
			}
			this->ike_sa->set_ike_cfg(this->ike_sa, ike_cfg);
			ike_cfg->destroy(ike_cfg);
			/* add a timeout if peer does not establish it completely */
			ike_sa_id = this->ike_sa->get_id(this->ike_sa);
			job = (job_t*)delete_ike_sa_job_create(ike_sa_id, FALSE);
			lib->scheduler->schedule_job(lib->scheduler, job,
					lib->settings->get_int(lib->settings,
						"charon.half_open_timeout",  HALF_OPEN_IKE_SA_TIMEOUT));
		}
		this->ike_sa->set_statistic(this->ike_sa, STAT_INBOUND,
									time_monotonic(NULL));
		this->ike_sa->update_hosts(this->ike_sa, me, other, TRUE);
		charon->bus->message(charon->bus, msg, TRUE);
		if (process_request(this, msg) != SUCCESS)
		{
			flush(this);
			return DESTROY_ME;
		}
		this->responding.hash = hash;
	}
	return SUCCESS;
}

METHOD(task_manager_t, queue_task, void,
	private_task_manager_t *this, task_t *task)
{
	DBG2(DBG_IKE, "queueing %N task", task_type_names, task->get_type(task));
	this->queued_tasks->insert_last(this->queued_tasks, task);
}

/**
 * Check if a given task has been queued already
 */
static bool has_queued(private_task_manager_t *this, task_type_t type)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	task_t *task;

	enumerator = this->queued_tasks->create_enumerator(this->queued_tasks);
	while (enumerator->enumerate(enumerator, &task))
	{
		if (task->get_type(task) == type)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(task_manager_t, queue_ike, void,
	private_task_manager_t *this)
{
	if (!has_queued(this, TASK_ISAKMP_VENDOR))
	{
		queue_task(this, (task_t*)isakmp_vendor_create(this->ike_sa, TRUE));
	}
	if (!has_queued(this, TASK_ISAKMP_CERT_PRE))
	{
		queue_task(this, (task_t*)isakmp_cert_pre_create(this->ike_sa, TRUE));
	}
	if (!has_queued(this, TASK_MAIN_MODE))
	{
		queue_task(this, (task_t*)main_mode_create(this->ike_sa, TRUE));
	}
	if (!has_queued(this, TASK_ISAKMP_CERT_POST))
	{
		queue_task(this, (task_t*)isakmp_cert_post_create(this->ike_sa, TRUE));
	}
	if (!has_queued(this, TASK_ISAKMP_NATD))
	{
		queue_task(this, (task_t*)isakmp_natd_create(this->ike_sa, TRUE));
	}
}

METHOD(task_manager_t, queue_ike_rekey, void,
	private_task_manager_t *this)
{
	/* TODO-IKEv1: IKE_SA rekeying */
}

METHOD(task_manager_t, queue_ike_reauth, void,
	private_task_manager_t *this)
{
	/* TODO-IKEv1: IKE_SA reauth */
}

METHOD(task_manager_t, queue_ike_delete, void,
	private_task_manager_t *this)
{
	enumerator_t *enumerator;
	child_sa_t *child_sa;

	enumerator = this->ike_sa->create_child_sa_enumerator(this->ike_sa);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		queue_task(this, (task_t*)
			quick_delete_create(this->ike_sa, child_sa->get_protocol(child_sa),
								child_sa->get_spi(child_sa, TRUE), FALSE));
	}
	enumerator->destroy(enumerator);

	queue_task(this, (task_t*)isakmp_delete_create(this->ike_sa, TRUE));
}

METHOD(task_manager_t, queue_mobike, void,
	private_task_manager_t *this, bool roam, bool address)
{
	/* Not supported in IKEv1 */
}

METHOD(task_manager_t, queue_child, void,
	private_task_manager_t *this, child_cfg_t *cfg, u_int32_t reqid,
	traffic_selector_t *tsi, traffic_selector_t *tsr)
{
	queue_task(this, (task_t*)quick_mode_create(this->ike_sa, cfg, tsi, tsr));
}

METHOD(task_manager_t, queue_child_rekey, void,
	private_task_manager_t *this, protocol_id_t protocol, u_int32_t spi)
{
	/* TODO-IKEv1: CHILD rekeying */
}

METHOD(task_manager_t, queue_child_delete, void,
	private_task_manager_t *this, protocol_id_t protocol, u_int32_t spi)
{
	queue_task(this, (task_t*)quick_delete_create(this->ike_sa, protocol,
												  spi, FALSE));
}

METHOD(task_manager_t, queue_dpd, void,
	private_task_manager_t *this)
{
	/* TODO-IKEv1: DPD checking */
}

METHOD(task_manager_t, adopt_tasks, void,
	private_task_manager_t *this, task_manager_t *other_public)
{
	private_task_manager_t *other = (private_task_manager_t*)other_public;
	task_t *task;

	/* move queued tasks from other to this */
	while (other->queued_tasks->remove_last(other->queued_tasks,
												(void**)&task) == SUCCESS)
	{
		DBG2(DBG_IKE, "migrating %N task", task_type_names, task->get_type(task));
		task->migrate(task, this->ike_sa);
		this->queued_tasks->insert_first(this->queued_tasks, task);
	}
}

METHOD(task_manager_t, busy, bool,
	private_task_manager_t *this)
{
	return (this->active_tasks->get_count(this->active_tasks) > 0);
}

METHOD(task_manager_t, incr_mid, void,
	private_task_manager_t *this, bool initiate)
{
}

METHOD(task_manager_t, reset, void,
	private_task_manager_t *this, u_int32_t initiate, u_int32_t respond)
{
	enumerator_t *enumerator;
	task_t *task;

	/* reset message counters and retransmit packets */
	DESTROY_IF(this->responding.packet);
	DESTROY_IF(this->initiating.packet);
	this->responding.packet = NULL;
	this->initiating.packet = NULL;
	this->initiating.mid = 0;
	this->initiating.seqnr = 0;
	this->initiating.retransmitted = 0;
	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;

	/* reset queued tasks */
	enumerator = this->queued_tasks->create_enumerator(this->queued_tasks);
	while (enumerator->enumerate(enumerator, &task))
	{
		task->migrate(task, this->ike_sa);
	}
	enumerator->destroy(enumerator);

	/* reset active tasks */
	while (this->active_tasks->remove_last(this->active_tasks,
										   (void**)&task) == SUCCESS)
	{
		task->migrate(task, this->ike_sa);
		this->queued_tasks->insert_first(this->queued_tasks, task);
	}
}

METHOD(task_manager_t, create_task_enumerator, enumerator_t*,
	private_task_manager_t *this, task_queue_t queue)
{
	switch (queue)
	{
		case TASK_QUEUE_ACTIVE:
			return this->active_tasks->create_enumerator(this->active_tasks);
		case TASK_QUEUE_PASSIVE:
			return this->passive_tasks->create_enumerator(this->passive_tasks);
		case TASK_QUEUE_QUEUED:
			return this->queued_tasks->create_enumerator(this->queued_tasks);
		default:
			return enumerator_create_empty();
	}
}

METHOD(task_manager_t, destroy, void,
	private_task_manager_t *this)
{
	flush(this);

	this->active_tasks->destroy(this->active_tasks);
	this->queued_tasks->destroy(this->queued_tasks);
	this->passive_tasks->destroy(this->passive_tasks);

	DESTROY_IF(this->queued);
	DESTROY_IF(this->responding.packet);
	DESTROY_IF(this->initiating.packet);
	DESTROY_IF(this->rng);
	free(this);
}

/*
 * see header file
 */
task_manager_v1_t *task_manager_v1_create(ike_sa_t *ike_sa)
{
	private_task_manager_t *this;

	INIT(this,
		.public = {
			.task_manager = {
				.process_message = _process_message,
				.queue_task = _queue_task,
				.queue_ike = _queue_ike,
				.queue_ike_rekey = _queue_ike_rekey,
				.queue_ike_reauth = _queue_ike_reauth,
				.queue_ike_delete = _queue_ike_delete,
				.queue_mobike = _queue_mobike,
				.queue_child = _queue_child,
				.queue_child_rekey = _queue_child_rekey,
				.queue_child_delete = _queue_child_delete,
				.queue_dpd = _queue_dpd,
				.initiate = _initiate,
				.retransmit = _retransmit,
				.incr_mid = _incr_mid,
				.reset = _reset,
				.adopt_tasks = _adopt_tasks,
				.busy = _busy,
				.create_task_enumerator = _create_task_enumerator,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.initiating.type = EXCHANGE_TYPE_UNDEFINED,
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		.queued_tasks = linked_list_create(),
		.active_tasks = linked_list_create(),
		.passive_tasks = linked_list_create(),
		.retransmit_tries = lib->settings->get_int(lib->settings,
								"charon.retransmit_tries", RETRANSMIT_TRIES),
		.retransmit_timeout = lib->settings->get_double(lib->settings,
								"charon.retransmit_timeout", RETRANSMIT_TIMEOUT),
		.retransmit_base = lib->settings->get_double(lib->settings,
								"charon.retransmit_base", RETRANSMIT_BASE),
	);

	return &this->public;
}
