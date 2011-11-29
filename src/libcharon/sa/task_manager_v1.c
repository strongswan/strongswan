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
#include <sa/tasks/ike_vendor.h>
#include <sa/tasks/main_mode.h>
#include <sa/tasks/quick_mode.h>
#include <sa/tasks/xauth_request.h>
#include <sa/tasks/ike_vendor_v1.h>
#include <processing/jobs/retransmit_job.h>
#include <processing/jobs/delete_ike_sa_job.h>

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
		 * Message ID of the exchange
		 */
		u_int32_t mid;

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
		 * Hash of a previously received message
		 */
		u_int32_t hash;

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
 * flush all tasks in the task manager
 */
static void flush(private_task_manager_t *this)
{
	this->queued_tasks->destroy_offset(this->queued_tasks,
										offsetof(task_t, destroy));
	this->queued_tasks = linked_list_create();
	this->passive_tasks->destroy_offset(this->passive_tasks,
										offsetof(task_t, destroy));
	this->passive_tasks = linked_list_create();
	this->active_tasks->destroy_offset(this->active_tasks,
										offsetof(task_t, destroy));
	this->active_tasks = linked_list_create();
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
	private_task_manager_t *this, u_int32_t message_id)
{
	if (message_id == this->initiating.mid)
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
			DBG1(DBG_IKE, "retransmit %d of request with message ID %d",
				 this->initiating.retransmitted, message_id);
		}
		packet = this->initiating.packet->clone(this->initiating.packet);
		charon->sender->send(charon->sender, packet);

		this->initiating.retransmitted++;
		job = (job_t*)retransmit_job_create(this->initiating.mid,
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
	bool new_mid = FALSE;

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
				activate_task(this, TASK_VENDOR_V1);
				if (activate_task(this, TASK_MAIN_MODE))
				{
					exchange = ID_PROT;
				}
				break;
			case IKE_ESTABLISHED:
				if (activate_task(this, TASK_QUICK_MODE))
				{
					exchange = QUICK_MODE;
					new_mid = TRUE;
					break;
				}
				if (activate_task(this, TASK_XAUTH_REQUEST))
				{
					exchange = TRANSACTION;
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
				case TASK_XAUTH_REQUEST:
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
				break;
			case NEED_MORE:
				/* processed, but task needs another exchange */
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
	}
	enumerator->destroy(enumerator);

	/* update exchange type if a task changed it */
	this->initiating.type = message->get_exchange_type(message);

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

	charon->sender->send(charon->sender,
				this->initiating.packet->clone(this->initiating.packet));

	return SUCCESS;
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
	bool delete = FALSE;
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
				break;
			case NEED_MORE:
				/* processed, but task needs another exchange */
				if (handle_collisions(this, task))
				{
					this->passive_tasks->remove_at(this->passive_tasks,
												   enumerator);
				}
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
		if (delete)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* message complete, send it */
	DESTROY_IF(this->responding.packet);
	this->responding.packet = NULL;
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
 * handle an incoming request message
 */
static status_t process_request(private_task_manager_t *this,
								message_t *message)
{
	enumerator_t *enumerator;
	task_t *task = NULL;

	if (this->passive_tasks->get_count(this->passive_tasks) == 0)
	{	/* create tasks depending on request type, if not already some queued */
		switch (message->get_exchange_type(message))
		{
			case ID_PROT:
				task = (task_t *)ike_vendor_v1_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t *)main_mode_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t *)xauth_request_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case AGGRESSIVE:
				/* TODO-IKEv1: agressive mode */
				return FAILED;
			case QUICK_MODE:
				task = (task_t *)quick_mode_create(this->ike_sa, NULL,
												   NULL, NULL);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case INFORMATIONAL_V1:
				/* TODO-IKEv1: informational */
				return FAILED;
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
				enumerator->destroy(enumerator);
				return SUCCESS;
			case NEED_MORE:
				/* processed, but task needs at least another call to build() */
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
	}
	enumerator->destroy(enumerator);

	return build_response(this, message);
}

/**
 * handle an incoming response message
 */
static status_t process_response(private_task_manager_t *this,
								 message_t *message)
{
	enumerator_t *enumerator;
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
				break;
			case NEED_MORE:
				/* processed, but task needs another exchange */
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
	}
	enumerator->destroy(enumerator);

	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	this->initiating.packet->destroy(this->initiating.packet);
	this->initiating.packet = NULL;

	return initiate(this);
}

/**
 * Send a notify in a separate INFORMATIONAL exchange back to the sender.
 */
static void send_notify_response(private_task_manager_t *this,
								 message_t *request, notify_type_t type,
								 chunk_t data)
{
	message_t *response;
	packet_t *packet;
	host_t *me, *other;
	u_int32_t mid;

	if (request->get_exchange_type(request) == INFORMATIONAL_V1)
	{	/* don't respond to INFORMATIONAL requests to avoid a notify war */
		DBG1(DBG_IKE, "ignore malformed INFORMATIONAL request");
		return;
	}

	response = message_create(IKEV1_MAJOR_VERSION, IKEV1_MINOR_VERSION);
	response->set_exchange_type(response, INFORMATIONAL_V1);
	response->set_request(response, TRUE);
	this->rng->get_bytes(this->rng, sizeof(mid), (void*)&mid);
	response->set_message_id(response, mid);
	response->add_notify(response, FALSE, type, data);
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
				send_notify_response(this, msg,
									 INVALID_EXCHANGE_TYPE, chunk_empty);
				break;
			case PARSE_ERROR:
				DBG1(DBG_IKE, "message parsing failed");
				send_notify_response(this, msg,
									 PAYLOAD_MALFORMED, chunk_empty);
				break;
			case VERIFY_ERROR:
				DBG1(DBG_IKE, "message verification failed");
				send_notify_response(this, msg,
									 PAYLOAD_MALFORMED, chunk_empty);
				break;
			case FAILED:
				DBG1(DBG_IKE, "integrity check failed");
				send_notify_response(this, msg,
									 INVALID_HASH_INFORMATION, chunk_empty);
				break;
			case INVALID_STATE:
				DBG1(DBG_IKE, "found encrypted message, but no keys available");
				send_notify_response(this, msg,
									 PAYLOAD_MALFORMED, chunk_empty);
			default:
				break;
		}
		DBG1(DBG_IKE, "%N %s with message ID %d processing failed",
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
	u_int32_t hash, mid;
	host_t *me, *other;
	status_t status;

	/* TODO-IKEv1: update hosts more selectively */
	me = msg->get_destination(msg);
	other = msg->get_source(msg);
	mid = msg->get_message_id(msg);

	if ((mid && mid == this->initiating.mid) ||
		(this->initiating.mid == 0 &&
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
	}
	else
	{
		hash = chunk_hash(msg->get_packet_data(msg));
		if (hash == this->responding.hash)
		{
			DBG1(DBG_IKE, "received retransmit of request with ID %d, "
				 "retransmitting response", mid);
			charon->sender->send(charon->sender,
						this->responding.packet->clone(this->responding.packet));
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
				send_notify_response(this, msg,
									 NO_PROPOSAL_CHOSEN, chunk_empty);
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

		this->responding.mid = mid;
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
