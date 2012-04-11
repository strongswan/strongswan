/*
 * Copyright (C) 2007 Tobias Brunner
 * Copyright (C) 2007-2010 Martin Willi
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

#include "task_manager.h"

#include <math.h>

#include <daemon.h>
#include <sa/tasks/ike_init.h>
#include <sa/tasks/ike_natd.h>
#include <sa/tasks/ike_mobike.h>
#include <sa/tasks/ike_auth.h>
#include <sa/tasks/ike_auth_lifetime.h>
#include <sa/tasks/ike_cert_pre.h>
#include <sa/tasks/ike_cert_post.h>
#include <sa/tasks/ike_rekey.h>
#include <sa/tasks/ike_delete.h>
#include <sa/tasks/ike_config.h>
#include <sa/tasks/ike_dpd.h>
#include <sa/tasks/ike_vendor.h>
#include <sa/tasks/child_create.h>
#include <sa/tasks/child_rekey.h>
#include <sa/tasks/child_delete.h>
#include <encoding/payloads/delete_payload.h>
#include <processing/jobs/retransmit_job.h>

#ifdef ME
#include <sa/tasks/ike_me.h>
#endif

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
	task_manager_t public;

	/**
	 * associated IKE_SA we are serving
	 */
	ike_sa_t *ike_sa;

	/**
	 * Exchange we are currently handling as responder
	 */
	struct {
		/**
		 * Message ID of the exchange
		 */
		u_int32_t mid;

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
	 * the task manager has been reset
	 */
	bool reset;

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
	this->passive_tasks->destroy_offset(this->passive_tasks,
										offsetof(task_t, destroy));
	this->passive_tasks = linked_list_create();
	this->active_tasks->destroy_offset(this->active_tasks,
										offsetof(task_t, destroy));
	this->active_tasks = linked_list_create();
	this->queued_tasks->destroy_offset(this->queued_tasks,
										offsetof(task_t, destroy));
	this->queued_tasks = linked_list_create();
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
		job_t *job;
		enumerator_t *enumerator;
		packet_t *packet;
		task_t *task;
		ike_mobike_t *mobike = NULL;

		/* check if we are retransmitting a MOBIKE routability check */
		enumerator = this->active_tasks->create_enumerator(this->active_tasks);
		while (enumerator->enumerate(enumerator, (void*)&task))
		{
			if (task->get_type(task) == IKE_MOBIKE)
			{
				mobike = (ike_mobike_t*)task;
				if (!mobike->is_probing(mobike))
				{
					mobike = NULL;
				}
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (mobike == NULL)
		{
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
		}
		else
		{	/* for routeability checks, we use a more aggressive behavior */
			if (this->initiating.retransmitted <= ROUTEABILITY_CHECK_TRIES)
			{
				timeout = ROUTEABILITY_CHECK_INTERVAL;
			}
			else
			{
				DBG1(DBG_IKE, "giving up after %d path probings",
					 this->initiating.retransmitted - 1);
				charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
				return DESTROY_ME;
			}

			if (this->initiating.retransmitted)
			{
				DBG1(DBG_IKE, "path probing attempt %d",
					 this->initiating.retransmitted);
			}
			mobike->transmit(mobike, this->initiating.packet);
		}

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
	exchange_type_t exchange = 0;

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
				activate_task(this, IKE_VENDOR);
				if (activate_task(this, IKE_INIT))
				{
					this->initiating.mid = 0;
					exchange = IKE_SA_INIT;
					activate_task(this, IKE_NATD);
					activate_task(this, IKE_CERT_PRE);
#ifdef ME
					/* this task has to be activated before the IKE_AUTHENTICATE
					 * task, because that task pregenerates the packet after
					 * which no payloads can be added to the message anymore.
					 */
					activate_task(this, IKE_ME);
#endif /* ME */
					activate_task(this, IKE_AUTHENTICATE);
					activate_task(this, IKE_CERT_POST);
					activate_task(this, IKE_CONFIG);
					activate_task(this, CHILD_CREATE);
					activate_task(this, IKE_AUTH_LIFETIME);
					activate_task(this, IKE_MOBIKE);
				}
				break;
			case IKE_ESTABLISHED:
				if (activate_task(this, CHILD_CREATE))
				{
					exchange = CREATE_CHILD_SA;
					break;
				}
				if (activate_task(this, CHILD_DELETE))
				{
					exchange = INFORMATIONAL;
					break;
				}
				if (activate_task(this, CHILD_REKEY))
				{
					exchange = CREATE_CHILD_SA;
					break;
				}
				if (activate_task(this, IKE_DELETE))
				{
					exchange = INFORMATIONAL;
					break;
				}
				if (activate_task(this, IKE_REKEY))
				{
					exchange = CREATE_CHILD_SA;
					break;
				}
				if (activate_task(this, IKE_REAUTH))
				{
					exchange = INFORMATIONAL;
					break;
				}
				if (activate_task(this, IKE_MOBIKE))
				{
					exchange = INFORMATIONAL;
					break;
				}
				if (activate_task(this, IKE_DPD))
				{
					exchange = INFORMATIONAL;
					break;
				}
				if (activate_task(this, IKE_AUTH_LIFETIME))
				{
					exchange = INFORMATIONAL;
					break;
				}
#ifdef ME
				if (activate_task(this, IKE_ME))
				{
					exchange = ME_CONNECT;
					break;
				}
#endif /* ME */
			case IKE_REKEYING:
				if (activate_task(this, IKE_DELETE))
				{
					exchange = INFORMATIONAL;
					break;
				}
			case IKE_DELETING:
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
				case IKE_INIT:
					exchange = IKE_SA_INIT;
					break;
				case IKE_AUTHENTICATE:
					exchange = IKE_AUTH;
					break;
				case CHILD_CREATE:
				case CHILD_REKEY:
				case IKE_REKEY:
					exchange = CREATE_CHILD_SA;
					break;
				case IKE_MOBIKE:
					exchange = INFORMATIONAL;
					break;
				default:
					continue;
			}
			break;
		}
		enumerator->destroy(enumerator);
	}

	if (exchange == 0)
	{
		DBG2(DBG_IKE, "nothing to initiate");
		/* nothing to do yet... */
		return SUCCESS;
	}

	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);

	message = message_create();
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

	return retransmit(this, this->initiating.mid);
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

	/* catch if we get resetted while processing */
	this->reset = FALSE;
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
		if (this->reset)
		{	/* start all over again if we were reset */
			this->reset = FALSE;
			enumerator->destroy(enumerator);
			return initiate(this);
		}
	}
	enumerator->destroy(enumerator);

	this->initiating.mid++;
	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	this->initiating.packet->destroy(this->initiating.packet);
	this->initiating.packet = NULL;

	return initiate(this);
}

/**
 * handle exchange collisions
 */
static bool handle_collisions(private_task_manager_t *this, task_t *task)
{
	enumerator_t *enumerator;
	task_t *active;
	task_type_t type;

	type = task->get_type(task);

	/* do we have to check  */
	if (type == IKE_REKEY || type == CHILD_REKEY ||
		type == CHILD_DELETE || type == IKE_DELETE || type == IKE_REAUTH)
	{
		/* find an exchange collision, and notify these tasks */
		enumerator = this->active_tasks->create_enumerator(this->active_tasks);
		while (enumerator->enumerate(enumerator, (void**)&active))
		{
			switch (active->get_type(active))
			{
				case IKE_REKEY:
					if (type == IKE_REKEY || type == IKE_DELETE ||
						type == IKE_REAUTH)
					{
						ike_rekey_t *rekey = (ike_rekey_t*)active;
						rekey->collide(rekey, task);
						break;
					}
					continue;
				case CHILD_REKEY:
					if (type == CHILD_REKEY || type == CHILD_DELETE)
					{
						child_rekey_t *rekey = (child_rekey_t*)active;
						rekey->collide(rekey, task);
						break;
					}
					continue;
				default:
					continue;
			}
			enumerator->destroy(enumerator);
			return TRUE;
		}
		enumerator->destroy(enumerator);
	}
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
	bool delete = FALSE, hook = FALSE;
	status_t status;

	me = request->get_destination(request);
	other = request->get_source(request);

	message = message_create();
	message->set_exchange_type(message, request->get_exchange_type(request));
	/* send response along the path the request came in */
	message->set_source(message, me->clone(me));
	message->set_destination(message, other->clone(other));
	message->set_message_id(message, this->responding.mid);
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
				hook = TRUE;
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

	/* remove resonder SPI if IKE_SA_INIT failed */
	if (delete && request->get_exchange_type(request) == IKE_SA_INIT)
	{
		ike_sa_id_t *id = this->ike_sa->get_id(this->ike_sa);
		id->set_responder_spi(id, 0);
	}

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
		if (hook)
		{
			charon->bus->ike_updown(charon->bus, this->ike_sa, FALSE);
		}
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
	payload_t *payload;
	notify_payload_t *notify;
	delete_payload_t *delete;

	if (this->passive_tasks->get_count(this->passive_tasks) == 0)
	{	/* create tasks depending on request type, if not already some queued */
		switch (message->get_exchange_type(message))
		{
			case IKE_SA_INIT:
			{
				task = (task_t*)ike_vendor_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_init_create(this->ike_sa, FALSE, NULL);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_natd_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_cert_pre_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
#ifdef ME
				task = (task_t*)ike_me_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
#endif /* ME */
				task = (task_t*)ike_auth_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_cert_post_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_config_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)child_create_create(this->ike_sa, NULL, FALSE,
													NULL, NULL);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_auth_lifetime_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				task = (task_t*)ike_mobike_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			}
			case CREATE_CHILD_SA:
			{	/* FIXME: we should prevent this on mediation connections */
				bool notify_found = FALSE, ts_found = FALSE;
				enumerator = message->create_payload_enumerator(message);
				while (enumerator->enumerate(enumerator, &payload))
				{
					switch (payload->get_type(payload))
					{
						case NOTIFY:
						{	/* if we find a rekey notify, its CHILD_SA rekeying */
							notify = (notify_payload_t*)payload;
							if (notify->get_notify_type(notify) == REKEY_SA &&
								(notify->get_protocol_id(notify) == PROTO_AH ||
								 notify->get_protocol_id(notify) == PROTO_ESP))
							{
								notify_found = TRUE;
							}
							break;
						}
						case TRAFFIC_SELECTOR_INITIATOR:
						case TRAFFIC_SELECTOR_RESPONDER:
						{	/* if we don't find a TS, its IKE rekeying */
							ts_found = TRUE;
							break;
						}
						default:
							break;
					}
				}
				enumerator->destroy(enumerator);

				if (ts_found)
				{
					if (notify_found)
					{
						task = (task_t*)child_rekey_create(this->ike_sa,
														   PROTO_NONE, 0);
					}
					else
					{
						task = (task_t*)child_create_create(this->ike_sa, NULL,
															FALSE, NULL, NULL);
					}
				}
				else
				{
					task = (task_t*)ike_rekey_create(this->ike_sa, FALSE);
				}
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			}
			case INFORMATIONAL:
			{
				enumerator = message->create_payload_enumerator(message);
				while (enumerator->enumerate(enumerator, &payload))
				{
					switch (payload->get_type(payload))
					{
						case NOTIFY:
						{
							notify = (notify_payload_t*)payload;
							switch (notify->get_notify_type(notify))
							{
								case ADDITIONAL_IP4_ADDRESS:
								case ADDITIONAL_IP6_ADDRESS:
								case NO_ADDITIONAL_ADDRESSES:
								case UPDATE_SA_ADDRESSES:
								case NO_NATS_ALLOWED:
								case UNACCEPTABLE_ADDRESSES:
								case UNEXPECTED_NAT_DETECTED:
								case COOKIE2:
								case NAT_DETECTION_SOURCE_IP:
								case NAT_DETECTION_DESTINATION_IP:
									task = (task_t*)ike_mobike_create(
															this->ike_sa, FALSE);
									break;
								case AUTH_LIFETIME:
									task = (task_t*)ike_auth_lifetime_create(
															this->ike_sa, FALSE);
									break;
								default:
									break;
							}
							break;
						}
						case DELETE:
						{
							delete = (delete_payload_t*)payload;
							if (delete->get_protocol_id(delete) == PROTO_IKE)
							{
								task = (task_t*)ike_delete_create(this->ike_sa,
																FALSE);
							}
							else
							{
								task = (task_t*)child_delete_create(this->ike_sa,
																PROTO_NONE, 0);
							}
							break;
						}
						default:
							break;
					}
					if (task)
					{
						break;
					}
				}
				enumerator->destroy(enumerator);

				if (task == NULL)
				{
					task = (task_t*)ike_dpd_create(FALSE);
				}
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			}
#ifdef ME
			case ME_CONNECT:
			{
				task = (task_t*)ike_me_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
			}
#endif /* ME */
			default:
				break;
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
				break;
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

METHOD(task_manager_t, process_message, status_t,
	private_task_manager_t *this, message_t *msg)
{
	host_t *me, *other;
	u_int32_t mid;

	mid = msg->get_message_id(msg);
	me = msg->get_destination(msg);
	other = msg->get_source(msg);

	if (msg->get_request(msg))
	{
		if (mid == this->responding.mid)
		{
			if (this->ike_sa->get_state(this->ike_sa) == IKE_CREATED ||
				this->ike_sa->get_state(this->ike_sa) == IKE_CONNECTING ||
				msg->get_exchange_type(msg) != IKE_SA_INIT)
			{	/* only do host updates based on verified messages */
				if (!this->ike_sa->supports_extension(this->ike_sa, EXT_MOBIKE))
				{	/* with MOBIKE, we do no implicit updates */
					this->ike_sa->update_hosts(this->ike_sa, me, other, mid == 1);
				}
			}
			charon->bus->message(charon->bus, msg, TRUE);
			if (msg->get_exchange_type(msg) == EXCHANGE_TYPE_UNDEFINED)
			{	/* ignore messages altered to EXCHANGE_TYPE_UNDEFINED */
				return SUCCESS;
			}
			if (process_request(this, msg) != SUCCESS)
			{
				flush(this);
				return DESTROY_ME;
			}
			this->responding.mid++;
		}
		else if ((mid == this->responding.mid - 1) && this->responding.packet)
		{
			packet_t *clone;
			host_t *host;

			DBG1(DBG_IKE, "received retransmit of request with ID %d, "
				 "retransmitting response", mid);
			clone = this->responding.packet->clone(this->responding.packet);
			host = msg->get_destination(msg);
			clone->set_source(clone, host->clone(host));
			host = msg->get_source(msg);
			clone->set_destination(clone, host->clone(host));
			charon->sender->send(charon->sender, clone);
		}
		else
		{
			DBG1(DBG_IKE, "received message ID %d, expected %d. Ignored",
				 mid, this->responding.mid);
		}
	}
	else
	{
		if (mid == this->initiating.mid)
		{
			if (this->ike_sa->get_state(this->ike_sa) == IKE_CREATED ||
				this->ike_sa->get_state(this->ike_sa) == IKE_CONNECTING ||
				msg->get_exchange_type(msg) != IKE_SA_INIT)
			{	/* only do host updates based on verified messages */
				if (!this->ike_sa->supports_extension(this->ike_sa, EXT_MOBIKE))
				{	/* with MOBIKE, we do no implicit updates */
					this->ike_sa->update_hosts(this->ike_sa, me, other, FALSE);
				}
			}
			charon->bus->message(charon->bus, msg, TRUE);
			if (msg->get_exchange_type(msg) == EXCHANGE_TYPE_UNDEFINED)
			{	/* ignore messages altered to EXCHANGE_TYPE_UNDEFINED */
				return SUCCESS;
			}
			if (process_response(this, msg) != SUCCESS)
			{
				flush(this);
				return DESTROY_ME;
			}
		}
		else
		{
			DBG1(DBG_IKE, "received message ID %d, expected %d. Ignored",
				 mid, this->initiating.mid);
			return SUCCESS;
		}
	}
	return SUCCESS;
}

METHOD(task_manager_t, queue_task, void,
	private_task_manager_t *this, task_t *task)
{
	if (task->get_type(task) == IKE_MOBIKE)
	{	/*  there is no need to queue more than one mobike task */
		enumerator_t *enumerator;
		task_t *current;

		enumerator = this->queued_tasks->create_enumerator(this->queued_tasks);
		while (enumerator->enumerate(enumerator, (void**)&current))
		{
			if (current->get_type(current) == IKE_MOBIKE)
			{
				enumerator->destroy(enumerator);
				task->destroy(task);
				return;
			}
		}
		enumerator->destroy(enumerator);
	}
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
	if (initiate)
	{
		this->initiating.mid++;
	}
	else
	{
		this->responding.mid++;
	}
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
	if (initiate != UINT_MAX)
	{
		this->initiating.mid = initiate;
	}
	if (respond != UINT_MAX)
	{
		this->responding.mid = respond;
	}
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

	this->reset = TRUE;
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
	free(this);
}

/*
 * see header file
 */
task_manager_t *task_manager_create(ike_sa_t *ike_sa)
{
	private_task_manager_t *this;

	INIT(this,
		.public = {
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
		.ike_sa = ike_sa,
		.initiating.type = EXCHANGE_TYPE_UNDEFINED,
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

