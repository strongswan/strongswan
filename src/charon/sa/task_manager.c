/**
 * @file task_manager.c
 *
 * @brief Implementation of task_manager_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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
#include <sa/tasks/ike_cert.h>
#include <sa/tasks/ike_rekey.h>
#include <sa/tasks/ike_delete.h>
#include <sa/tasks/ike_config.h>
#include <sa/tasks/ike_dpd.h>
#include <sa/tasks/child_create.h>
#include <sa/tasks/child_rekey.h>
#include <sa/tasks/child_delete.h>
#include <encoding/payloads/delete_payload.h>
#include <processing/jobs/retransmit_job.h>

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
};

/**
 * flush all tasks in the task manager
 */
static void flush(private_task_manager_t *this)
{
	task_t *task;
	
	this->queued_tasks->destroy_offset(this->queued_tasks, 
										offsetof(task_t, destroy));
	this->passive_tasks->destroy_offset(this->passive_tasks,
										offsetof(task_t, destroy));
	
	/* emmit outstanding signals for tasks */
	while (this->active_tasks->remove_last(this->active_tasks,
										   (void**)&task) == SUCCESS)
	{
		switch (task->get_type(task))
		{
			case IKE_AUTH:
				SIG(IKE_UP_FAILED, "establishing IKE_SA failed");
				break;
			case IKE_DELETE:
				SIG(IKE_DOWN_FAILED, "IKE_SA deleted");
				break;
			case IKE_REKEY:
				SIG(IKE_REKEY_FAILED, "rekeying IKE_SA failed");
				break;
			case CHILD_CREATE:
				SIG(CHILD_UP_FAILED, "establishing CHILD_SA failed");
				break;
			case CHILD_DELETE:
				SIG(CHILD_DOWN_FAILED, "deleting CHILD_SA failed");
				break;
			case CHILD_REKEY:
				SIG(IKE_REKEY_FAILED, "rekeying CHILD_SA failed");
				break;
			default:
				break;
		}
		task->destroy(task);
	}
	this->queued_tasks = linked_list_create();
	this->passive_tasks = linked_list_create();
}

/**
 * move a task of a specific type from the queue to the active list
 */
static bool activate_task(private_task_manager_t *this, task_type_t type)
{
	iterator_t *iterator;
	task_t *task;
	bool found = FALSE;
	
	iterator = this->queued_tasks->create_iterator(this->queued_tasks, TRUE);
	while (iterator->iterate(iterator, (void**)&task))
	{
		if (task->get_type(task) == type)
		{
			DBG2(DBG_IKE, "  activating %N task", task_type_names, type);
			iterator->remove(iterator);
			this->active_tasks->insert_last(this->active_tasks, task);
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of task_manager_t.retransmit
 */
static status_t retransmit(private_task_manager_t *this, u_int32_t message_id)
{
	if (message_id == this->initiating.mid)
	{
		u_int32_t timeout;
		job_t *job;

		if (this->initiating.retransmitted <= RETRANSMIT_TRIES)
		{
			timeout = (u_int32_t)(RETRANSMIT_TIMEOUT *
						pow(RETRANSMIT_BASE, this->initiating.retransmitted));
		}
		else
		{
			DBG1(DBG_IKE, "giving up after %d retransmits",
				 this->initiating.retransmitted - 1);
			return DESTROY_ME;
		}
		
		if (this->initiating.retransmitted)
		{
			DBG1(DBG_IKE, "retransmit %d of request with message ID %d",
				 this->initiating.retransmitted, message_id);
		}
		this->initiating.retransmitted++;
		
		charon->sender->send(charon->sender,
					this->initiating.packet->clone(this->initiating.packet));
		job = (job_t*)retransmit_job_create(this->initiating.mid,
											this->ike_sa->get_id(this->ike_sa));
		charon->scheduler->schedule_job(charon->scheduler, job, timeout);
	}
	return SUCCESS;
}

/**
 * build a request using the active task list
 * Implementation of task_manager_t.initiate
 */
static status_t build_request(private_task_manager_t *this)
{
	iterator_t *iterator;
	task_t *task;
	message_t *message;
	status_t status;
	exchange_type_t exchange = 0;
	
	if (this->initiating.type != EXCHANGE_TYPE_UNDEFINED)
	{
		DBG2(DBG_IKE, "delaying task initiation, exchange in progress");
		/* do not initiate if we already have a message in the air */
		return SUCCESS;
	}
	
	if (this->active_tasks->get_count(this->active_tasks) == 0)
	{
		DBG2(DBG_IKE, "activating new tasks");
		switch (this->ike_sa->get_state(this->ike_sa))
		{
			case IKE_CREATED:
				if (activate_task(this, IKE_INIT))
				{
					this->initiating.mid = 0;
					exchange = IKE_SA_INIT;
					activate_task(this, IKE_NATD);
					activate_task(this, IKE_CERT);
					activate_task(this, IKE_AUTHENTICATE);
					activate_task(this, IKE_CONFIG);
					activate_task(this, CHILD_CREATE);
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
		iterator = this->active_tasks->create_iterator(this->active_tasks, TRUE);
		while (iterator->iterate(iterator, (void**)&task))
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
				default:
					continue;
			}
			break;
		}
		iterator->destroy(iterator);
	}
	
	if (exchange == 0)
	{
		DBG2(DBG_IKE, "nothing to initiate");
		/* nothing to do yet... */
		return SUCCESS;
	}
	
	message = message_create();
	message->set_message_id(message, this->initiating.mid);
	message->set_exchange_type(message, exchange);
	this->initiating.type = exchange;
	this->initiating.retransmitted = 0;

	iterator = this->active_tasks->create_iterator(this->active_tasks, TRUE);
	while (iterator->iterate(iterator, (void*)&task))
	{
	    switch (task->build(task, message))
	    {
	        case SUCCESS:
	            /* task completed, remove it */
	            iterator->remove(iterator);
	            task->destroy(task);
	            break;
	        case NEED_MORE:
	            /* processed, but task needs another exchange */
	            break;
	        case FAILED:
	        default:
	            /* critical failure, destroy IKE_SA */
	            iterator->destroy(iterator);
				message->destroy(message);
				flush(this);
	            return DESTROY_ME;
	    }
	}
	iterator->destroy(iterator);

	DESTROY_IF(this->initiating.packet);
	status = this->ike_sa->generate_message(this->ike_sa, message,
											&this->initiating.packet);
	message->destroy(message);
	if (status != SUCCESS)
	{
	    /* message generation failed. There is nothing more to do than to
		 * close the SA */
		flush(this);
	    return DESTROY_ME;
	}						
	
	return retransmit(this, this->initiating.mid);
}

/**
 * handle an incoming response message
 */
static status_t process_response(private_task_manager_t *this,
								 message_t *message)
{
	iterator_t *iterator;
	task_t *task;
	
	if (message->get_exchange_type(message) != this->initiating.type)
	{
		DBG1(DBG_IKE, "received %N response, but expected %N",
			 exchange_type_names, message->get_exchange_type(message),
			 exchange_type_names, this->initiating.type);
		return DESTROY_ME;
	}

	/* catch if we get resetted while processing */
	this->reset = FALSE;
	iterator = this->active_tasks->create_iterator(this->active_tasks, TRUE);
	while (iterator->iterate(iterator, (void*)&task))
	{
	    switch (task->process(task, message))
	    {
	        case SUCCESS:
	            /* task completed, remove it */
	            iterator->remove(iterator);
	            task->destroy(task);
	            break;
	        case NEED_MORE:
	            /* processed, but task needs another exchange */
	            break;
	        case FAILED:
	        default:
	            /* critical failure, destroy IKE_SA */
	            iterator->destroy(iterator);
	            return DESTROY_ME;
	    }
	    if (this->reset)
	    {	/* start all over again if we were reset */
	    	this->reset = FALSE;
	    	iterator->destroy(iterator);
			return build_request(this);
		}	
	}
	iterator->destroy(iterator);
	
	this->initiating.mid++;
	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;

	return build_request(this);
}

/**
 * handle exchange collisions
 */
static void handle_collisions(private_task_manager_t *this, task_t *task)
{
	iterator_t *iterator;
	task_t *active;
	task_type_t type;
	
	type = task->get_type(task);
	
	/* do we have to check  */
	if (type == IKE_REKEY || type == CHILD_REKEY ||
		type == CHILD_DELETE || type == IKE_DELETE || type == IKE_REAUTH)
	{
	    /* find an exchange collision, and notify these tasks */
	    iterator = this->active_tasks->create_iterator(this->active_tasks, TRUE);
	    while (iterator->iterate(iterator, (void**)&active))
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
		    iterator->destroy(iterator);
	    	return;
		}
		iterator->destroy(iterator);
	}
	/* destroy task if not registered in any active task */
	task->destroy(task);
}

/**
 * build a response depending on the "passive" task list
 */
static status_t build_response(private_task_manager_t *this,
							   exchange_type_t exchange)
{
	iterator_t *iterator;
	task_t *task;
	message_t *message;
	bool delete = FALSE;
	status_t status;

	message = message_create();
	message->set_exchange_type(message, exchange);
	message->set_message_id(message, this->responding.mid);
	message->set_request(message, FALSE);

	iterator = this->passive_tasks->create_iterator(this->passive_tasks, TRUE);
	while (iterator->iterate(iterator, (void*)&task))
	{
	    switch (task->build(task, message))
	    {
	        case SUCCESS:
	            /* task completed, remove it */
	            iterator->remove(iterator);
				handle_collisions(this, task);
	        case NEED_MORE:
	            /* processed, but task needs another exchange */
	            break;
	        case FAILED:
	        default:
	            /* destroy IKE_SA, but SEND response first */
	            delete = TRUE;
	            break;
	    }
	    if (delete)
	    {
	    	break;
	    }
	}
	iterator->destroy(iterator);
	
	/* remove resonder SPI if IKE_SA_INIT failed */
	if (delete && exchange == IKE_SA_INIT)
	{
		ike_sa_id_t *id = this->ike_sa->get_id(this->ike_sa);
		id->set_responder_spi(id, 0);
	}

	/* message complete, send it */
	DESTROY_IF(this->responding.packet);
	status = this->ike_sa->generate_message(this->ike_sa, message,
											&this->responding.packet);
	message->destroy(message);
	if (status != SUCCESS)
	{
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
	iterator_t *iterator;
	task_t *task = NULL;
	exchange_type_t exchange;
	payload_t *payload;
	notify_payload_t *notify;
	delete_payload_t *delete;

	exchange = message->get_exchange_type(message);

	/* create tasks depending on request type */
	switch (exchange)
	{
		case IKE_SA_INIT:
		{
			task = (task_t*)ike_init_create(this->ike_sa, FALSE, NULL);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)ike_natd_create(this->ike_sa, FALSE);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)ike_cert_create(this->ike_sa, FALSE);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)ike_auth_create(this->ike_sa, FALSE);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)ike_config_create(this->ike_sa, FALSE);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)child_create_create(this->ike_sa, NULL);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			task = (task_t*)ike_mobike_create(this->ike_sa, FALSE);
			this->passive_tasks->insert_last(this->passive_tasks, task);
			break;
		}
		case CREATE_CHILD_SA:
		{
			bool notify_found = FALSE, ts_found = FALSE;
			iterator = message->get_payload_iterator(message);
			while (iterator->iterate(iterator, (void**)&payload))
			{
				switch (payload->get_type(payload))
				{
					case NOTIFY:
					{
						/* if we find a rekey notify, its CHILD_SA rekeying */
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
					{
						/* if we don't find a TS, its IKE rekeying */
						ts_found = TRUE;
						break;
					}
					default:
						break;
				}
			}
			iterator->destroy(iterator);
		
			if (ts_found)
			{
				if (notify_found)
				{
					task = (task_t*)child_rekey_create(this->ike_sa, NULL);
				}
				else
				{
					task = (task_t*)child_create_create(this->ike_sa, NULL);
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
			iterator = message->get_payload_iterator(message);
			while (iterator->iterate(iterator, (void**)&payload))
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
								task = (task_t*)ike_mobike_create(this->ike_sa,
																  FALSE);
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
							task = (task_t*)ike_delete_create(this->ike_sa, FALSE);
						}
						else
						{
							task = (task_t*)child_delete_create(this->ike_sa, NULL);
						}
						break;
					}
					default:
						break;
				}
			}
			iterator->destroy(iterator);
			
			if (task == NULL)
			{
				task = (task_t*)ike_dpd_create(FALSE);
			}
			this->passive_tasks->insert_last(this->passive_tasks, task);
			break;
		}
		default:
			break;
	}

	/* let the tasks process the message */
	iterator = this->passive_tasks->create_iterator(this->passive_tasks, TRUE);
	while (iterator->iterate(iterator, (void*)&task))
	{
	    switch (task->process(task, message))
	    {
	        case SUCCESS:
	            /* task completed, remove it */
	            iterator->remove(iterator);
	            task->destroy(task);
	            break;
	        case NEED_MORE:
	            /* processed, but task needs at least another call to build() */
	            break;
	        case FAILED:
	        default:
	            /* critical failure, destroy IKE_SA */
	            iterator->destroy(iterator);
	            return DESTROY_ME;
	    }
	}
	iterator->destroy(iterator);

	return build_response(this, exchange);
}

/**
 * Implementation of task_manager_t.process_message
 */
static status_t process_message(private_task_manager_t *this, message_t *msg)
{
	u_int32_t mid = msg->get_message_id(msg);

	if (msg->get_request(msg))
	{
		if (mid == this->responding.mid)
		{
			if (process_request(this, msg) != SUCCESS)
			{
				flush(this);
				return DESTROY_ME;
			}
			this->responding.mid++;
		}
		else if ((mid == this->responding.mid - 1) && this->responding.packet)
		{
			DBG1(DBG_IKE, "received retransmit of request with ID %d, "
			 	 "retransmitting response", mid);
			charon->sender->send(charon->sender,
					 this->responding.packet->clone(this->responding.packet));
		}
		else
		{
			DBG1(DBG_IKE, "received message ID %d, excepted %d. Ignored",
				 mid, this->responding.mid);
		}
	}
	else
	{
		if (mid == this->initiating.mid)
		{
			if (process_response(this, msg) != SUCCESS)
			{
				flush(this);
				return DESTROY_ME;
			}
		}
		else
		{
			DBG1(DBG_IKE, "received message ID %d, excepted %d. Ignored",
				 mid, this->initiating.mid);
			return SUCCESS;
		}
	}
	return SUCCESS;
}

/**
 * Implementation of task_manager_t.queue_task
 */
static void queue_task(private_task_manager_t *this, task_t *task)
{
	DBG2(DBG_IKE, "queueing %N task", task_type_names, task->get_type(task));
	this->queued_tasks->insert_last(this->queued_tasks, task);
}

/**
 * Implementation of task_manager_t.adopt_tasks
 */
static void adopt_tasks(private_task_manager_t *this, private_task_manager_t *other)
{
	task_t *task;

	/* move queued tasks from other to this */
	while (other->queued_tasks->remove_last(other->queued_tasks,
												(void**)&task) == SUCCESS)
	{
		DBG2(DBG_IKE, "migrating %N task", task_type_names, task->get_type(task));
		task->migrate(task, this->ike_sa);
		this->queued_tasks->insert_first(this->queued_tasks, task);
	}
	
	/* reset active tasks and move them to others queued tasks */
	while (other->active_tasks->remove_last(other->active_tasks,
												(void**)&task) == SUCCESS)
	{
		DBG2(DBG_IKE, "migrating %N task", task_type_names, task->get_type(task));
		task->migrate(task, this->ike_sa);
		this->queued_tasks->insert_first(this->queued_tasks, task);
	}
}

/**
 * Implementation of task_manager_t.busy
 */
static bool busy(private_task_manager_t *this)
{
	return (this->active_tasks->get_count(this->active_tasks) > 0);
}

/**
 * Implementation of task_manager_t.reset
 */
static void reset(private_task_manager_t *this)
{
	task_t *task;
	
	/* reset message counters and retransmit packets */
	DESTROY_IF(this->responding.packet);
	DESTROY_IF(this->initiating.packet);
	this->responding.packet = NULL;
	this->initiating.packet = NULL;
	this->responding.mid = 0;
	this->initiating.mid = 0;
	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	
	/* reset active tasks */
	while (this->active_tasks->remove_last(this->active_tasks,
										   (void**)&task) == SUCCESS)
	{
		task->migrate(task, this->ike_sa);
		this->queued_tasks->insert_first(this->queued_tasks, task);
	}
	
	this->reset = TRUE;
}

/**
 * Implementation of task_manager_t.destroy
 */
static void destroy(private_task_manager_t *this)
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
	private_task_manager_t *this = malloc_thing(private_task_manager_t);

	this->public.process_message = (status_t(*)(task_manager_t*,message_t*))process_message;
	this->public.queue_task = (void(*)(task_manager_t*,task_t*))queue_task;
	this->public.initiate = (status_t(*)(task_manager_t*))build_request;
	this->public.retransmit = (status_t(*)(task_manager_t*,u_int32_t))retransmit;
	this->public.reset = (void(*)(task_manager_t*))reset;
	this->public.adopt_tasks = (void(*)(task_manager_t*,task_manager_t*))adopt_tasks;
	this->public.busy = (bool(*)(task_manager_t*))busy;
	this->public.destroy = (void(*)(task_manager_t*))destroy;

	this->ike_sa = ike_sa;
	this->responding.packet = NULL;
	this->initiating.packet = NULL;
	this->responding.mid = 0;
	this->initiating.mid = 0;
	this->initiating.type = EXCHANGE_TYPE_UNDEFINED;
	this->queued_tasks = linked_list_create();
	this->active_tasks = linked_list_create();
	this->passive_tasks = linked_list_create();
	this->reset = FALSE;

	return &this->public;
}
