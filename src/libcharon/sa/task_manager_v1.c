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

#include "task_manager_v1.h"

#include <daemon.h>
#include <sa/tasks/main_mode.h>

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

METHOD(task_manager_t, retransmit, status_t,
	private_task_manager_t *this, u_int32_t message_id)
{
	return FAILED;
}

METHOD(task_manager_t, initiate, status_t,
	private_task_manager_t *this)
{
	return FAILED;
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
				task = (task_t *)main_mode_create(this->ike_sa, FALSE);
				this->passive_tasks->insert_last(this->passive_tasks, task);
				break;
			case AGGRESSIVE:
				/* TODO-IKEv1: agressive mode */
				return FAILED;
			case QUICK_MODE:
				/* TODO-IKEv1: quick mode */
				return FAILED;
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
	/* TODO-IKEv1: detect request/response */
	if (TRUE)
	{
		/* TODO-IKEv1: detect mainmode retransmission */
		charon->bus->message(charon->bus, msg, TRUE);
		if (process_request(this, msg) != SUCCESS)
		{
			flush(this);
			return DESTROY_ME;
		}
	}
	else
	{
		/* TODO-IKEv1: handle response */
		return DESTROY_ME;
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
