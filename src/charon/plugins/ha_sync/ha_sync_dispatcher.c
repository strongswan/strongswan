/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "ha_sync_dispatcher.h"

#include <daemon.h>
#include <processing/jobs/callback_job.h>

typedef struct private_ha_sync_dispatcher_t private_ha_sync_dispatcher_t;

/**
 * Private data of an ha_sync_dispatcher_t object.
 */
struct private_ha_sync_dispatcher_t {

	/**
	 * Public ha_sync_dispatcher_t interface.
	 */
	ha_sync_dispatcher_t public;

	/**
	 * socket to pull messages from
	 */
	ha_sync_socket_t *socket;

	/**
	 * Dispatcher job
	 */
	callback_job_t *job;
};

/**
 * Process messages of type IKE_ADD
 */
static void process_ike_add(private_ha_sync_dispatcher_t *this,
							ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			/* ike_sa_id_t* */
			case HA_SYNC_IKE_ID:
			case HA_SYNC_IKE_REKEY_ID:
				DBG1(DBG_IKE, " %d -> %llu:%llu %s", attribute,
					 value.ike_sa_id->get_initiator_spi(value.ike_sa_id),
					 value.ike_sa_id->get_responder_spi(value.ike_sa_id),
					 value.ike_sa_id->is_initiator(value.ike_sa_id) ?
						"initiator" : "responder");
				break;
			/* identification_t* */
			case HA_SYNC_LOCAL_ID:
			case HA_SYNC_REMOTE_ID:
			case HA_SYNC_EAP_ID:
				DBG1(DBG_IKE, " %d -> %D", attribute, value.id);
				break;
			/* host_t* */
			case HA_SYNC_LOCAL_ADDR:
			case HA_SYNC_REMOTE_ADDR:
			case HA_SYNC_LOCAL_VIP:
			case HA_SYNC_REMOTE_VIP:
			case HA_SYNC_ADDITIONAL_ADDR:
				DBG1(DBG_IKE, " %d -> %H", attribute, value.host);
				break;
			/* char* */
			case HA_SYNC_CONFIG_NAME:
				DBG1(DBG_IKE, " %d -> %s", attribute, value.str);
				break;
			/** u_int32_t */
			case HA_SYNC_CONDITIONS:
			case HA_SYNC_EXTENSIONS:
				DBG1(DBG_IKE, " %d -> %lu", attribute, value.u32);
				break;
			/** chunk_t */
			case HA_SYNC_NONCE_I:
			case HA_SYNC_NONCE_R:
			case HA_SYNC_SECRET:
				DBG1(DBG_IKE, " %d -> %B", attribute, &value.chunk);
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Dispatcher job function
 */
static job_requeue_t dispatch(private_ha_sync_dispatcher_t *this)
{
	ha_sync_message_t *message;

	message = this->socket->pull(this->socket);
	switch (message->get_type(message))
	{
		case HA_SYNC_IKE_ADD:
			process_ike_add(this, message);
			break;
		case HA_SYNC_IKE_UPDATE:
			break;
		case HA_SYNC_IKE_DELETE:
			break;
		case HA_SYNC_IKE_REKEY:
			break;
		case HA_SYNC_CHILD_ADD:
			break;
		case HA_SYNC_CHILD_DELETE:
			break;
		default:
			DBG1(DBG_CFG, "received unknown HA sync message type %d",
				 message->get_type(message));
			break;
	}
	message->destroy(message);

	return JOB_REQUEUE_DIRECT;
}

/**
 * Implementation of ha_sync_dispatcher_t.destroy.
 */
static void destroy(private_ha_sync_dispatcher_t *this)
{
	this->job->cancel(this->job);
	free(this);
}

/**
 * See header
 */
ha_sync_dispatcher_t *ha_sync_dispatcher_create(ha_sync_socket_t *socket)
{
	private_ha_sync_dispatcher_t *this = malloc_thing(private_ha_sync_dispatcher_t);

	this->public.destroy = (void(*)(ha_sync_dispatcher_t*))destroy;

	this->socket = socket;
	this->job = callback_job_create((callback_job_cb_t)dispatch,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}
