/*
 * Copyright (C) 2015-2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "demo_listener.h"

#include <crypto/hashers/hasher.h>
#include <utils/debug.h>
#include <daemon.h>

typedef struct private_demo_listener_t private_demo_listener_t;

/**
 * Private data of a demo_listener_t object.
 */
struct private_demo_listener_t {

	/**
	 * Public demo_listener_t interface.
	 */
	demo_listener_t public;

	/**
	 * SHA-1 hasher used to hash DEMO payload.
	 */
	hasher_t *hasher;

};

METHOD(listener_t, message, bool,
	private_demo_listener_t *this,
	ike_sa_t *ike_sa, message_t *message, bool incoming, bool plain)
{
	enumerator_t *enumerator;
	payload_t *payload;
	notify_payload_t *notify;
	ike_sa_id_t *ike_sa_id;
	chunk_t data = chunk_empty;
	char *demo_str;

	if (plain && message->get_exchange_type(message) == CREATE_CHILD_SA)
	{
		ike_sa_id = ike_sa->get_id(ike_sa);
				
		if (incoming)
		{
			enumerator = message->create_payload_enumerator(message);
			while (enumerator->enumerate(enumerator, &payload))
			{
				if (payload->get_type(payload) == PLV2_NOTIFY)
				{
					notify = (notify_payload_t*)payload;
					if (notify->get_notify_type(notify) == DEMO_PAYLOAD)
					{
						data = notify->get_notification_data(notify);
						break;
					}
				}
			}
			enumerator->destroy(enumerator);

			if (data.len)
			{
				DBG1(DBG_IKE, "received %.*s", data.len, data.ptr);
			}
		}
		else
		{
			demo_str = ike_sa_id->is_initiator(ike_sa_id) ? "demo request" :
															"demo response";
			DBG1(DBG_IKE, "sending %s", demo_str);
			data = chunk_from_str(demo_str);
			message->add_notify(message, FALSE, DEMO_PAYLOAD, data);
		}
	}
	return TRUE;
}

METHOD(demo_listener_t, destroy, void,
	private_demo_listener_t *this)
{
	DESTROY_IF(this->hasher);
	free(this);
}

/**
 * See header
 */
demo_listener_t *demo_listener_create()
{
	private_demo_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.message = _message,
			},
			.destroy = _destroy,
		},
		.hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1),
	);

	return &this->public;
}
