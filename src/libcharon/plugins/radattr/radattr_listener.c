/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "radattr_listener.h"

#include <daemon.h>

#include <radius_message.h>

typedef struct private_radattr_listener_t private_radattr_listener_t;

/**
 * Private data of an radattr_listener_t object.
 */
struct private_radattr_listener_t {

	/**
	 * Public radattr_listener_t interface.
	 */
	radattr_listener_t public;
};

/**
 * Print RADIUS attributes found in IKE message notifies
 */
static void print_radius_attributes(private_radattr_listener_t *this,
									message_t *message)
{
	radius_attribute_type_t type;
	enumerator_t *enumerator;
	notify_payload_t *notify;
	payload_t *payload;
	chunk_t data;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify = (notify_payload_t*)payload;
			if (notify->get_notify_type(notify) == RADIUS_ATTRIBUTE)
			{
				data = notify->get_notification_data(notify);
				if (data.len >= 2)
				{
					type = data.ptr[0];
					data = chunk_skip(data, 2);
					if (chunk_printable(data, NULL, 0))
					{
						DBG1(DBG_IKE, "received RADIUS %N: %.*s",
							 radius_attribute_type_names, type,
							 (int)data.len, data.ptr);
					}
					else
					{
						DBG1(DBG_IKE, "received RADIUS %N: %#B",
							 radius_attribute_type_names, type, &data);

					}
				}
			}
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(listener_t, message, bool,
	private_radattr_listener_t *this,
	ike_sa_t *ike_sa, message_t *message, bool incoming)
{
	if (ike_sa->supports_extension(ike_sa, EXT_STRONGSWAN) &&
		message->get_exchange_type(message) == IKE_AUTH)
	{
		if (incoming)
		{
			print_radius_attributes(this, message);
		}
	}
	return TRUE;
}


METHOD(radattr_listener_t, destroy, void,
	private_radattr_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
radattr_listener_t *radattr_listener_create()
{
	private_radattr_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.message = _message,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
