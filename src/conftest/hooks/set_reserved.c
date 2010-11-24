/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "hook.h"

#include <encoding/payloads/unknown_payload.h>

typedef struct private_set_reserved_t private_set_reserved_t;

/**
 * Private data of an set_reserved_t object.
 */
struct private_set_reserved_t {

	/**
	 * Implements the hook_t interface.
	 */
	hook_t hook;

	/**
	 * Alter requests or responses?
	 */
	bool req;

	/**
	 * ID of message to alter.
	 */
	int id;

	/**
	 * Hook name
	 */
	char *name;
};

METHOD(listener_t, message, bool,
	private_set_reserved_t *this, ike_sa_t *ike_sa, message_t *message,
	bool incoming)
{
	if (!incoming &&
		message->get_request(message) == this->req &&
		message->get_message_id(message) == this->id)
	{
		enumerator_t *bits, *bytes, *types, *payloads;
		payload_type_t type;
		payload_t *payload;
		char *nr, *name;
		bool *bit;
		u_int8_t *byte, byteval;

		types = conftest->test->create_section_enumerator(conftest->test,
													"hooks.%s", this->name);
		while (types->enumerate(types, &name))
		{
			type = atoi(name);
			if (!type)
			{
				type = enum_from_name(payload_type_short_names, name);
				if (type == -1)
				{
					DBG1(DBG_CFG, "invalid payload name '%s'", name);
					break;
				}
			}
			nr = conftest->test->get_str(conftest->test,
								"hooks.%s.%s.bits", "", this->name, name);
			bits = enumerator_create_token(nr, ",", " ");
			while (bits->enumerate(bits, &nr))
			{
				if (type == HEADER)
				{
					message->set_reserved_header_bit(message, atoi(nr));
					DBG1(DBG_CFG, "setting reserved bit %s of %N",
						  nr, payload_type_short_names, type);
					continue;
				}
				payloads = message->create_payload_enumerator(message);
				while (payloads->enumerate(payloads, &payload))
				{
					if (payload->get_type(payload) == type)
					{
						bit = payload_get_field(payload, RESERVED_BIT, atoi(nr));
						if (bit)
						{
							DBG1(DBG_CFG, "setting reserved bit %s of %N",
								  nr, payload_type_short_names, type);
							*bit = TRUE;
						}
					}
				}
				payloads->destroy(payloads);
			}
			bits->destroy(bits);

			nr = conftest->test->get_str(conftest->test,
								"hooks.%s.%s.bytes", "", this->name, name);
			byteval = conftest->test->get_int(conftest->test,
								"hooks.%s.%s.byteval", 255, this->name, name);
			bytes = enumerator_create_token(nr, ",", " ");
			while (bytes->enumerate(bytes, &nr))
			{
				payloads = message->create_payload_enumerator(message);
				while (payloads->enumerate(payloads, &payload))
				{
					if (payload->get_type(payload) == type)
					{
						byte = payload_get_field(payload, RESERVED_BYTE, atoi(nr));
						if (byte)
						{
							DBG1(DBG_CFG, "setting reserved byte %s of %N to %d",
								  nr, payload_type_short_names, type, byteval);
							*byte = byteval;
						}
					}
				}
				payloads->destroy(payloads);
			}
			bytes->destroy(bytes);
		}
		types->destroy(types);
	}
	return TRUE;
}

METHOD(hook_t, destroy, void,
	private_set_reserved_t *this)
{
	free(this->name);
	free(this);
}

/**
 * Create the IKE_AUTH fill hook
 */
hook_t *set_reserved_hook_create(char *name)
{
	private_set_reserved_t *this;

	INIT(this,
		.hook = {
			.listener = {
				.message = _message,
			},
			.destroy = _destroy,
		},
		.req = conftest->test->get_bool(conftest->test,
										"hooks.%s.request", TRUE, name),
		.id = conftest->test->get_int(conftest->test,
										"hooks.%s.id", 0, name),
		.name = strdup(name),
	);

	return &this->hook;
}
