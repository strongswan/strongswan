/*
 * Copyright (C) 2009 Martin Willi
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

#include "ike_vendor.h"

#include <daemon.h>
#include <encoding/payloads/vendor_id_payload.h>

typedef struct private_ike_vendor_t private_ike_vendor_t;

/**
 * Private data of an ike_vendor_t object.
 */
struct private_ike_vendor_t {

	/**
	 * Public ike_vendor_t interface.
	 */
	ike_vendor_t public;

	/**
	 * Associated IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the inititator of this task
	 */
	bool initiator;
};

/**
 * strongSwan specific vendor ID without version, MD5("strongSwan")
 */
static chunk_t strongswan_vid = chunk_from_chars(
	0x88,0x2f,0xe5,0x6d,0x6f,0xd2,0x0d,0xbc,
	0x22,0x51,0x61,0x3b,0x2e,0xbe,0x5b,0xeb
);

METHOD(task_t, build, status_t,
	private_ike_vendor_t *this, message_t *message)
{
	if (lib->settings->get_bool(lib->settings,
								"%s.send_vendor_id", FALSE, charon->name))
	{
		vendor_id_payload_t *vid;

		vid = vendor_id_payload_create_data(VENDOR_ID,
											chunk_clone(strongswan_vid));
		message->add_payload(message, &vid->payload_interface);
	}

	return this->initiator ? NEED_MORE : SUCCESS;
}

METHOD(task_t, process, status_t,
	private_ike_vendor_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == VENDOR_ID)
		{
			vendor_id_payload_t *vid;
			chunk_t data;

			vid = (vendor_id_payload_t*)payload;
			data = vid->get_data(vid);

			if (chunk_equals(data, strongswan_vid))
			{
				DBG1(DBG_IKE, "received strongSwan vendor ID");
				this->ike_sa->enable_extension(this->ike_sa, EXT_STRONGSWAN);
			}
			else
			{
				DBG1(DBG_ENC, "received unknown vendor ID: %#B", &data);
			}
		}
	}
	enumerator->destroy(enumerator);

	return this->initiator ? SUCCESS : NEED_MORE;
}

METHOD(task_t, migrate, void,
	private_ike_vendor_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, get_type, task_type_t,
	private_ike_vendor_t *this)
{
	return TASK_IKE_VENDOR;
}

METHOD(task_t, destroy, void,
	private_ike_vendor_t *this)
{
	free(this);
}

/**
 * See header
 */
ike_vendor_t *ike_vendor_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_vendor_t *this;

	INIT(this,
		.public = {
			.task = {
				.build = _build,
				.process = _process,
				.migrate = _migrate,
				.get_type = _get_type,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
	);

	return &this->public;
}
