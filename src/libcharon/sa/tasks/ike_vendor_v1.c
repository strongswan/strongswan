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

#include "ike_vendor_v1.h"

#include <daemon.h>
#include <encoding/payloads/vendor_id_payload.h>

typedef struct private_ike_vendor_v1_t private_ike_vendor_v1_t;

/**
 * Private data of an ike_vendor_v1_t object.
 */
struct private_ike_vendor_v1_t {

	/**
	 * Public ike_vendor_v1_t interface.
	 */
	ike_vendor_v1_t public;

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
 * IKEv1 Vendor ID database
 */
static struct {
	/* Description */
	char *desc;
	/* extension flag negotiated with vendor ID, if any */
	ike_extension_t extension;
	/* send yourself? */
	bool send;
	/* length of vendor ID string */
	int len;
	/* vendor ID string */
	char *id;
} vendor_ids[] = {

	/* strongSwan MD5("strongSwan") */
	{ "strongSwan", EXT_STRONGSWAN, FALSE, 16,
	  "\x88\x2f\xe5\x6d\x6f\xd2\x0d\xbc\x22\x51\x61\x3b\x2e\xbe\x5b\xeb"},

	/* XAuth, MD5("draft-ietf-ipsra-isakmp-xauth-06.txt") */
	{ "XAuth", EXT_XAUTH, TRUE, 8,
	  "\x09\x00\x26\x89\xdf\xd6\xb7\x12"},

	/* NAT-Traversal, MD5("RFC 3947") */
	{ "NAT-T (RFC 3947)", EXT_NATT, TRUE, 16,
	  "\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f"},
};

METHOD(task_t, build, status_t,
	private_ike_vendor_v1_t *this, message_t *message)
{
	vendor_id_payload_t *vid_payload;
	bool strongswan;
	int i;

	strongswan = lib->settings->get_bool(lib->settings,
										 "charon.send_vendor_id", FALSE);
	for (i = 0; i < countof(vendor_ids); i++)
	{
		if (vendor_ids[i].send ||
			(vendor_ids[i].extension == EXT_STRONGSWAN && strongswan))
		{
			vid_payload = vendor_id_payload_create_data(VENDOR_ID_V1,
				chunk_clone(chunk_create(vendor_ids[i].id, vendor_ids[i].len)));
			message->add_payload(message, &vid_payload->payload_interface);
		}
	}
	return this->initiator ? NEED_MORE : SUCCESS;
}

METHOD(task_t, process, status_t,
	private_ike_vendor_v1_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int i;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == VENDOR_ID_V1)
		{
			vendor_id_payload_t *vid;
			bool found = FALSE;
			chunk_t data;

			vid = (vendor_id_payload_t*)payload;
			data = vid->get_data(vid);

			for (i = 0; i < countof(vendor_ids); i++)
			{
				if (chunk_equals(data, chunk_create(vendor_ids[i].id,
													vendor_ids[i].len)))
				{
					DBG1(DBG_IKE, "received %s vendor id", vendor_ids[i].desc);
					if (vendor_ids[i].extension)
					{
						this->ike_sa->enable_extension(this->ike_sa,
													   vendor_ids[i].extension);
					}
					found = TRUE;
				}
			}
			if (!found)
			{
				DBG1(DBG_ENC, "received unknown vendor id: %#B", &data);
			}
		}
	}
	enumerator->destroy(enumerator);

	return this->initiator ? SUCCESS : NEED_MORE;
}

METHOD(task_t, migrate, void,
	private_ike_vendor_v1_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, get_type, task_type_t,
	private_ike_vendor_v1_t *this)
{
	return TASK_VENDOR_V1;
}

METHOD(task_t, destroy, void,
	private_ike_vendor_v1_t *this)
{
	free(this);
}

/**
 * See header
 */
ike_vendor_v1_t *ike_vendor_v1_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_vendor_v1_t *this;

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
