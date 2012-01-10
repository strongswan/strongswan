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

#include "isakmp_vendor.h"

#include <daemon.h>
#include <encoding/payloads/vendor_id_payload.h>

typedef struct private_isakmp_vendor_t private_isakmp_vendor_t;

/**
 * Private data of an isakmp_vendor_t object.
 */
struct private_isakmp_vendor_t {

	/**
	 * Public isakmp_vendor_t interface.
	 */
	isakmp_vendor_t public;

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

	/* Dead peer detection, RFC 3706 */
	{ "DPD", EXT_DPD, TRUE, 16,
	  "\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00"},

	{ "draft-stenberg-ipsec-nat-traversal-01", 0, FALSE, 16,
	  "\x27\xba\xb5\xdc\x01\xea\x07\x60\xea\x4e\x31\x90\xac\x27\xc0\xd0"},

	{ "draft-stenberg-ipsec-nat-traversal-02", 0, FALSE, 16,
	  "\x61\x05\xc4\x22\xe7\x68\x47\xe4\x3f\x96\x84\x80\x12\x92\xae\xcd"},

	{ "draft-ietf-ipsec-nat-t-ike-00", 0, FALSE, 16,
	  "\x44\x85\x15\x2d\x18\xb6\xbb\xcd\x0b\xe8\xa8\x46\x95\x79\xdd\xcc"},

	{ "draft-ietf-ipsec-nat-t-ike-02", 0, FALSE, 16,
	  "\xcd\x60\x46\x43\x35\xdf\x21\xf8\x7c\xfd\xb2\xfc\x68\xb6\xa4\x48"},

	{ "draft-ietf-ipsec-nat-t-ike-02", 0, FALSE, 16,
	  "\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f"},

	{ "draft-ietf-ipsec-nat-t-ike-03", 0, FALSE, 16,
	  "\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56"},

	{ "Cisco Unity", 0, FALSE, 16,
	  "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00"},
};

METHOD(task_t, build, status_t,
	private_isakmp_vendor_t *this, message_t *message)
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
	private_isakmp_vendor_t *this, message_t *message)
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
	private_isakmp_vendor_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, get_type, task_type_t,
	private_isakmp_vendor_t *this)
{
	return TASK_ISAKMP_VENDOR;
}

METHOD(task_t, destroy, void,
	private_isakmp_vendor_t *this)
{
	free(this);
}

/**
 * See header
 */
isakmp_vendor_t *isakmp_vendor_create(ike_sa_t *ike_sa, bool initiator)
{
	private_isakmp_vendor_t *this;

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
