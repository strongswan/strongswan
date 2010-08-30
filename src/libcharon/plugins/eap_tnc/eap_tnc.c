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

#include "eap_tnc.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_tnc_t private_eap_tnc_t;

/**
 * Private data of an eap_tnc_t object.
 */
struct private_eap_tnc_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_tnc_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;
};

/**
 * Flags of an EAP-TNC message
 */
typedef enum {
	EAP_TNC_LENGTH = (1<<7),
	EAP_TNC_MORE_FRAGS = (1<<6),
	EAP_TNC_START = (1<<5),
	EAP_TNC_DH = (1<<4),
	EAP_TNC_VERSION = 0x07
} eap_tnc_flags_t;

/**
 * EAP-TNC packet format
 */
typedef struct __attribute__((packed)) {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;
	u_int8_t type;
	u_int8_t flags;
} eap_tnc_packet_t;

METHOD(eap_method_t, initiate_peer, status_t,
	private_eap_tnc_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

METHOD(eap_method_t, initiate_server, status_t,
	private_eap_tnc_t *this, eap_payload_t **out)
{
	return NEED_MORE;
}

METHOD(eap_method_t, process_peer, status_t,
	private_eap_tnc_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_tnc_packet_t *pkt;
	chunk_t data;

	data = in->get_data(in);

	pkt = (eap_tnc_packet_t*)data.ptr;
	if (data.len < sizeof(eap_tnc_packet_t) ||
		untoh16(&pkt->length) != data.len)
	{
		DBG1(DBG_IKE, "invalid EAP-TNC packet length");
		return FAILED;
	}
	if (pkt->flags & EAP_TNC_START)
	{
		DBG1(DBG_IKE, "EAP-TNC version is v%u", pkt->flags & EAP_TNC_VERSION);
	}
	*out = eap_payload_create_nak(in->get_identifier(in));

	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	private_eap_tnc_t *this, eap_payload_t *in, eap_payload_t **out)
{
	chunk_t data;

	data = in->get_data(in);
	DBG2(DBG_IKE, "received EAP-TNC data: %B", &data);

	return SUCCESS;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_tnc_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_TNC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_tnc_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_tnc_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_tnc_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/*
 * See header
 */
eap_tnc_t *eap_tnc_create_server(identification_t *server, identification_t *peer)
{
	private_eap_tnc_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_server,
				.process = _process_server,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

	return &this->public;
}

/*
 * See header
 */
eap_tnc_t *eap_tnc_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_tnc_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_peer,
				.process = _process_peer,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

	return &this->public;
}

