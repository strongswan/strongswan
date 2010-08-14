/*
 * Copyright (C) 2010 Andreas Steffen
 * Copyright (C) 2010 HSR Hochschule fuer Technik Rapperswil
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

#include "eap_ttls_peer.h"

#include <debug.h>
#include <daemon.h>

#include <sa/authenticators/eap/eap_method.h>

#define AVP_EAP_MESSAGE		79

typedef struct private_eap_ttls_peer_t private_eap_ttls_peer_t;

/**
 * Private data of an eap_ttls_peer_t object.
 */
struct private_eap_ttls_peer_t {

	/**
	 * Public eap_ttls_peer_t interface.
	 */
	eap_ttls_peer_t public;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * Current EAP-TTLS state
	 */
	bool start_phase2;

	/**
     * Current phase 2 EAP method 
	 */
	eap_method_t *method;

	/**
     * Pending outbound EAP message 
	 */
	eap_payload_t *out;
};

/**
 * Send an EAP-Message Attribute-Value Pair
 */
static void send_avp_eap_message(tls_writer_t *writer, chunk_t data)
{
	char zero_padding[] = { 0x00, 0x00, 0x00 };
	chunk_t   avp_padding;
	u_int8_t  avp_flags;
	u_int32_t avp_len;

	avp_flags = 0x40;
	avp_len = 8 + data.len;
	avp_padding = chunk_create(zero_padding, (4 - data.len) % 4);

	writer->write_uint32(writer, AVP_EAP_MESSAGE);
	writer->write_uint8(writer, avp_flags);
	writer->write_uint24(writer, avp_len);
	writer->write_data(writer, data);
	writer->write_data(writer, avp_padding);
}

/**
 * Process an EAP-Message Attribute-Value Pair
 */
static status_t process_avp_eap_message(tls_reader_t *reader, chunk_t *data)
{
	u_int32_t avp_code;
	u_int8_t  avp_flags;
	u_int32_t avp_len, data_len;

	if (!reader->read_uint32(reader, &avp_code) ||
		!reader->read_uint8(reader, &avp_flags) ||
		!reader->read_uint24(reader, &avp_len))
	{
		DBG1(DBG_IKE, "received invalid AVP");
		return FAILED;
	}
 	if (avp_code != AVP_EAP_MESSAGE)
	{
		DBG1(DBG_IKE, "expected AVP_EAP_MESSAGE but received %u", avp_code);
		return FAILED;
	}
	data_len = avp_len - 8;
	if (!reader->read_data(reader, data_len + (4 - avp_len) % 4, data))
	{
		DBG1(DBG_IKE, "received insufficient AVP data");
		return FAILED;
	}
	data->len = data_len;
	return SUCCESS;	
}

METHOD(tls_application_t, process, status_t,
	private_eap_ttls_peer_t *this, tls_reader_t *reader)
{
	chunk_t data;
	status_t status;
	payload_t *payload;
	eap_payload_t *in;
	eap_code_t code;
	eap_type_t type;
	u_int32_t vendor;

	status = process_avp_eap_message(reader, &data);
	if (status == FAILED)
	{
		return FAILED;
	}
	in = eap_payload_create_data(data);
	payload = (payload_t*)in;

	if (payload->verify(payload) != SUCCESS)
	{
		in->destroy(in);
		return FAILED;
	}
	code = in->get_code(in);
	type = in->get_type(in, &vendor);
	DBG1(DBG_IKE, "received tunneled EAP-TTLS AVP [EAP/%N/%N]",
				   eap_code_short_names, code, eap_type_short_names, type);

	if (code != EAP_REQUEST)
	{
		in->destroy(in);
		return FAILED;
	}

	if (this->method == NULL)
	{
		if (vendor)
		{
			DBG1(DBG_IKE, "server requested vendor specific EAP method %d-%d",
				 type, vendor);
		}
		else
		{
			DBG1(DBG_IKE, "server requested %N authentication",
				 eap_type_names, type);
		}
		this->method = charon->eap->create_instance(charon->eap, type, vendor,
									EAP_PEER, this->server, this->peer);
		if (!this->method)
		{
			u_int8_t identifier = in->get_identifier(in);

			DBG1(DBG_IKE, "EAP method not supported, sending EAP_NAK");
			in->destroy(in);
			this->out = eap_payload_create_nak(identifier);
			in->destroy(in);
			return NEED_MORE;
		}
	}
		
	type = this->method->get_type(this->method, &vendor);

	if (this->method->process(this->method, in, &this->out) == NEED_MORE)
	{
		in->destroy(in);
		return NEED_MORE;
	}

	if (vendor)
	{
		DBG1(DBG_IKE, "vendor specific EAP method %d-%d failed", type, vendor);
	}
	else
	{
		DBG1(DBG_IKE, "%N method failed", eap_type_names, type);
	}
	in->destroy(in);
	return FAILED;
}

METHOD(tls_application_t, build, status_t,
	private_eap_ttls_peer_t *this, tls_writer_t *writer)
{
	chunk_t data;
	eap_code_t code;
	eap_type_t type;
	u_int32_t vendor;

	if (this->method == NULL && this->start_phase2)
	{
		/* generate an EAP Identity response */
		this->method = charon->eap->create_instance(charon->eap, EAP_IDENTITY,
								 0,	EAP_PEER, this->server, this->peer);
		if (this->method == NULL)
		{
			DBG1(DBG_IKE, "EAP_IDENTITY method not available");
			return FAILED;
		}
		this->method->process(this->method, NULL, &this->out);
		this->method->destroy(this->method);
		this->method = NULL;
		this->start_phase2 = FALSE;
	}

	if (this->out)
	{
		code = this->out->get_code(this->out);
		type = this->out->get_type(this->out, &vendor);
		DBG1(DBG_IKE, "sending tunneled EAP-TTLS AVP [EAP/%N/%N]",
						eap_code_short_names, code, eap_type_short_names, type);

		/* get the raw EAP message data */
		data = this->out->get_data(this->out);
		send_avp_eap_message(writer, data);

		this->out->destroy(this->out);
		this->out = NULL;
	}
	return INVALID_STATE;
}

METHOD(tls_application_t, destroy, void,
	private_eap_ttls_peer_t *this)
{
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	DESTROY_IF(this->method);
	DESTROY_IF(this->out);
	free(this);
}

/**
 * See header
 */
eap_ttls_peer_t *eap_ttls_peer_create(identification_t *server,
									  identification_t *peer)
{
	private_eap_ttls_peer_t *this;

	INIT(this,
		.public.application = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.server = server->clone(server),
		.peer = peer->clone(peer),
		.start_phase2 = TRUE,
		.method = NULL,
		.out = NULL,
	);

	return &this->public;
}
