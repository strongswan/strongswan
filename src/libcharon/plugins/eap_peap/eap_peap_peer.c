/*
 * Copyright (C) 2011 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "eap_peap_peer.h"
#include "eap_peap.h"

#include <debug.h>
#include <daemon.h>

typedef struct private_eap_peap_peer_t private_eap_peap_peer_t;

/**
 * Private data of an eap_peap_peer_t object.
 */
struct private_eap_peap_peer_t {

	/**
	 * Public eap_peap_peer_t interface.
	 */
	eap_peap_peer_t public;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * Outer phase 1 EAP method
	 */
	eap_method_t *ph1;

	/**
	 * Current phase 2 EAP method
	 */
	eap_method_t *ph2;

	/**
	 * Pending outbound EAP message
	 */
	eap_payload_t *out;
};

/**
 * Construct an EAP header and append data
 */
static eap_payload_t *construct_eap(private_eap_peap_peer_t *this, chunk_t data)
{
	payload_t *payload;
	eap_payload_t *eap;
	eap_hdr_t hdr = {
		.code = EAP_REQUEST,
		.identifier = this->ph1->get_identifier(this->ph1),
		.length = ntohs(data.len + sizeof(hdr)),
	};

	data = chunk_cat("cc", chunk_from_thing(hdr), data);
	eap = eap_payload_create_data_own(data);
	payload = &eap->payload_interface;
	if (payload->verify(payload) != SUCCESS)
	{
		eap->destroy(eap);
		return NULL;
	}
	return eap;
}

/**
 * Process an authentication EAP method
 */
static status_t process_phase2(private_eap_peap_peer_t *this, eap_payload_t *in)
{
	status_t status;
	eap_code_t code;
	eap_type_t type, received_type;
	u_int32_t vendor, received_vendor;

	code = in->get_code(in);
	received_type = in->get_type(in, &received_vendor);
	DBG1(DBG_IKE, "received tunneled EAP-PEAP AVP [ EAP/%N/%N ]",
		 eap_code_short_names, code,
		 eap_type_get_names(received_vendor), received_type);

	/* yet another phase2 authentication? */
	if (this->ph2)
	{
		type = this->ph2->get_type(this->ph2, &vendor);

		if (type != received_type || vendor != received_vendor)
		{
			this->ph2->destroy(this->ph2);
			this->ph2 = NULL;
		}
	}

	if (this->ph2 == NULL)
	{
		DBG1(DBG_IKE, "server requested EAP method %N (id 0x%02X)",
			 eap_type_get_names(received_vendor), received_type,
			 in->get_identifier(in));
		this->ph2 = charon->eap->create_instance(charon->eap,
									received_type, received_vendor,
									EAP_PEER, this->server, this->peer);
		if (!this->ph2)
		{
			DBG1(DBG_IKE, "EAP method not supported");
			this->out = eap_payload_create_nak(in->get_identifier(in), 0, 0,
											   in->is_expanded(in));
			in->destroy(in);
			return NEED_MORE;
		}
		type = this->ph2->get_type(this->ph2, &vendor);
	}

	status = this->ph2->process(this->ph2, in, &this->out);
	in->destroy(in);

	switch (status)
	{
		case SUCCESS:
			this->ph2->destroy(this->ph2);
			this->ph2 = NULL;
			/* fall through to NEED_MORE */
		case NEED_MORE:
			return NEED_MORE;
		case FAILED:
		default:
			DBG1(DBG_IKE, "EAP-%N failed", eap_type_get_names(vendor), type);
			return FAILED;
	}
}

/**
 * Create an EAP payload from a buffered writer, prepend header
 */
static eap_payload_t *create_eap_from_writer(private_eap_peap_peer_t *this,
											 bio_writer_t *writer)
{
	chunk_t data;
	eap_hdr_t hdr = {
		.code = EAP_RESPONSE,
		.identifier = this->ph1->get_identifier(this->ph1),
		.length = htons(sizeof(hdr) + writer->get_buf(writer).len),
	};

	data = chunk_cat("cc", chunk_from_thing(hdr), writer->get_buf(writer));
	return eap_payload_create_data_own(data);
}

/**
 * Process a capabilities request
 */
static status_t process_capabilities(private_eap_peap_peer_t *this,
									 bio_reader_t *reader)
{	u_int32_t capabilities;
	bio_writer_t *writer;

	if (!reader->read_uint32(reader, &capabilities))
	{
		return FAILED;
	}

	writer = bio_writer_create(16);
	writer->write_uint8(writer, EAP_EXPANDED);
	writer->write_uint24(writer, PEN_MICROSOFT);
	writer->write_uint32(writer, EAP_MS_CAPABILITES);
	writer->write_uint32(writer, 0);

	this->out = create_eap_from_writer(this, writer);
	writer->destroy(writer);

	return NEED_MORE;
}

/**
 * Process a TLV request
 */
static status_t process_tlv(private_eap_peap_peer_t *this, bio_reader_t *reader)
{
	bio_writer_t *writer;
	u_int16_t type, length, result;
	chunk_t value;
	bool mandatory;

	writer = bio_writer_create(32);
	writer->write_uint8(writer, EAP_MSTLV);

	while (reader->remaining(reader))
	{
		if (!reader->read_uint16(reader, &type) ||
			!reader->read_uint16(reader, &length))
		{
			writer->destroy(writer);
			return FAILED;
		}
		mandatory = type | MSTLV_MANDATORY;
		type &= ~MSTLV_MANDATORY;
		switch (type)
		{
			case MSTLV_RESULT:
				if (length == sizeof(result) &&
					reader->read_uint16(reader, &result))
				{
					/* echo back result */
					writer->write_uint16(writer, MSTLV_RESULT | MSTLV_MANDATORY);
					writer->write_uint16(writer, length);
					writer->write_uint16(writer, result);
					continue;
				}
				break;
			case MSTLV_CRYPTO_BINDING:
				if (reader->read_data(reader, length, &value))
				{
					/* TODO: add crypto binding support */
					continue;
				}
				break;
			case MSTLV_SOH:
			case MSTLV_SOH_REQUEST:
			case MSTLV_VENDOR:
			default:
				DBG1(DBG_IKE, "%smandatory PEAP TLV %d",
					 mandatory ? "received " : "ignoring non-", type);
				if (mandatory || !reader->read_data(reader, length, &value))
				{
					break;
				}
				continue;
		}
		writer->destroy(writer);
		return FAILED;
	}

	this->out = create_eap_from_writer(this, writer);
	writer->destroy(writer);
	return NEED_MORE;
}

/**
 * Process a full EAP packet, EAP_MSTLV or EAP_EXPANDED
 */
static status_t process_eap_with_header(private_eap_peap_peer_t *this,
							bio_reader_t *reader, u_int8_t code, u_int32_t type)
{
	u_int32_t vendor;

	if (type != EAP_EXPANDED)
	{
		DBG1(DBG_IKE, "received tunneled EAP-PEAP AVP [ EAP/%N/%N ]",
			 eap_code_short_names, code, eap_type_short_names, type);
	}
	switch (type)
	{
		case EAP_MSTLV:
			return process_tlv(this, reader);
		case EAP_EXPANDED:
			if (!reader->read_uint24(reader, &vendor) ||
				!reader->read_uint32(reader, &type))
			{
				DBG1(DBG_IKE, "parsing PEAP inner expanded EAP header failed");
				return FAILED;
			}
			DBG1(DBG_IKE, "received tunneled EAP-PEAP AVP [ EAP/%N/%N ]",
				 eap_code_short_names, code,
				 eap_type_get_names(vendor), type);
			if (vendor == PEN_MICROSOFT && type == EAP_MS_CAPABILITES)
			{
				return process_capabilities(this, reader);
			}
			/* no SoH processing here, as it comes with compressed EAP header */
			break;
		default:
			break;
	}
	DBG1(DBG_IKE, "unsupported PEAP payload");
	return FAILED;
}

METHOD(tls_application_t, process, status_t,
	private_eap_peap_peer_t *this, bio_reader_t *reader)
{
	u_int8_t code, identifier, type;
	u_int16_t length;
	eap_payload_t *in;
	chunk_t chunk;

	/* EAP_MSTLV and the capabilities EAP_EXPANDED come with a full EAP header,
	 * identity, SoH and the authentication method with a compressed header.
	 * Try to deduce what we got. */
	chunk = reader->peek(reader);

	if (chunk.len > sizeof(eap_hdr_t) &&
		reader->read_uint8(reader, &code) &&
		reader->read_uint8(reader, &identifier) &&
		reader->read_uint16(reader, &length) &&
		reader->read_uint8(reader, &type) &&
		code == EAP_REQUEST &&
		identifier == this->ph1->get_identifier(this->ph1))
	{
		return process_eap_with_header(this, reader, code, type);
	}
	in = construct_eap(this, chunk);
	/* consume peeked reader bytes */
	reader->read_data(reader, reader->remaining(reader), &chunk);
	if (!in)
	{
		return FAILED;
	}
	return process_phase2(this, in);
}

METHOD(tls_application_t, build, status_t,
	private_eap_peap_peer_t *this, bio_writer_t *writer)
{
	eap_code_t code;
	u_int32_t vendor, type;
	chunk_t data;

	if (this->out)
	{
		code = this->out->get_code(this->out);
		type = this->out->get_type(this->out, &vendor);
		DBG1(DBG_IKE, "sending tunneled EAP-PEAP AVP [ EAP/%N/%N ]",
			 eap_code_short_names, code,
			 eap_type_get_names(vendor), type);

		data = this->out->get_data(this->out);

		if (!(vendor == 0 && type == EAP_MSTLV) &&
			!(vendor == PEN_MICROSOFT && type == EAP_MS_CAPABILITES))
		{
			/* remove EAP header for compressed types */
			data = chunk_skip(data, sizeof(eap_hdr_t));
		}
		writer->write_data(writer, data);

		this->out->destroy(this->out);
		this->out = NULL;

		return NEED_MORE;
	}
	return INVALID_STATE;
}

METHOD(tls_application_t, destroy, void,
	private_eap_peap_peer_t *this)
{
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	DESTROY_IF(this->ph2);
	DESTROY_IF(this->out);
	free(this);
}

/**
 * See header
 */
eap_peap_peer_t *eap_peap_peer_create(identification_t *server,
									  identification_t *peer,
									  eap_method_t *eap_method)
{
	private_eap_peap_peer_t *this;

	INIT(this,
		.public = {
			.application = {
				.process = _process,
				.build = _build,
				.destroy = _destroy,
			},
		},
		.server = server->clone(server),
		.peer = peer->clone(peer),
		.ph1 = eap_method,
	);

	return &this->public;
}
