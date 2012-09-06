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

#include "eap_peap_server.h"
#include "eap_peap.h"

#include <debug.h>
#include <daemon.h>

typedef struct private_eap_peap_server_t private_eap_peap_server_t;

/**
 * Private data of an eap_peap_server_t object.
 */
struct private_eap_peap_server_t {

	/**
	 * Public eap_peap_server_t interface.
	 */
	eap_peap_server_t public;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * Do EAP Identity authentication exchange?
	 */
	bool identity;

	/**
	 * Use Microsoft Statement of Health EAP exchange?
	 */
	bool soh;

	/**
	 * TLS exchange completed?
	 */
	bool tls_completed;

	/**
	 * Result TLV sent?
	 */
	bool result_sent;

	/**
	 * EAP-PEAP phase2 authentication result
	 */
	status_t state;

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
 * Process a TLV request
 */
static status_t process_tlv(private_eap_peap_server_t *this,
							bio_reader_t *reader)
{
	u_int16_t type, length, result;
	chunk_t value;
	bool mandatory;
	status_t status = FAILED;

	while (reader->remaining(reader))
	{
		if (!reader->read_uint16(reader, &type) ||
			!reader->read_uint16(reader, &length))
		{
			return FAILED;
		}
		mandatory = type | MSTLV_MANDATORY;
		type &= ~MSTLV_MANDATORY;
		switch (type)
		{
			case MSTLV_RESULT:
				if (length == sizeof(result) &&
					reader->read_uint16(reader, &result) &&
					result == MSTLV_RESULT_SUCCESS &&
					this->state == SUCCESS)
				{
					status = SUCCESS;
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
		return FAILED;
	}
	return status;
}

/**
 * Process a full EAP packet, EAP_MSTLV or EAP_EXPANDED
 */
static status_t process_eap_with_header(private_eap_peap_server_t *this,
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
			DBG1(DBG_IKE, "received tunneled EAP-PEAP AVP [ EAP/%N/%M ]",
				 eap_code_short_names, code,
				 eap_type_get_names, &vendor, type);
			/* TODO: process requested capabilities? */
			break;
		default:
			break;
	}
	DBG1(DBG_IKE, "unsupported PEAP payload");
	return FAILED;
}

/**
 * Process EAP-Identity response
 */
static status_t process_identity(private_eap_peap_server_t *this,
								 eap_payload_t *in)
{
	eap_payload_t *out;
	chunk_t id;

	switch (this->ph2->process(this->ph2, in, &out))
	{
		case SUCCESS:
			break;
		case NEED_MORE:
			/* not expected */
			out->destroy(out);
			return FAILED;
		default:
			return FAILED;
	}

	if (this->ph2->get_msk(this->ph2, &id) == SUCCESS)
	{
		this->peer->destroy(this->peer);
		this->peer = identification_create_from_data(id);
		DBG1(DBG_IKE, "received tunneled EAP identity '%Y'", this->peer);
	}
	in->destroy(in);
	this->ph2->destroy(this->ph2);
	this->ph2 = NULL;
	this->identity = FALSE;
	return NEED_MORE;
}

/**
 * Process Statement of Health response
 */
static status_t process_soh(private_eap_peap_server_t *this, eap_payload_t *in)
{
	eap_type_t type;
	u_int32_t vendor;

	type = this->ph2->get_type(this->ph2, &vendor);
	switch (this->ph2->process(this->ph2, in, &this->out))
	{
		case SUCCESS:
			DBG1(DBG_IKE, "%N SoH exchange successful", eap_type_names,
				 EAP_PEAP, this->peer, eap_type_get_names, &vendor, type);
			this->ph2->destroy(this->ph2);
			this->ph2 = NULL;
			break;
		case NEED_MORE:
			break;
		case FAILED:
		default:
			DBG1(DBG_IKE, "EAP-%M method failed",
				 eap_type_get_names, &vendor, type);
			this->ph2->destroy(this->ph2);
			this->ph2 = NULL;
			this->state = FAILED;
			break;
	}
	in->destroy(in);
	this->soh = FALSE;
	return NEED_MORE;
}

/**
 * Process EAP authentication method response
 */
static status_t process_auth(private_eap_peap_server_t *this, eap_payload_t *in)
{
	eap_type_t type;
	u_int32_t vendor;

	type = this->ph2->get_type(this->ph2, &vendor);
	switch (this->ph2->process(this->ph2, in, &this->out))
	{
		case SUCCESS:
			DBG1(DBG_IKE, "%N phase2 authentication of '%Y' with %M successful",
				 eap_type_names, EAP_PEAP, this->peer,
				 eap_type_get_names, &vendor, type);
			this->ph2->destroy(this->ph2);
			this->ph2 = NULL;
			this->state = SUCCESS;
			break;
		case NEED_MORE:
			break;
		case FAILED:
		default:
			DBG1(DBG_IKE, "EAP-%M method failed",
				 eap_type_get_names, &vendor, type);
			this->state = FAILED;
			break;
	}
	in->destroy(in);
	return NEED_MORE;
}

/**
 * Construct an EAP header and append data
 */
static eap_payload_t *construct_eap(private_eap_peap_server_t *this,
									chunk_t data)
{
	payload_t *payload;
	eap_payload_t *eap;
	eap_hdr_t hdr = {
		.code = EAP_RESPONSE,
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

METHOD(tls_application_t, process, status_t,
	private_eap_peap_server_t *this, bio_reader_t *reader)
{
	u_int8_t code, identifier, type;
	u_int16_t length;
	u_int32_t vendor;
	eap_payload_t *in;
	chunk_t chunk;

	/* EAP_MSTLV and the capabilities EAP_EXPANDED come with a full EAP header,
	 * identity, SoH and the authentication method with a compressed header.
	 * Try to deduce what we got. */
	chunk = reader->peek(reader);
	if (!chunk.len)
	{
		return NEED_MORE;
	}
	if (chunk.len > sizeof(eap_hdr_t) &&
		reader->read_uint8(reader, &code) &&
		reader->read_uint8(reader, &identifier) &&
		reader->read_uint16(reader, &length) &&
		reader->read_uint8(reader, &type) &&
		code == EAP_RESPONSE &&
		identifier == this->ph1->get_identifier(this->ph1))
	{
		return process_eap_with_header(this, reader, code, type);
	}

	if (chunk.ptr[0] == EAP_NAK)
	{
		DBG1(DBG_IKE, "received EAP-NAK within EAP-PEAP, aborting");
		return FAILED;
	}
	if (!this->ph2)
	{
		return FAILED;
	}
	in = construct_eap(this, chunk);
	/* consume peeked reader bytes */
	reader->read_data(reader, reader->remaining(reader), &chunk);
	if (!in)
	{
		return FAILED;
	}

	type = in->get_type(in, &vendor);
	DBG1(DBG_IKE, "received tunneled EAP-PEAP AVP [ EAP/%N/%M ]",
		 eap_code_short_names, EAP_RESPONSE, eap_type_get_names, &vendor, type);

	if (this->identity)
	{
		return process_identity(this, in);
	}
	if (this->soh)
	{
		return process_soh(this, in);
	}
	return process_auth(this, in);
}

/**
 * Build result TLV
 */
static status_t build_result(private_eap_peap_server_t *this,
							 bio_writer_t *writer, eap_mstlv_result_t result)
{
	writer->write_uint8(writer, EAP_REQUEST);
	writer->write_uint8(writer, this->ph1->get_identifier(this->ph1));
	/* write complete EAP packet length */
	writer->write_uint16(writer, 11);
	writer->write_uint8(writer, EAP_MSTLV);
	/* TLV type: Result */
	writer->write_uint16(writer, MSTLV_RESULT | MSTLV_MANDATORY);
	/* TLV length */
	writer->write_uint16(writer, 2);
	writer->write_uint16(writer, result);

	DBG1(DBG_IKE, "sending tunneled EAP-PEAP AVP [ EAP/%N/%N ]",
		 eap_code_short_names, EAP_REQUEST, eap_type_short_names, EAP_MSTLV);

	this->result_sent = TRUE;

	return NEED_MORE;
}

/**
 * Write stored EAP payload to writer
 */
static status_t build_eap(private_eap_peap_server_t *this, bio_writer_t *writer)
{
	u_int32_t type, vendor;
	chunk_t data;

	if (!this->out)
	{
		return INVALID_STATE;
	}
	type = this->out->get_type(this->out, &vendor);
	DBG1(DBG_IKE, "sending tunneled EAP-PEAP AVP [ EAP/%N/%M ]",
		 eap_code_short_names, this->out->get_code(this->out),
		 eap_type_get_names, &vendor, type);

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

/**
 * Initiate an arbitrary EAP method
 */
static status_t initiate_eap(private_eap_peap_server_t *this, eap_type_t type,
							 u_int32_t vendor, bio_writer_t *writer)
{
	this->ph2 = charon->eap->create_instance(charon->eap, type,
								vendor, EAP_SERVER, this->server, this->peer);
	if (!this->ph2)
	{
		DBG1(DBG_IKE, "EAP-%M method not available",
			 eap_type_get_names, &vendor, type);
		return FAILED;
	}
	this->ph2->set_identifier(this->ph2, this->ph1->get_identifier(this->ph1));
	if (this->ph2->initiate(this->ph2, &this->out) != NEED_MORE)
	{
		DBG1(DBG_IKE, "initiating %M within PEAP failed",
			 eap_type_get_names, &vendor, type);
		return FAILED;
	}
	return build_eap(this, writer);
}

/**
 * Initiate inner authentication method
 */
static status_t initiate_auth(private_eap_peap_server_t *this,
							  bio_writer_t *writer)
{
	eap_type_t type;
	u_int32_t vendor;
	char *str;

	str = lib->settings->get_str(lib->settings,
								 "%s.plugins.eap-peap.ph2_method", "mschapv2",
								 charon->name);
	type = eap_type_from_string(str, &vendor);
	if (!type)
	{
		DBG1(DBG_IKE, "unknown EAP method: %s", str);
		return FAILED;
	}
	DBG1(DBG_IKE, "initiating %N inner authentication with EAP-%M",
		 eap_type_names, EAP_PEAP, eap_type_get_names, &vendor, type);
	return initiate_eap(this, type, vendor, writer);
}

METHOD(tls_application_t, build, status_t,
	private_eap_peap_server_t *this, bio_writer_t *writer)
{
	if (!this->tls_completed)
	{
		/* don't piggyback application data to TLS handshake */
		this->tls_completed = TRUE;
		return INVALID_STATE;
	}

	switch (this->state)
	{
		case NEED_MORE:
			if (this->ph2)
			{
				return build_eap(this, writer);
			}
			if (this->identity)
			{
				return initiate_eap(this, EAP_IDENTITY, 0, writer);
			}
			if (this->soh)
			{
				return initiate_eap(this, EAP_MS_SOH, PEN_MICROSOFT, writer);
			}
			return initiate_auth(this, writer);
		case SUCCESS:
			if (this->result_sent)
			{
				return INVALID_STATE;
			}
			return build_result(this, writer, MSTLV_RESULT_SUCCESS);
		case FAILED:
			if (this->result_sent)
			{
				return INVALID_STATE;
			}
			return build_result(this, writer, MSTLV_RESULT_FAILURE);
		default:
			return FAILED;
	}
}

METHOD(tls_application_t, destroy, void,
	private_eap_peap_server_t *this)
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
eap_peap_server_t *eap_peap_server_create(identification_t *server,
										  identification_t *peer,
										  eap_method_t *eap_method)
{
	private_eap_peap_server_t *this;

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
		.state = NEED_MORE,
		.identity = lib->settings->get_bool(lib->settings,
							"%s.plugins.eap-peap.identity", TRUE, charon->name),
		.soh = lib->settings->get_bool(lib->settings,
							"%s.plugins.eap-peap.soh", FALSE, charon->name),
	);

	return &this->public;
}
