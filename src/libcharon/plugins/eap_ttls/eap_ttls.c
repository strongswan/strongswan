/*
 * Copyright (C) 2010 Martin Willi, revosec AG
 * Copyright (C) 2010 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "eap_ttls.h"
#include "eap_ttls_peer.h"

#include <tls.h>

#include <daemon.h>
#include <library.h>

typedef struct private_eap_ttls_t private_eap_ttls_t;

/**
 * Private data of an eap_ttls_t object.
 */
struct private_eap_ttls_t {

	/**
	 * Public interface.
	 */
	eap_ttls_t public;

	/**
	 * Number of EAP-TLS messages processed so far
	 */
	int processed;

	/**
	 * Is this method instance acting as server?
	 */
	bool is_server;

	/**
	 * TLS layers
	 */
	tls_t *tls;

	/**
	 * Allocated input buffer
	 */
	chunk_t input;

	/**
	 * Number of bytes read in input buffer
	 */
	size_t inpos;

	/**
	 * Allocated ouput buffer
	 */
	chunk_t output;

	/**
	 * Number of bytes sent from output buffer
	 */
	size_t outpos;
};

/** Size limit for a single TLS message */
#define MAX_TLS_MESSAGE_LEN 16384
/** Size of a EAP-TLS fragment */
#define EAP_TTLS_FRAGMENT_LEN 1014
/** Maximum number of EAP-TLS messages/fragments allowed */
#define MAX_EAP_TTLS_MESSAGE_COUNT 16

/**
 * Flags of an EAP-TLS message
 */
typedef enum {
	EAP_TTLS_LENGTH = (1<<7),
	EAP_TTLS_MORE_FRAGS = (1<<6),
	EAP_TTLS_START = (1<<5),
	EAP_TTLS_VERSION = 0x07
} eap_ttls_flags_t;

/**
 * EAP-TLS packet format
 */
typedef struct __attribute__((packed)) {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;
	u_int8_t type;
	u_int8_t flags;
} eap_ttls_packet_t;

/**
 * TLS record
 */
typedef struct __attribute__((packed)) {
	u_int8_t type;
	u_int16_t version;
	u_int16_t length;
	char data[];
} tls_record_t;

METHOD(eap_method_t, initiate, status_t,
	private_eap_ttls_t *this, eap_payload_t **out)
{
	if (this->is_server)
	{
		eap_ttls_packet_t pkt = {
			.type = EAP_TTLS,
			.code = EAP_REQUEST,
			.flags = EAP_TTLS_START,
		};
		htoun16(&pkt.length, sizeof(eap_ttls_packet_t));
		/* start with non-zero random identifier */
		do {
			pkt.identifier = random();
		} while (!pkt.identifier);
		DBG2(DBG_IKE, "sending EAP-TLS start packet");

		*out = eap_payload_create_data(chunk_from_thing(pkt));
		return NEED_MORE;
	}
	return FAILED;
}

/**
 * Write received TLS data to the input buffer
 */
static bool write_buf(private_eap_ttls_t *this, eap_ttls_packet_t *pkt)
{
	u_int32_t msg_len;
	u_int16_t pkt_len;
	chunk_t data;

	pkt_len = untoh16(&pkt->length);

	if (pkt->flags & EAP_TTLS_LENGTH)
	{
		if (pkt_len < sizeof(eap_ttls_packet_t) + sizeof(msg_len))
		{
			DBG1(DBG_IKE, "EAP-TLS packet too short");
			return FALSE;
		}
		msg_len = untoh32(pkt + 1);
		if (msg_len < pkt_len - sizeof(eap_ttls_packet_t) - sizeof(msg_len) ||
			msg_len > MAX_TLS_MESSAGE_LEN)
		{
			DBG1(DBG_IKE, "invalid EAP-TLS packet length");
			return FALSE;
		}
		if (this->input.ptr)
		{
			if (msg_len != this->input.len)
			{
				DBG1(DBG_IKE, "received unexpected TLS message length");
				return FALSE;
			}
		}
		else
		{
			this->input = chunk_alloc(msg_len);
			this->inpos = 0;
		}
		data = chunk_create((char*)(pkt + 1) + sizeof(msg_len),
						pkt_len - sizeof(eap_ttls_packet_t) - sizeof(msg_len));
	}
	else
	{
		data = chunk_create((char*)(pkt + 1),
						pkt_len - sizeof(eap_ttls_packet_t));
	}
	if (data.len > this->input.len - this->inpos)
	{
		DBG1(DBG_IKE, "EAP-TLS fragment exceeds TLS message length");
		return FALSE;
	}
	memcpy(this->input.ptr + this->inpos, data.ptr, data.len);
	this->inpos += data.len;
	return TRUE;
}

/**
 * Send an ack to request next fragment
 */
static eap_payload_t *create_ack(private_eap_ttls_t *this, u_int8_t identifier)
{
	eap_ttls_packet_t pkt = {
		.code = this->is_server ? EAP_REQUEST : EAP_RESPONSE,
		.identifier = this->is_server ? identifier + 1 : identifier,
		.type = EAP_TTLS,
	};
	htoun16(&pkt.length, sizeof(pkt));
	DBG2(DBG_IKE, "sending EAP-TLS acknowledgement packet");

	return eap_payload_create_data(chunk_from_thing(pkt));
}

/**
 * Create a eap response from data in the TLS output buffer
 */
static eap_payload_t *read_buf(private_eap_ttls_t *this, u_int8_t identifier)
{
	char buf[EAP_TTLS_FRAGMENT_LEN + sizeof(eap_ttls_packet_t) + 4], *start;
	eap_ttls_packet_t *pkt = (eap_ttls_packet_t*)buf;
	u_int16_t pkt_len = sizeof(eap_ttls_packet_t);

	pkt->code = this->is_server ? EAP_REQUEST : EAP_RESPONSE;
	pkt->identifier = this->is_server ? identifier + 1 : identifier;
	pkt->type = EAP_TTLS;
	pkt->flags = 0;

	if (this->output.len)
	{
		start = (char*)(pkt + 1);
		if (this->outpos == 0)
		{	/* first fragment */
			pkt->flags = EAP_TTLS_LENGTH;
			pkt_len += 4;
			start += 4;
			htoun32(pkt + 1, this->output.len);
		}

		if (this->output.len - this->outpos > EAP_TTLS_FRAGMENT_LEN)
		{
			pkt->flags |= EAP_TTLS_MORE_FRAGS;
			pkt_len += EAP_TTLS_FRAGMENT_LEN;
			memcpy(start, this->output.ptr + this->outpos, EAP_TTLS_FRAGMENT_LEN);
			this->outpos += EAP_TTLS_FRAGMENT_LEN;
			DBG2(DBG_IKE, "sending EAP-TLS packet fragment");
		}
		else
		{
			pkt_len += this->output.len - this->outpos;
			memcpy(start, this->output.ptr + this->outpos,
				   this->output.len - this->outpos);
			chunk_free(&this->output);
			this->outpos = 0;
			DBG2(DBG_IKE, "sending EAP-TLS packet");
		}
	}
	else
	{
		DBG2(DBG_IKE, "sending EAP-TLS acknowledgement packet");
	}
	htoun16(&pkt->length, pkt_len);
	return eap_payload_create_data(chunk_create(buf, pkt_len));
}

/**
 * Pass data in input buffer to upper layers, write result to output buffer
 */
static status_t process_buf(private_eap_ttls_t *this)
{
	tls_record_t *in, out;
	chunk_t data;
	u_int16_t len;
	status_t status;

	/* pass input buffer to upper layer, record for record */
	data = this->input;
	while (data.len > sizeof(tls_record_t))
	{
		in = (tls_record_t*)data.ptr;
		len = untoh16(&in->length);
		if (len > data.len - sizeof(tls_record_t))
		{
			DBG1(DBG_IKE, "TLS record length invalid");
			return FAILED;
		}
		if (untoh16(&in->version) < TLS_1_0)
		{
			DBG1(DBG_IKE, "%N invalid with EAP-TLS",
				 tls_version_names, untoh16(&in->version));
			return FAILED;
		}

		status = this->tls->process(this->tls, in->type,
									chunk_create(in->data, len));
		if (status != NEED_MORE)
		{
			return status;
		}
		data = chunk_skip(data, len + sizeof(tls_record_t));
	}
	chunk_free(&this->input);
	this->inpos = 0;

	/* read in records from upper layer, append to output buffer */
	chunk_free(&this->output);
	while (TRUE)
	{
		tls_content_type_t type;
		chunk_t header = chunk_from_thing(out);

		status = this->tls->build(this->tls, &type, &data);
		switch (status)
		{
			case NEED_MORE:
				break;
			case INVALID_STATE:
				/* invalid state means we need more input from peer first */
				return NEED_MORE;
			case SUCCESS:
				return SUCCESS;
			case FAILED:
			default:
				return FAILED;
		}
		out.type = type;
		htoun16(&out.version, this->tls->get_version(this->tls));
		htoun16(&out.length, data.len);
		this->output = chunk_cat("mcm", this->output, header, data);
	}
}

METHOD(eap_method_t, process, status_t,
	private_eap_ttls_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_ttls_packet_t *pkt;
	chunk_t data;
	status_t status;

	if (++this->processed > MAX_EAP_TTLS_MESSAGE_COUNT)
	{
		DBG1(DBG_IKE, "EAP-TTLS packet count exceeded");
		return FAILED;
	}

	data = in->get_data(in);

	pkt = (eap_ttls_packet_t*)data.ptr;
	if (data.len < sizeof(eap_ttls_packet_t) ||
		untoh16(&pkt->length) != data.len)
	{
		DBG1(DBG_IKE, "invalid EAP-TLS packet length");
		return FAILED;
	}
	if (pkt->flags & EAP_TTLS_START)
	{
		DBG1(DBG_IKE, "EAP-TTLS version is v%u",
		pkt->flags & EAP_TTLS_VERSION);
	}
	else
	{
		if (data.len == sizeof(eap_ttls_packet_t))
		{
			if (this->output.len)
			{	/* ACK to our fragment, send next */
				*out = read_buf(this, pkt->identifier);
				return NEED_MORE;
			}
			if (this->tls->is_complete(this->tls))
			{
				return SUCCESS;
			}
			return FAILED;
		}
		if (!write_buf(this, pkt))
		{
			return FAILED;
		}
		if (pkt->flags & EAP_TTLS_MORE_FRAGS)
		{	/* more fragments follow */
			*out = create_ack(this, pkt->identifier);
			return NEED_MORE;
		}
		else if (this->input.len != this->inpos)
		{
			DBG1(DBG_IKE, "defragmented TLS message has invalid length");
			return FAILED;
		}
	}
	status = process_buf(this);
	if (status == NEED_MORE)
	{
		*out = read_buf(this, pkt->identifier);
	}
	return status;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_ttls_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_TTLS;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_ttls_t *this, chunk_t *msk)
{
	*msk = this->tls->get_eap_msk(this->tls);
	if (msk->len)
	{
		return SUCCESS;
	}
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_ttls_t *this)
{
	return TRUE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_ttls_t *this)
{
	free(this->input.ptr);
	free(this->output.ptr);

	this->tls->destroy(this->tls);

	free(this);
}

/**
 * Generic private constructor
 */
static eap_ttls_t *eap_ttls_create(identification_t *server,
								 identification_t *peer, bool is_server,
								 tls_application_t *application)
{
	private_eap_ttls_t *this;

	INIT(this,
		.public.eap_method = {
			.initiate = _initiate,
			.process = _process,
			.get_type = _get_type,
			.is_mutual = _is_mutual,
			.get_msk = _get_msk,
			.destroy = _destroy,
		},
		.is_server = is_server,
	);
	/* MSK PRF ASCII constant label according to EAP-TTLS RFC 5281 */
	this->tls = tls_create(is_server, server, peer, "ttls keying material",
						   application);
	return &this->public;
}

eap_ttls_t *eap_ttls_create_server(identification_t *server,
								 identification_t *peer)
{
	return eap_ttls_create(server, peer, TRUE, NULL);
}

eap_ttls_t *eap_ttls_create_peer(identification_t *server,
							   identification_t *peer)
{
	return eap_ttls_create(server, peer, FALSE,
						   &eap_ttls_peer_create(peer)->application);
}
