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

#include "tls_eap.h"

#include "tls.h"

#include <debug.h>
#include <library.h>

/** Size limit for a single TLS message */
#define MAX_TLS_MESSAGE_LEN 65536

typedef struct private_tls_eap_t private_tls_eap_t;

/**
 * Private data of an tls_eap_t object.
 */
struct private_tls_eap_t {

	/**
	 * Public tls_eap_t interface.
	 */
	tls_eap_t public;

	/**
	 * Type of EAP method, EAP-TLS or EAP-TTLS
	 */
	eap_type_t type;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * Role
	 */
	bool is_server;

	/**
	 * First fragment of a multi-fragment record?
	 */
	bool first_fragment;

	/**
	 * Maximum size of an outgoing EAP-TLS fragment
	 */
	size_t frag_size;
};

/**
 * Flags of an EAP-TLS/TTLS message
 */
typedef enum {
	EAP_TLS_LENGTH = (1<<7),
	EAP_TLS_MORE_FRAGS = (1<<6),
	EAP_TLS_START = (1<<5),
	EAP_TTLS_VERSION = (0x07),
} eap_tls_flags_t;

/**
 * EAP-TLS/TTLS packet format
 */
typedef struct __attribute__((packed)) {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;
	u_int8_t type;
	u_int8_t flags;
} eap_tls_packet_t;

METHOD(tls_eap_t, initiate, status_t,
	private_tls_eap_t *this, chunk_t *out)
{
	if (this->is_server)
	{
		eap_tls_packet_t pkt = {
			.type = this->type,
			.code = EAP_REQUEST,
			.flags = EAP_TLS_START,
		};
		htoun16(&pkt.length, sizeof(eap_tls_packet_t));
		do
		{	/* start with non-zero random identifier */
			pkt.identifier = random();
		}
		while (!pkt.identifier);

		DBG2(DBG_IKE, "sending %N start packet", eap_type_names, this->type);
		*out = chunk_clone(chunk_from_thing(pkt));
		return NEED_MORE;
	}
	return FAILED;
}

/**
 * Process a received packet
 */
static status_t process_pkt(private_tls_eap_t *this, eap_tls_packet_t *pkt)
{
	u_int32_t msg_len;
	u_int16_t pkt_len;

	pkt_len = untoh16(&pkt->length);
	if (pkt->flags & EAP_TLS_LENGTH)
	{
		if (pkt_len < sizeof(eap_tls_packet_t) + sizeof(msg_len))
		{
			DBG1(DBG_TLS, "%N packet too short", eap_type_names, this->type);
			return FAILED;
		}
		msg_len = untoh32(pkt + 1);
		if (msg_len < pkt_len - sizeof(eap_tls_packet_t) - sizeof(msg_len) ||
			msg_len > MAX_TLS_MESSAGE_LEN)
		{
			DBG1(DBG_TLS, "invalid %N packet length", eap_type_names, this->type);
			return FAILED;
		}
		return this->tls->process(this->tls, (char*)(pkt + 1) + sizeof(msg_len),
						pkt_len - sizeof(eap_tls_packet_t) - sizeof(msg_len));
	}
	return this->tls->process(this->tls, (char*)(pkt + 1),
							  pkt_len - sizeof(eap_tls_packet_t));
}

/**
 * Build a packet to send
 */
static status_t build_pkt(private_tls_eap_t *this,
						  u_int8_t identifier, chunk_t *out)
{
	char buf[this->frag_size];
	eap_tls_packet_t *pkt;
	size_t len, reclen;
	status_t status;
	char *kind;

	pkt = (eap_tls_packet_t*)buf;
	pkt->code = this->is_server ? EAP_REQUEST : EAP_RESPONSE;
	pkt->identifier = this->is_server ? identifier + 1 : identifier;
	pkt->type = this->type;
	pkt->flags = 0;

	if (this->first_fragment)
	{
		pkt->flags = EAP_TLS_LENGTH;
		len = sizeof(buf) - sizeof(eap_tls_packet_t) - sizeof(u_int32_t);
		status = this->tls->build(this->tls, buf + sizeof(eap_tls_packet_t) +
								  sizeof(u_int32_t), &len, &reclen);
	}
	else
	{
		len = sizeof(buf) - sizeof(eap_tls_packet_t);
		status = this->tls->build(this->tls, buf + sizeof(eap_tls_packet_t),
								  &len, &reclen);
	}
	switch (status)
	{
		case NEED_MORE:
			pkt->flags |= EAP_TLS_MORE_FRAGS;
			kind = "non-first fragment";
			if (this->first_fragment)
			{
				this->first_fragment = FALSE;
				kind = "first fragment";
			}
			break;
		case ALREADY_DONE:
			kind = "packet";
			if (!this->first_fragment)
			{
				this->first_fragment = TRUE;
				kind = "final fragment";
			}
			break;
		default:
			return status;
	}
	DBG2(DBG_TLS, "sending %N %s (%u bytes)",
		 eap_type_names, this->type, kind, len);
	if (reclen)
	{
		htoun32(pkt + 1, reclen);
		len += sizeof(u_int32_t);
		pkt->flags |= EAP_TLS_LENGTH;
	}
	len += sizeof(eap_tls_packet_t);
	htoun16(&pkt->length, len);
	*out = chunk_clone(chunk_create(buf, len));
	return NEED_MORE;
}

/**
 * Send an ack to request next fragment
 */
static chunk_t create_ack(private_tls_eap_t *this, u_int8_t identifier)
{
	eap_tls_packet_t pkt = {
		.code = this->is_server ? EAP_REQUEST : EAP_RESPONSE,
		.identifier = this->is_server ? identifier + 1 : identifier,
		.type = this->type,
	};
	htoun16(&pkt.length, sizeof(pkt));
	DBG2(DBG_TLS, "sending %N acknowledgement packet",
		 eap_type_names, this->type);
	return chunk_clone(chunk_from_thing(pkt));
}

METHOD(tls_eap_t, process, status_t,
	private_tls_eap_t *this, chunk_t in, chunk_t *out)
{
	eap_tls_packet_t *pkt;
	status_t status;

	pkt = (eap_tls_packet_t*)in.ptr;
	if (in.len < sizeof(eap_tls_packet_t) ||
		untoh16(&pkt->length) != in.len)
	{
		DBG1(DBG_IKE, "invalid EAP-TLS packet length");
		return FAILED;
	}
	if (pkt->flags & EAP_TLS_START)
	{
		if (this->type == EAP_TTLS)
		{
			DBG1(DBG_TLS, "EAP-TTLS version is v%u",
				 pkt->flags & EAP_TTLS_VERSION);
		}
	}
	else
	{
		if (in.len == sizeof(eap_tls_packet_t))
		{
			DBG2(DBG_TLS, "received %N acknowledgement packet",
				 eap_type_names, this->type);
			status = build_pkt(this, pkt->identifier, out);
			if (status == INVALID_STATE &&
				this->tls->is_complete(this->tls))
			{
				return SUCCESS;
			}
			return status;
		}
		status = process_pkt(this, pkt);
		if (status != NEED_MORE)
		{
			return status;
		}
	}
	status = build_pkt(this, pkt->identifier, out);
	switch (status)
	{
		case INVALID_STATE:
			*out = create_ack(this, pkt->identifier);
			return NEED_MORE;
		case FAILED:
			if (!this->is_server)
			{
				*out = create_ack(this, pkt->identifier);
				return NEED_MORE;
			}
			return FAILED;
		default:
			return status;
	}
}

METHOD(tls_eap_t, get_msk, chunk_t,
	private_tls_eap_t *this)
{
	return this->tls->get_eap_msk(this->tls);
}

METHOD(tls_eap_t, destroy, void,
	private_tls_eap_t *this)
{
	this->tls->destroy(this->tls);
	free(this);
}

/**
 * See header
 */
tls_eap_t *tls_eap_create(eap_type_t type, bool is_server,
						  identification_t *server, identification_t *peer,
						  tls_application_t *application, size_t frag_size)
{
	private_tls_eap_t *this;
	tls_purpose_t purpose;

	switch (type)
	{
		case EAP_TLS:
			purpose = TLS_PURPOSE_EAP_TLS;
			break;
		case EAP_TTLS:
			purpose = TLS_PURPOSE_EAP_TTLS;
			break;
		default:
			return NULL;
	};

	INIT(this,
		.public = {
			.initiate = _initiate,
			.process = _process,
			.get_msk = _get_msk,
			.destroy = _destroy,
		},
		.type = type,
		.is_server = is_server,
		.first_fragment = TRUE,
		.frag_size = frag_size,
		.tls = tls_create(is_server, server, peer, purpose, application),
	);
	if (!this->tls)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}
