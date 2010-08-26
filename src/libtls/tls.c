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

#include "tls.h"

#include <debug.h>

#include "tls_protection.h"
#include "tls_compression.h"
#include "tls_fragmentation.h"
#include "tls_crypto.h"
#include "tls_server.h"
#include "tls_peer.h"

ENUM_BEGIN(tls_version_names, SSL_2_0, SSL_2_0,
	"SSLv2");
ENUM_NEXT(tls_version_names, SSL_3_0, TLS_1_2, SSL_2_0,
	"SSLv3",
	"TLS 1.0",
	"TLS 1.1",
	"TLS 1.2");
ENUM_END(tls_version_names, TLS_1_2);

ENUM(tls_content_type_names, TLS_CHANGE_CIPHER_SPEC, TLS_APPLICATION_DATA,
	"ChangeCipherSpec",
	"Alert",
	"Handshake",
	"ApplicationData",
);

ENUM_BEGIN(tls_handshake_type_names, TLS_HELLO_REQUEST, TLS_SERVER_HELLO,
	"HelloRequest",
	"ClientHello",
	"ServerHello");
ENUM_NEXT(tls_handshake_type_names, TLS_CERTIFICATE, TLS_CLIENT_KEY_EXCHANGE, TLS_SERVER_HELLO,
	"Certificate",
	"ServerKeyExchange",
	"CertificateRequest",
	"ServerHelloDone",
	"CertificateVerify",
	"ClientKeyExchange");
ENUM_NEXT(tls_handshake_type_names, TLS_FINISHED, TLS_FINISHED, TLS_CLIENT_KEY_EXCHANGE,
	"Finished");
ENUM_END(tls_handshake_type_names, TLS_FINISHED);


typedef struct private_tls_t private_tls_t;

/**
 * Private data of an tls_protection_t object.
 */
struct private_tls_t {

	/**
	 * Public tls_t interface.
	 */
	tls_t public;

	/**
	 * Role this TLS stack acts as.
	 */
	bool is_server;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * Negotiated TLS version
	 */
	tls_version_t version;

	/**
	 * TLS stack purpose, as given to constructor
	 */
	tls_purpose_t purpose;

	/**
	 * TLS record protection layer
	 */
	tls_protection_t *protection;

	/**
	 * TLS record compression layer
	 */
	tls_compression_t *compression;

	/**
	 * TLS record fragmentation layer
	 */
	tls_fragmentation_t *fragmentation;

	/**
	 * TLS alert handler
	 */
	tls_alert_t *alert;

	/**
	 * TLS crypto helper context
	 */
	tls_crypto_t *crypto;

	/**
	 * TLS handshake protocol handler
	 */
	tls_handshake_t *handshake;

	/**
	 * TLS application data handler
	 */
	tls_application_t *application;

	/**
	 * Allocated input buffer
	 */
	chunk_t input;

	/**
	 * Number of bytes read in input buffer
	 */
	size_t inpos;
};

/**
 * TLS record
 */
typedef struct __attribute__((packed)) {
	u_int8_t type;
	u_int16_t version;
	u_int16_t length;
	char data[];
} tls_record_t;

METHOD(tls_t, process, status_t,
	private_tls_t *this, chunk_t data)
{
	tls_record_t *record;
	status_t status;
	u_int len;

	while (data.len > sizeof(tls_record_t))
	{
		if (this->input.len == 0)
		{
			while (TRUE)
			{
				/* try to process records inline */
				record = (tls_record_t*)data.ptr;
				len = untoh16(&record->length);

				if (len + sizeof(tls_record_t) > data.len)
				{	/* not a full record, read to buffer */
					this->input = chunk_alloc(len + sizeof(tls_record_t));
					this->inpos = 0;
					break;
				}
				DBG2(DBG_TLS, "processing TLS %N record (%d bytes)",
					 tls_content_type_names, record->type, len);
				status = this->protection->process(this->protection,
								record->type, chunk_create(record->data, len));
				if (status != NEED_MORE)
				{
					return status;
				}
				data = chunk_skip(data, len + sizeof(tls_record_t));
				if (data.len == 0)
				{
					return NEED_MORE;
				}
			}
		}
		len = min(data.len, this->input.len - this->inpos);
		memcpy(this->input.ptr + this->inpos, data.ptr, len);
		data = chunk_skip(data, len);
		this->inpos += len;
		DBG2(DBG_TLS, "buffering %d bytes, %d bytes of %d byte record received",
			 len, this->inpos, this->input.len);
		if (this->input.len == this->inpos)
		{
			record = (tls_record_t*)this->input.ptr;
			len = untoh16(&record->length);

			DBG2(DBG_TLS, "processing buffered TLS %N record (%d bytes)",
				 tls_content_type_names, record->type, len);
			status = this->protection->process(this->protection,
								record->type, chunk_create(record->data, len));
			chunk_free(&this->input);
			this->inpos = 0;
			if (status != NEED_MORE)
			{
				return status;
			}
		}
	}
	if (data.len != 0)
	{
		DBG1(DBG_TLS, "received incomplete TLS record header");
		return FAILED;
	}
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tls_t *this, chunk_t *data)
{
	tls_record_t record;
	status_t status;

	*data = chunk_empty;
	while (TRUE)
	{
		tls_content_type_t type;
		chunk_t body;

		status = this->protection->build(this->protection, &type, &body);
		switch (status)
		{
			case INVALID_STATE:
				return NEED_MORE;
			case NEED_MORE:
				break;
			default:
				return status;
		}
		record.type = type;
		htoun16(&record.version, this->version);
		htoun16(&record.length, body.len);
		*data = chunk_cat("mcm", *data, chunk_from_thing(record), body);
		DBG2(DBG_TLS, "sending TLS %N record (%u bytes)",
			 tls_content_type_names, type, sizeof(tls_record_t) + body.len);
	}
}

METHOD(tls_t, is_server, bool,
	private_tls_t *this)
{
	return this->is_server;
}

METHOD(tls_t, get_version, tls_version_t,
	private_tls_t *this)
{
	return this->version;
}

METHOD(tls_t, set_version, bool,
	private_tls_t *this, tls_version_t version)
{
	if (version > this->version)
	{
		return FALSE;
	}
	switch (version)
	{
		case TLS_1_0:
		case TLS_1_1:
		case TLS_1_2:
			this->version = version;
			this->protection->set_version(this->protection, version);
			return TRUE;
		case SSL_2_0:
		case SSL_3_0:
		default:
			return FALSE;
	}
}

METHOD(tls_t, get_purpose, tls_purpose_t,
	private_tls_t *this)
{
	return this->purpose;
}

METHOD(tls_t, is_complete, bool,
	private_tls_t *this)
{
	if (this->handshake->finished(this->handshake))
	{
		if (!this->application)
		{
			return TRUE;
		}
		return this->fragmentation->application_finished(this->fragmentation);
	}
	return FALSE;
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tls_t *this)
{
	return this->crypto->get_eap_msk(this->crypto);
}

METHOD(tls_t, destroy, void,
	private_tls_t *this)
{
	this->protection->destroy(this->protection);
	this->compression->destroy(this->compression);
	this->fragmentation->destroy(this->fragmentation);
	this->crypto->destroy(this->crypto);
	this->handshake->destroy(this->handshake);
	DESTROY_IF(this->peer);
	this->server->destroy(this->server);
	DESTROY_IF(this->application);
	this->alert->destroy(this->alert);

	free(this->input.ptr);

	free(this);
}

/**
 * See header
 */
tls_t *tls_create(bool is_server, identification_t *server,
				  identification_t *peer, tls_purpose_t purpose,
				  tls_application_t *application)
{
	private_tls_t *this;

	switch (purpose)
	{
		case TLS_PURPOSE_EAP_TLS:
		case TLS_PURPOSE_EAP_TTLS:
		case TLS_PURPOSE_GENERIC:
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.is_server = _is_server,
			.get_version = _get_version,
			.set_version = _set_version,
			.get_purpose = _get_purpose,
			.is_complete = _is_complete,
			.get_eap_msk = _get_eap_msk,
			.destroy = _destroy,
		},
		.is_server = is_server,
		.version = TLS_1_2,
		.server = server->clone(server),
		.peer = peer ? peer->clone(peer) : NULL,
		.application = application,
		.purpose = purpose,
	);

	this->crypto = tls_crypto_create(&this->public);
	this->alert = tls_alert_create();
	if (is_server)
	{
		this->handshake = &tls_server_create(&this->public, this->crypto,
							this->alert, this->server, this->peer)->handshake;
	}
	else
	{
		this->handshake = &tls_peer_create(&this->public, this->crypto,
							this->alert, this->peer, this->server)->handshake;
	}
	this->fragmentation = tls_fragmentation_create(this->handshake, this->alert,
												   this->application);
	this->compression = tls_compression_create(this->fragmentation, this->alert);
	this->protection = tls_protection_create(this->compression, this->alert);
	this->crypto->set_protection(this->crypto, this->protection);

	return &this->public;
}
