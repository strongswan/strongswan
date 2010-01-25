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

#include "tls_protection.h"
#include "tls_compression.h"
#include "tls_fragmentation.h"
#include "tls_crypto.h"
#include "tls_server.h"
#include "tls_peer.h"

#include <daemon.h>

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
	 * Negotiated TLS version
	 */
	tls_version_t version;

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
	 * TLS crypto helper context
	 */
	tls_crypto_t *crypto;

	/**
	 * TLS handshake protocol handler
	 */
	tls_handshake_t *handshake;
};

METHOD(tls_t, process, status_t,
	private_tls_t *this, tls_content_type_t type, chunk_t data)
{
	return this->protection->process(this->protection, type, data);
}

METHOD(tls_t, build, status_t,
	private_tls_t *this, tls_content_type_t *type, chunk_t *data)
{
	return this->protection->build(this->protection, type, data);
}

METHOD(tls_t, get_version, tls_version_t,
	private_tls_t *this)
{
	return this->version;
}

METHOD(tls_t, set_version, void,
	private_tls_t *this, tls_version_t version)
{
	this->version = version;
}

METHOD(tls_t, destroy, void,
	private_tls_t *this)
{
	this->protection->destroy(this->protection);
	this->compression->destroy(this->compression);
	this->fragmentation->destroy(this->fragmentation);
	this->crypto->destroy(this->crypto);
	this->handshake->destroy(this->handshake);

	free(this);
}

/**
 * See header
 */
tls_t *tls_create(bool is_server)
{
	private_tls_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.get_version = _get_version,
			.set_version = _set_version,
			.destroy = _destroy,
		},
		.is_server = is_server,
		.crypto = tls_crypto_create(),
		.version = TLS_1_2,
	);

	if (is_server)
	{
		this->handshake = &tls_server_create(&this->public,
											 this->crypto)->handshake;
	}
	else
	{
		this->handshake = &tls_peer_create(&this->public,
										   this->crypto)->handshake;
	}
	this->fragmentation = tls_fragmentation_create(this->handshake);
	this->compression = tls_compression_create(this->fragmentation);
	this->protection = tls_protection_create(this->compression);

	return &this->public;
}
