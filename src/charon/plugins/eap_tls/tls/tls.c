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

#include <daemon.h>

ENUM(tls_version_names, SSL_2_0, TLS_1_2,
	"SSLv2",
	"SSLv3",
	"TLS 1.0",
	"TLS 1.1",
	"TLS 1.2",
);

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
};

METHOD(tls_t, process, status_t,
	private_tls_t *this, tls_content_type_t type, chunk_t data)
{
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tls_t *this, tls_content_type_t *type, chunk_t *data)
{
	return INVALID_STATE;
}

METHOD(tls_t, destroy, void,
	private_tls_t *this)
{
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
			.destroy = _destroy,
		},
		.is_server = is_server,
	);

	return &this->public;
}
