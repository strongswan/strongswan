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
