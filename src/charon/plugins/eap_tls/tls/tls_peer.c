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

#include "tls_peer.h"

#include <daemon.h>

#include <time.h>

typedef struct private_tls_peer_t private_tls_peer_t;

typedef enum {
	STATE_INIT,
	STATE_HELLO_SENT,
	STATE_HELLO_DONE,
} peer_state_t;

/**
 * Private data of an tls_peer_t object.
 */
struct private_tls_peer_t {

	/**
	 * Public tls_peer_t interface.
	 */
	tls_peer_t public;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * TLS crypto context
	 */
	tls_crypto_t *crypto;

	/**
	 * State we are in
	 */
	peer_state_t state;
};

/**
 * Process a server hello message
 */
static status_t process_server_hello(private_tls_peer_t *this,
									 tls_reader_t *reader)
{
	u_int8_t compression;
	u_int16_t version, cipher;
	u_int32_t gmt;
	chunk_t random, session, ext = chunk_empty;

	if (!reader->read_uint16(reader, &version) ||
		!reader->read_uint32(reader, &gmt) ||
		!reader->read_data(reader, 28, &random) ||
		!reader->read_data8(reader, &session) ||
		!reader->read_uint16(reader, &cipher) ||
		!reader->read_uint8(reader, &compression) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_IKE, "received invalid ServerHello");
		return FAILED;
	}
	if (version < this->tls->get_version(this->tls))
	{
		this->tls->set_version(this->tls, version);
	}
	return NEED_MORE;
}

/**
 * Process a Certificate message
 */
static status_t process_certificate(private_tls_peer_t *this,
									tls_reader_t *reader)
{
	certificate_t *cert;
	tls_reader_t *certs;
	chunk_t data;

	if (!reader->read_data24(reader, &data))
	{
		return FAILED;
	}
	certs = tls_reader_create(data);
	while (certs->remaining(certs))
	{
		if (!certs->read_data24(certs, &data))
		{
			certs->destroy(certs);
			return FAILED;
		}
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								   BUILD_BLOB_ASN1_DER, data, BUILD_END);
		if (cert)
		{
			DBG1(DBG_IKE, "got certificate: %Y", cert->get_subject(cert));
			cert->destroy(cert);
		}
	}
	certs->destroy(certs);
	return NEED_MORE;
}

/**
 * Process a Certificate message
 */
static status_t process_certreq(private_tls_peer_t *this, tls_reader_t *reader)
{
	chunk_t types, hashsig, data;
	tls_reader_t *authorities;
	identification_t *id;

	if (!reader->read_data8(reader, &types))
	{
		return FAILED;
	}
	if (this->tls->get_version(this->tls) >= TLS_1_2)
	{
		if (!reader->read_data16(reader, &hashsig))
		{
			return FAILED;
		}
	}
	if (!reader->read_data16(reader, &data))
	{
		return FAILED;
	}
	authorities = tls_reader_create(data);
	while (authorities->remaining(authorities))
	{
		if (!authorities->read_data16(authorities, &data))
		{
			authorities->destroy(authorities);
			return FAILED;
		}
		id = identification_create_from_encoding(ID_DER_ASN1_DN, data);
		DBG1(DBG_IKE, "received certificate request for %Y", id);
		id->destroy(id);
	}
	authorities->destroy(authorities);
	return NEED_MORE;
}

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, tls_reader_t *reader)
{
	switch (this->state)
	{
		case STATE_HELLO_SENT:
			switch (type)
			{
				case TLS_SERVER_HELLO:
					return process_server_hello(this, reader);
				case TLS_CERTIFICATE:
					return process_certificate(this, reader);
				case TLS_CERTIFICATE_REQUEST:
					return process_certreq(this, reader);
				case TLS_SERVER_HELLO_DONE:
					this->state = STATE_HELLO_DONE;
					return NEED_MORE;
				default:
					break;
			}
			break;
		default:
			break;
	}
	DBG1(DBG_IKE, "received TLS handshake message %N, ignored",
		 tls_handshake_type_names, type);
	return NEED_MORE;
}

/**
 * Build the Client Hello using a given set of ciphers
 */
static chunk_t build_hello(private_tls_peer_t *this,
						   int count, tls_cipher_suite_t *suite, rng_t *rng)
{
	int i;

	struct __attribute__((packed)) {
		u_int16_t version;
		struct __attribute__((packed)) {
			u_int32_t gmt;
			u_int8_t bytes[28];
		} random;
		struct __attribute__((packed)) {
			/* never send a session identifier */
			u_int8_t len;
			u_int8_t id[0];
		} session;
		struct __attribute__((packed)) {
			u_int16_t len;
			u_int16_t suite[count];
		} cipher;
		struct __attribute__((packed)) {
			/* currently NULL compression only */
			u_int8_t len;
			u_int8_t method[1];
		} compression;
		u_int8_t extensions[0];
	} hello;

	htoun16(&hello.session.len, 0);
	htoun16(&hello.version, this->tls->get_version(this->tls));
	htoun32(&hello.random.gmt, time(NULL));
	rng->get_bytes(rng, sizeof(hello.random.bytes), (char*)&hello.random.bytes);
	htoun16(&hello.cipher.len, count * 2);
	for (i = 0; i < count; i++)
	{
		htoun16(&hello.cipher.suite[i], suite[i]);
	}
	hello.compression.len = 1;
	hello.compression.method[0] = 0;
	return chunk_clone(chunk_create((char*)&hello, sizeof(hello)));
}

/**
 * Send a client hello
 */
static status_t send_hello(private_tls_peer_t *this,
						   tls_handshake_type_t *type, chunk_t *data)
{
	tls_cipher_suite_t *suite;
	int count;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FAILED;
	}
	count = this->crypto->get_cipher_suites(this->crypto, &suite);
	*data = build_hello(this, count, suite, rng);
	*type = TLS_CLIENT_HELLO;
	free(suite);
	rng->destroy(rng);
	this->state = STATE_HELLO_SENT;
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, chunk_t *data)
{
	switch (this->state)
	{
		case STATE_INIT:
			return send_hello(this, type, data);
		default:
			return INVALID_STATE;
	}
}

METHOD(tls_handshake_t, destroy, void,
	private_tls_peer_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_peer_t *tls_peer_create(tls_t *tls, tls_crypto_t *crypto)
{
	private_tls_peer_t *this;

	INIT(this,
		.public.handshake = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.state = STATE_INIT,
		.tls = tls,
		.crypto = crypto,
	);

	return &this->public;
}
