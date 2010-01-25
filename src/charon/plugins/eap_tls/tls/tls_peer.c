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
	 * TLS crypto context
	 */
	tls_crypto_t *crypto;

	/**
	 * State we are in
	 */
	peer_state_t state;
};

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, chunk_t data)
{
	return NEED_MORE;
}

/**
 * Build the Client Hello using a given set of ciphers
 */
static chunk_t build_hello(int count, tls_cipher_suite_t *suite, rng_t *rng)
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
	htoun16(&hello.version, TLS_1_2);
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
	*data = build_hello(count, suite, rng);
	*type = TLS_CLIENT_HELLO;
	free(suite);
	rng->destroy(rng);
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, chunk_t *data)
{
	switch (this->state)
	{
		case STATE_INIT:
			this->state = STATE_HELLO_SENT;
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
tls_peer_t *tls_peer_create(tls_crypto_t *crypto)
{
	private_tls_peer_t *this;

	INIT(this,
		.public.handshake = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.state = STATE_INIT,
		.crypto = crypto,
	);

	return &this->public;
}
