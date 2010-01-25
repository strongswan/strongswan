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
static status_t process_server_hello(private_tls_peer_t *this, chunk_t data)
{
	if (data.len >= 38)
	{
		tls_version_t version;

		struct __attribute__((packed)) {
			u_int16_t version;
			struct __attribute__((packed)) {
				u_int32_t gmt;
				u_int8_t bytes[28];
			} random;
			struct __attribute__((packed)) {
				u_int8_t len;
				/* points to len */
				u_int8_t id[data.ptr[34]];
			} session;
			u_int16_t cipher;
			u_int8_t compression;
			char extensions[];
		} *hello = (void*)data.ptr;

		if (sizeof(*hello) > data.len)
		{
			DBG1(DBG_IKE, "received invalid ServerHello");
			return FAILED;
		}

		version = untoh16(&hello->version);
		if (version < this->tls->get_version(this->tls))
		{
			this->tls->set_version(this->tls, version);
		}
		return NEED_MORE;
	}
	DBG1(DBG_IKE, "server hello has %d bytes", data.len);
	return FAILED;
}

/**
 * Process a Certificate message
 */
static status_t process_certificate(private_tls_peer_t *this, chunk_t data)
{
	if (data.len > 3)
	{
		u_int32_t total;

		total = untoh32(data.ptr) >> 8;
		data = chunk_skip(data, 3);
		if (total != data.len)
		{
			DBG1(DBG_IKE, "certificate chain length invalid");
			return FAILED;
		}
		while (data.len > 3)
		{
			certificate_t *cert;
			u_int32_t len;

			len = untoh32(data.ptr) >> 8;
			data = chunk_skip(data, 3);
			if (len > data.len)
			{
				DBG1(DBG_IKE, "certificate length invalid");
				return FAILED;
			}
			cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
					BUILD_BLOB_ASN1_DER, chunk_create(data.ptr, len), BUILD_END);
			if (cert)
			{
				DBG1(DBG_IKE, "got certificate: %Y", cert->get_subject(cert));
				cert->destroy(cert);
			}
			data = chunk_skip(data, len);
		}
	}
	return NEED_MORE;
}

/**
 * Process a Certificate message
 */
static status_t process_certreq(private_tls_peer_t *this, chunk_t data)
{
	struct __attribute__((packed)) {
		u_int8_t len;
		u_int8_t types[];
	} *certificate;
	struct __attribute__((packed)) {
		u_int16_t len;
		struct __attribute__((packed)) {
			u_int8_t hash;
			u_int8_t sig;
		} types[];
	} *alg;
	u_int16_t len;
	identification_t *id;

	certificate = (void*)data.ptr;
	data = chunk_skip(data, 1);
	if (!data.len || certificate->len > data.len)
	{
		return FAILED;
	}
	data = chunk_skip(data, certificate->len);

	if (this->tls->get_version(this->tls) >= TLS_1_2)
	{
		alg = (void*)data.ptr;
		data = chunk_skip(data, 2);
		if (!data.len || untoh16(&alg->len) > data.len)
		{
			return FAILED;
		}
		data = chunk_skip(data, untoh16(&alg->len));
	}
	if (data.len < 2 || untoh16(data.ptr) != data.len - 2)
	{
		return FAILED;
	}
	data = chunk_skip(data, 2);

	while (data.len >= 2)
	{
		len = untoh16(data.ptr);
		data = chunk_skip(data, 2);
		if (len > data.len)
		{
			return FAILED;
		}
		id = identification_create_from_encoding(ID_DER_ASN1_DN,
												 chunk_create(data.ptr, len));
		DBG1(DBG_IKE, "received certificate request for %Y", id);
		id->destroy(id);
		data = chunk_skip(data, len);
	}
	return NEED_MORE;
}

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, chunk_t data)
{
	switch (this->state)
	{
		case STATE_HELLO_SENT:
			switch (type)
			{
				case TLS_SERVER_HELLO:
					return process_server_hello(this, data);
				case TLS_CERTIFICATE:
					return process_certificate(this, data);
				case TLS_CERTIFICATE_REQUEST:
					return process_certreq(this, data);
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
