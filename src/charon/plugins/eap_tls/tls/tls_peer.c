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
 * Send a client hello
 */
static status_t send_hello(private_tls_peer_t *this,
						   tls_handshake_type_t *type, tls_writer_t *writer)
{
	tls_cipher_suite_t *suite;
	int count, i;
	rng_t *rng;
	char random[28];

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(random), random);
	rng->destroy(rng);

	writer->write_uint16(writer, this->tls->get_version(this->tls));
	writer->write_uint32(writer, time(NULL));
	writer->write_data(writer, chunk_from_thing(random));
	/* session identifier => none */
	writer->write_data8(writer, chunk_empty);

	count = this->crypto->get_cipher_suites(this->crypto, &suite);
	writer->write_uint16(writer, count * 2);
	for (i = 0; i < count; i++)
	{
		writer->write_uint16(writer, suite[i]);
	}
	free(suite);
	/* NULL compression only */
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 0);

	*type = TLS_CLIENT_HELLO;
	this->state = STATE_HELLO_SENT;
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, tls_writer_t *writer)
{
	switch (this->state)
	{
		case STATE_INIT:
			return send_hello(this, type, writer);
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
