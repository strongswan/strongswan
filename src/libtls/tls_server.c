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

#include "tls_server.h"

#include <time.h>

#include <debug.h>

typedef struct private_tls_server_t private_tls_server_t;


typedef enum {
	STATE_INIT,
	STATE_HELLO_RECEIVED,
	STATE_HELLO_SENT,
	STATE_CERT_SENT,
	STATE_CERTREQ_SENT,
	STATE_HELLO_DONE,
	STATE_CERT_RECEIVED,
	STATE_KEY_EXCHANGE_RECEIVED,
	STATE_CERT_VERIFY_RECEIVED,
	STATE_CIPHERSPEC_CHANGED_IN,
	STATE_FINISHED_RECEIVED,
	STATE_CIPHERSPEC_CHANGED_OUT,
	STATE_FINISHED_SENT,
} server_state_t;

/**
 * Private data of an tls_server_t object.
 */
struct private_tls_server_t {

	/**
	 * Public tls_server_t interface.
	 */
	tls_server_t public;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * TLS crypto context
	 */
	tls_crypto_t *crypto;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * State we are in
	 */
	server_state_t state;

	/**
	 * Hello random data selected by client
	 */
	char client_random[32];

	/**
	 * Hello random data selected by server
	 */
	char server_random[32];

	/**
	 * Auth helper for peer authentication
	 */
	auth_cfg_t *peer_auth;

	/**
	 * Auth helper for server authentication
	 */
	auth_cfg_t *server_auth;

	/**
	 * Peer private key
	 */
	private_key_t *private;

	/**
	 * Selected TLS cipher suite
	 */
	tls_cipher_suite_t suite;
};

/**
 * Process client hello message
 */
static status_t process_client_hello(private_tls_server_t *this,
									 tls_reader_t *reader)
{
	u_int16_t version;
	chunk_t random, session, ciphers, compression, ext = chunk_empty;
	tls_cipher_suite_t *suites;
	int count, i;

	this->crypto->append_handshake(this->crypto,
								   TLS_CLIENT_HELLO, reader->peek(reader));

	if (!reader->read_uint16(reader, &version) ||
		!reader->read_data(reader, sizeof(this->client_random), &random) ||
		!reader->read_data8(reader, &session) ||
		!reader->read_data16(reader, &ciphers) ||
		!reader->read_data8(reader, &compression) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_IKE, "received invalid ClientHello");
		return FAILED;
	}

	memcpy(this->client_random, random.ptr, sizeof(this->client_random));

	DBG1(DBG_IKE, "received TLS version: %N", tls_version_names, version);
	if (version < this->tls->get_version(this->tls))
	{
		this->tls->set_version(this->tls, version);
	}

	count = ciphers.len / sizeof(u_int16_t);
	suites = alloca(count * sizeof(tls_cipher_suite_t));
	DBG2(DBG_IKE, "received %d TLS cipher suites:", count);
	for (i = 0; i < count; i++)
	{
		suites[i] = untoh16(&ciphers.ptr[i * sizeof(u_int16_t)]);
		DBG2(DBG_IKE, "  %N", tls_cipher_suite_names, suites[i]);
	}
	this->suite = this->crypto->select_cipher_suite(this->crypto, suites, count);
	if (!this->suite)
	{
		DBG1(DBG_IKE, "received cipher suite inacceptable");
		return FAILED;
	}
	this->state = STATE_HELLO_RECEIVED;
	return NEED_MORE;
}

/**
 * Process certificate
 */
static status_t process_certificate(private_tls_server_t *this,
									tls_reader_t *reader)
{
	certificate_t *cert;
	tls_reader_t *certs;
	chunk_t data;
	bool first = TRUE;

	this->crypto->append_handshake(this->crypto,
								   TLS_CERTIFICATE, reader->peek(reader));

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
			if (first)
			{
				this->peer_auth->add(this->peer_auth,
									 AUTH_HELPER_SUBJECT_CERT, cert);
				DBG1(DBG_IKE, "received TLS peer certificate '%Y'",
					 cert->get_subject(cert));
				first = FALSE;
			}
			else
			{
				DBG1(DBG_IKE, "received TLS intermediate certificate '%Y'",
					 cert->get_subject(cert));
				this->peer_auth->add(this->peer_auth, AUTH_HELPER_IM_CERT, cert);
			}
		}
		else
		{
			DBG1(DBG_IKE, "parsing TLS certificate failed, skipped");
		}
	}
	certs->destroy(certs);
	this->state = STATE_CERT_RECEIVED;
	return NEED_MORE;
}

/**
 * Process Client Key Exchange
 */
static status_t process_key_exchange(private_tls_server_t *this,
									 tls_reader_t *reader)
{
	chunk_t encrypted, premaster;

	this->crypto->append_handshake(this->crypto,
								   TLS_CLIENT_KEY_EXCHANGE, reader->peek(reader));

	if (!reader->read_data16(reader, &encrypted))
	{
		DBG1(DBG_IKE, "received invalid Client Key Exchange");
		return FAILED;
	}

	if (!this->private ||
		!this->private->decrypt(this->private, ENCRYPT_RSA_PKCS1,
								encrypted, &premaster))
	{
		DBG1(DBG_IKE, "decrypting Client Key Exchange data failed");
		return FAILED;
	}
	this->crypto->derive_secrets(this->crypto, premaster,
								 chunk_from_thing(this->client_random),
								 chunk_from_thing(this->server_random));
	chunk_clear(&premaster);

	this->state = STATE_KEY_EXCHANGE_RECEIVED;
	return NEED_MORE;
}

/**
 * Process Certificate verify
 */
static status_t process_cert_verify(private_tls_server_t *this,
									tls_reader_t *reader)
{
	bool verified = FALSE;
	enumerator_t *enumerator;
	public_key_t *public;
	auth_cfg_t *auth;
	tls_reader_t *sig;

	enumerator = lib->credmgr->create_public_enumerator(lib->credmgr,
										KEY_ANY, this->peer, this->peer_auth);
	while (enumerator->enumerate(enumerator, &public, &auth))
	{
		sig = tls_reader_create(reader->peek(reader));
		verified = this->crypto->verify_handshake(this->crypto, public, sig);
		sig->destroy(sig);
		if (verified)
		{
			break;
		}
		DBG1(DBG_IKE, "signature verification failed, trying another key");
	}
	enumerator->destroy(enumerator);

	if (!verified)
	{
		DBG1(DBG_IKE, "no trusted certificate found for '%Y' to verify TLS peer",
			 this->peer);
		return FAILED;
	}

	this->crypto->append_handshake(this->crypto,
								   TLS_CERTIFICATE_VERIFY, reader->peek(reader));
	this->state = STATE_CERT_VERIFY_RECEIVED;
	return NEED_MORE;
}

/**
 * Process finished message
 */
static status_t process_finished(private_tls_server_t *this,
								 tls_reader_t *reader)
{
	chunk_t received;
	char buf[12];

	if (!reader->read_data(reader, sizeof(buf), &received))
	{
		DBG1(DBG_IKE, "received client finished too short");
		return FAILED;
	}
	if (!this->crypto->calculate_finished(this->crypto, "client finished", buf))
	{
		DBG1(DBG_IKE, "calculating client finished failed");
		return FAILED;
	}
	if (!chunk_equals(received, chunk_from_thing(buf)))
	{
		DBG1(DBG_IKE, "received client finished invalid");
		return FAILED;
	}

	this->crypto->append_handshake(this->crypto, TLS_FINISHED, received);
	this->state = STATE_FINISHED_RECEIVED;
	return NEED_MORE;
}

METHOD(tls_handshake_t, process, status_t,
	private_tls_server_t *this, tls_handshake_type_t type, tls_reader_t *reader)
{
	tls_handshake_type_t expected;

	switch (this->state)
	{
		case STATE_INIT:
			if (type == TLS_CLIENT_HELLO)
			{
				return process_client_hello(this, reader);
			}
			expected = TLS_CLIENT_HELLO;
			break;
		case STATE_HELLO_DONE:
			if (type == TLS_CERTIFICATE)
			{
				return process_certificate(this, reader);
			}
			expected = TLS_CERTIFICATE;
			break;
		case STATE_CERT_RECEIVED:
			if (type == TLS_CLIENT_KEY_EXCHANGE)
			{
				return process_key_exchange(this, reader);
			}
			expected = TLS_CLIENT_KEY_EXCHANGE;
			break;
		case STATE_KEY_EXCHANGE_RECEIVED:
			if (type == TLS_CERTIFICATE_VERIFY)
			{
				return process_cert_verify(this, reader);
			}
			expected = TLS_CERTIFICATE_VERIFY;
			break;
		case STATE_CIPHERSPEC_CHANGED_IN:
			if (type == TLS_FINISHED)
			{
				return process_finished(this, reader);
			}
			expected = TLS_FINISHED;
			break;
		default:
			DBG1(DBG_IKE, "TLS %N not expected in current state",
				 tls_handshake_type_names, type);
			return FAILED;
	}
	DBG1(DBG_IKE, "TLS %N expected, but received %N",
		 tls_handshake_type_names, expected, tls_handshake_type_names, type);
	return FAILED;
}

/**
 * Send ServerHello message
 */
static status_t send_server_hello(private_tls_server_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	tls_version_t version;
	rng_t *rng;

	htoun32(&this->server_random, time(NULL));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(this->server_random) - 4, this->server_random + 4);
	rng->destroy(rng);

	/* TLS version */
	version = this->tls->get_version(this->tls);
	DBG1(DBG_IKE, "sending TLS version: %N", tls_version_names, version);
	writer->write_uint16(writer, version);
	writer->write_data(writer, chunk_from_thing(this->server_random));

	/* session identifier => none, we don't support session resumption */
	writer->write_data8(writer, chunk_empty);

	/* add selected TLS cipher suite */
	DBG1(DBG_IKE, "sending TLS cipher suite: %N", tls_cipher_suite_names,
												  this->suite);
	writer->write_uint16(writer, this->suite);

	/* NULL compression only */
	writer->write_uint8(writer, 0);

	*type = TLS_SERVER_HELLO;
	this->state = STATE_HELLO_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Certificate
 */
static status_t send_certificate(private_tls_server_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_rule_t rule;
	tls_writer_t *certs;
	chunk_t data;

	this->private = lib->credmgr->get_private(lib->credmgr,
									KEY_ANY, this->server, this->server_auth);
	if (!this->private)
	{
		DBG1(DBG_IKE, "no TLS server certificate found for '%Y'", this->server);
		return FAILED;
	}

	/* generate certificate payload */
	certs = tls_writer_create(256);
	cert = this->server_auth->get(this->server_auth, AUTH_RULE_SUBJECT_CERT);
	if (cert)
	{
		if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
		{
			DBG1(DBG_IKE, "sending TLS server certificate '%Y'",
				 cert->get_subject(cert));
			certs->write_data24(certs, data);
			free(data.ptr);
		}
	}
	enumerator = this->server_auth->create_enumerator(this->server_auth);
	while (enumerator->enumerate(enumerator, &rule, &cert))
	{
		if (rule == AUTH_RULE_IM_CERT)
		{
			if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
			{
				DBG1(DBG_IKE, "sending TLS intermediate certificate '%Y'",
					 cert->get_subject(cert));
				certs->write_data24(certs, data);
				free(data.ptr);
			}
		}
	}
	enumerator->destroy(enumerator);

	writer->write_data24(writer, certs->get_buf(certs));
	certs->destroy(certs);

	*type = TLS_CERTIFICATE;
	this->state = STATE_CERT_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Certificate Request
 */
static status_t send_certificate_request(private_tls_server_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	tls_writer_t *authorities;
	enumerator_t *enumerator;
	certificate_t *cert;
	identification_t *id;

	/* currently only RSA signatures are supported */
	writer->write_data8(writer, chunk_from_chars(1));
	if (this->tls->get_version(this->tls) >= TLS_1_2)
	{
		/* enforce RSA with SHA1 signatures */
		writer->write_data16(writer, chunk_from_chars(2, 1));
	}

	authorities = tls_writer_create(64);
	enumerator = lib->credmgr->create_cert_enumerator(lib->credmgr,
												CERT_X509, KEY_RSA, NULL, TRUE);
	while (enumerator->enumerate(enumerator, &cert))
	{
		id = cert->get_subject(cert);
		authorities->write_data16(authorities, id->get_encoding(id));
	}
	enumerator->destroy(enumerator);
	writer->write_data16(writer, authorities->get_buf(authorities));
	authorities->destroy(authorities);

	*type = TLS_CERTIFICATE_REQUEST;
	this->state = STATE_CERTREQ_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Hello Done
 */
static status_t send_hello_done(private_tls_server_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	*type = TLS_SERVER_HELLO_DONE;
	this->state = STATE_HELLO_DONE;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Finished
 */
static status_t send_finished(private_tls_server_t *this,
							  tls_handshake_type_t *type, tls_writer_t *writer)
{
	char buf[12];

	if (!this->crypto->calculate_finished(this->crypto, "server finished", buf))
	{
		DBG1(DBG_IKE, "calculating server finished data failed");
		return FAILED;
	}

	writer->write_data(writer, chunk_from_thing(buf));

	*type = TLS_FINISHED;
	this->state = STATE_FINISHED_SENT;
	this->crypto->derive_eap_msk(this->crypto,
								 chunk_from_thing(this->client_random),
								 chunk_from_thing(this->server_random));
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_server_t *this, tls_handshake_type_t *type, tls_writer_t *writer)
{
	switch (this->state)
	{
		case STATE_HELLO_RECEIVED:
			return send_server_hello(this, type, writer);
		case STATE_HELLO_SENT:
			return send_certificate(this, type, writer);
		case STATE_CERT_SENT:
			return send_certificate_request(this, type, writer);
		case STATE_CERTREQ_SENT:
			return send_hello_done(this, type, writer);
		case STATE_CIPHERSPEC_CHANGED_OUT:
			return send_finished(this, type, writer);
		case STATE_FINISHED_SENT:
			return INVALID_STATE;
		default:
			return INVALID_STATE;
	}
}

METHOD(tls_handshake_t, cipherspec_changed, bool,
	private_tls_server_t *this)
{
	if (this->state == STATE_FINISHED_RECEIVED)
	{
		this->crypto->change_cipher(this->crypto, FALSE);
		this->state = STATE_CIPHERSPEC_CHANGED_OUT;
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_handshake_t, change_cipherspec, bool,
	private_tls_server_t *this)
{
	if (this->state == STATE_CERT_VERIFY_RECEIVED)
	{
		this->crypto->change_cipher(this->crypto, TRUE);
		this->state = STATE_CIPHERSPEC_CHANGED_IN;
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_handshake_t, finished, bool,
	private_tls_server_t *this)
{
	return this->state == STATE_FINISHED_SENT;
}

METHOD(tls_handshake_t, destroy, void,
	private_tls_server_t *this)
{
	DESTROY_IF(this->private);
	this->peer_auth->destroy(this->peer_auth);
	this->server_auth->destroy(this->server_auth);
	free(this);
}

/**
 * See header
 */
tls_server_t *tls_server_create(tls_t *tls, tls_crypto_t *crypto,
							identification_t *server, identification_t *peer)
{
	private_tls_server_t *this;

	INIT(this,
		.public.handshake = {
			.process = _process,
			.build = _build,
			.cipherspec_changed = _cipherspec_changed,
			.change_cipherspec = _change_cipherspec,
			.finished = _finished,
			.destroy = _destroy,
		},
		.tls = tls,
		.crypto = crypto,
		.server = server,
		.peer = peer,
		.state = STATE_INIT,
		.peer_auth = auth_cfg_create(),
		.server_auth = auth_cfg_create(),
	);

	return &this->public;
}
