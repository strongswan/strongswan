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

#include <debug.h>

#include <time.h>

typedef struct private_tls_peer_t private_tls_peer_t;

typedef enum {
	STATE_INIT,
	STATE_HELLO_SENT,
	STATE_HELLO_RECEIVED,
	STATE_HELLO_DONE,
	STATE_CERT_SENT,
	STATE_CERT_RECEIVED,
	STATE_CERTREQ_RECEIVED,
	STATE_KEY_EXCHANGE_SENT,
	STATE_VERIFY_SENT,
	STATE_CIPHERSPEC_CHANGED_OUT,
	STATE_FINISHED_SENT,
	STATE_CIPHERSPEC_CHANGED_IN,
	STATE_COMPLETE,
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
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * State we are in
	 */
	peer_state_t state;

	/**
	 * Hello random data selected by client
	 */
	char client_random[32];

	/**
	 * Hello random data selected by server
	 */
	char server_random[32];

	/**
	 * Does the server request a peer authentication?
	 */
	bool peer_auth_requested;

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
};

/**
 * Process a server hello message
 */
static status_t process_server_hello(private_tls_peer_t *this,
									 tls_reader_t *reader)
{
	u_int8_t compression;
	u_int16_t version, cipher;
	chunk_t random, session, ext = chunk_empty;
	tls_cipher_suite_t suite;

	this->crypto->append_handshake(this->crypto,
								   TLS_SERVER_HELLO, reader->peek(reader));

	if (!reader->read_uint16(reader, &version) ||
		!reader->read_data(reader, sizeof(this->server_random), &random) ||
		!reader->read_data8(reader, &session) ||
		!reader->read_uint16(reader, &cipher) ||
		!reader->read_uint8(reader, &compression) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_TLS, "received invalid ServerHello");
		return FAILED;
	}

	memcpy(this->server_random, random.ptr, sizeof(this->server_random));

	if (!this->tls->set_version(this->tls, version))
	{
		DBG1(DBG_TLS, "negotiated version %N not supported",
			 tls_version_names, version);
		return FAILED;
	}
	suite = cipher;
	if (!this->crypto->select_cipher_suite(this->crypto, &suite, 1))
	{
		DBG1(DBG_TLS, "received TLS cipher suite %N inacceptable",
			 tls_cipher_suite_names, suite);
		return FAILED;
	}
	DBG1(DBG_TLS, "negotiated TLS version %N with suite %N",
		 tls_version_names, version, tls_cipher_suite_names, suite);
	this->state = STATE_HELLO_RECEIVED;
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
				this->server_auth->add(this->server_auth,
									   AUTH_HELPER_SUBJECT_CERT, cert);
				DBG1(DBG_TLS, "received TLS server certificate '%Y'",
					 cert->get_subject(cert));
				first = FALSE;
			}
			else
			{
				DBG1(DBG_TLS, "received TLS intermediate certificate '%Y'",
					 cert->get_subject(cert));
				this->server_auth->add(this->server_auth,
									   AUTH_HELPER_IM_CERT, cert);
			}
		}
		else
		{
			DBG1(DBG_TLS, "parsing TLS certificate failed, skipped");
		}
	}
	certs->destroy(certs);
	this->state = STATE_CERT_RECEIVED;
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
	certificate_t *cert;

	this->crypto->append_handshake(this->crypto,
								TLS_CERTIFICATE_REQUEST, reader->peek(reader));

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
		/* TODO: store supported hashsig algorithms */
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
		cert = lib->credmgr->get_cert(lib->credmgr,
									  CERT_X509, KEY_ANY, id, TRUE);
		if (cert)
		{
			DBG1(DBG_TLS, "received TLS cert request for '%Y", id);
			this->peer_auth->add(this->peer_auth, AUTH_RULE_CA_CERT, cert);
		}
		else
		{
			DBG1(DBG_TLS, "received TLS cert request for unknown CA '%Y'", id);
		}
		id->destroy(id);
	}
	authorities->destroy(authorities);
	this->state = STATE_CERTREQ_RECEIVED;
	return NEED_MORE;
}

/**
 * Process Hello Done message
 */
static status_t process_hello_done(private_tls_peer_t *this,
								   tls_reader_t *reader)
{
	this->crypto->append_handshake(this->crypto,
								   TLS_SERVER_HELLO_DONE, reader->peek(reader));
	this->state = STATE_HELLO_DONE;
	return NEED_MORE;
}

/**
 * Process finished message
 */
static status_t process_finished(private_tls_peer_t *this, tls_reader_t *reader)
{
	chunk_t received;
	char buf[12];

	if (!reader->read_data(reader, sizeof(buf), &received))
	{
		DBG1(DBG_TLS, "received server finished too short");
		return FAILED;
	}
	if (!this->crypto->calculate_finished(this->crypto, "server finished", buf))
	{
		DBG1(DBG_TLS, "calculating server finished failed");
		return FAILED;
	}
	if (!chunk_equals(received, chunk_from_thing(buf)))
	{
		DBG1(DBG_TLS, "received server finished invalid");
		return FAILED;
	}
	this->state = STATE_COMPLETE;
	this->crypto->derive_eap_msk(this->crypto,
								 chunk_from_thing(this->client_random),
								 chunk_from_thing(this->server_random));
	return NEED_MORE;
}

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, tls_reader_t *reader)
{
	tls_handshake_type_t expected;

	switch (this->state)
	{
		case STATE_HELLO_SENT:
			if (type == TLS_SERVER_HELLO)
			{
				return process_server_hello(this, reader);
			}
			expected = TLS_SERVER_HELLO;
			break;
		case STATE_HELLO_RECEIVED:
			if (type == TLS_CERTIFICATE)
			{
				return process_certificate(this, reader);
			}
			expected = TLS_CERTIFICATE;
			break;
		case STATE_CERT_RECEIVED:
			if (type == TLS_CERTIFICATE_REQUEST)
			{
				this->peer_auth_requested = TRUE;
				return process_certreq(this, reader);
			}
			/* fall through since TLS_CERTIFICATE_REQUEST is optional */
		case STATE_CERTREQ_RECEIVED:
			if (type == TLS_SERVER_HELLO_DONE)
			{
				return process_hello_done(this, reader);
			}
			expected = TLS_SERVER_HELLO_DONE;
			break;
		case STATE_CIPHERSPEC_CHANGED_IN:
			if (type == TLS_FINISHED)
			{
				return process_finished(this, reader);
			}
			expected = TLS_FINISHED;
			break;
		default:
			DBG1(DBG_TLS, "TLS %N not expected in current state",
				 tls_handshake_type_names, type);
			return FAILED;
	}
	DBG1(DBG_TLS, "TLS %N expected, but received %N",
		 tls_handshake_type_names, expected, tls_handshake_type_names, type);
	return FAILED;
}

/**
 * Send a client hello
 */
static status_t send_client_hello(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	tls_cipher_suite_t *suites;
	tls_version_t version;
	int count, i;
	rng_t *rng;

	htoun32(&this->client_random, time(NULL));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(this->client_random) - 4, this->client_random + 4);
	rng->destroy(rng);

	/* TLS version */
	version = this->tls->get_version(this->tls);
	writer->write_uint16(writer, version);
	writer->write_data(writer, chunk_from_thing(this->client_random));

	/* session identifier => none */
	writer->write_data8(writer, chunk_empty);

	/* add TLS cipher suites */
	count = this->crypto->get_cipher_suites(this->crypto, &suites);
	DBG2(DBG_TLS, "sending %d TLS cipher suites:", count);
	writer->write_uint16(writer, count * 2);
	for (i = 0; i < count; i++)
	{
		DBG2(DBG_TLS, "  %N", tls_cipher_suite_names, suites[i]);
		writer->write_uint16(writer, suites[i]);
	}

	/* NULL compression only */
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 0);

	*type = TLS_CLIENT_HELLO;
	this->state = STATE_HELLO_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Certificate
 */
static status_t send_certificate(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_rule_t rule;
	tls_writer_t *certs;
	chunk_t data;

	this->private = lib->credmgr->get_private(lib->credmgr,
										KEY_ANY, this->peer, this->peer_auth);
	if (!this->private)
	{
		DBG1(DBG_TLS, "no TLS peer certificate found for '%Y'", this->peer);
		return FAILED;
	}

	/* generate certificate payload */
	certs = tls_writer_create(256);
	cert = this->peer_auth->get(this->peer_auth, AUTH_RULE_SUBJECT_CERT);
	if (cert)
	{
		if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
		{
			DBG1(DBG_TLS, "sending TLS peer certificate '%Y'",
				 cert->get_subject(cert));
			certs->write_data24(certs, data);
			free(data.ptr);
		}
	}
	enumerator = this->peer_auth->create_enumerator(this->peer_auth);
	while (enumerator->enumerate(enumerator, &rule, &cert))
	{
		if (rule == AUTH_RULE_IM_CERT)
		{
			if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
			{
				DBG1(DBG_TLS, "sending TLS intermediate certificate '%Y'",
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
 * Send client key exchange
 */
static status_t send_key_exchange(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	public_key_t *public = NULL, *current;
	certificate_t *cert;
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	rng_t *rng;
	char premaster[48];
	chunk_t encrypted;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_TLS, "no suitable RNG found for TLS premaster secret");
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(premaster) - 2, premaster + 2);
	rng->destroy(rng);
	htoun16(premaster, TLS_1_2);

	this->crypto->derive_secrets(this->crypto, chunk_from_thing(premaster),
								 chunk_from_thing(this->client_random),
								 chunk_from_thing(this->server_random));

	cert = this->server_auth->get(this->server_auth, AUTH_HELPER_SUBJECT_CERT);
	if (cert)
	{
		enumerator = lib->credmgr->create_public_enumerator(lib->credmgr,
						KEY_ANY, cert->get_subject(cert), this->server_auth);
		while (enumerator->enumerate(enumerator, &current, &auth))
		{
			public = current->get_ref(current);
			break;
		}
		enumerator->destroy(enumerator);
	}
	if (!public)
	{
		DBG1(DBG_TLS, "no TLS public key found for server '%Y'", this->server);
		return FAILED;
	}
	if (!public->encrypt(public, ENCRYPT_RSA_PKCS1,
						 chunk_from_thing(premaster), &encrypted))
	{
		public->destroy(public);
		DBG1(DBG_TLS, "encrypting TLS premaster secret failed");
		return FAILED;
	}

	public->destroy(public);

	writer->write_data16(writer, encrypted);
	free(encrypted.ptr);

	*type = TLS_CLIENT_KEY_EXCHANGE;
	this->state = STATE_KEY_EXCHANGE_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send certificate verify
 */
static status_t send_certificate_verify(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	if (!this->private ||
		!this->crypto->sign_handshake(this->crypto, this->private, writer))
	{
		DBG1(DBG_TLS, "creating TLS Certificate Verify signature failed");
		return FAILED;
	}

	*type = TLS_CERTIFICATE_VERIFY;
	this->state = STATE_VERIFY_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Finished
 */
static status_t send_finished(private_tls_peer_t *this,
							  tls_handshake_type_t *type, tls_writer_t *writer)
{
	char buf[12];

	if (!this->crypto->calculate_finished(this->crypto, "client finished", buf))
	{
		DBG1(DBG_TLS, "calculating client finished data failed");
		return FAILED;
	}

	writer->write_data(writer, chunk_from_thing(buf));

	*type = TLS_FINISHED;
	this->state = STATE_FINISHED_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, tls_writer_t *writer)
{
	switch (this->state)
	{
		case STATE_INIT:
			return send_client_hello(this, type, writer);
		case STATE_HELLO_DONE:
			if (this->peer_auth_requested)
			{
				return send_certificate(this, type, writer);
			}
			/* otherwise fall through to next state */
		case STATE_CERT_SENT:
			return send_key_exchange(this, type, writer);
		case STATE_KEY_EXCHANGE_SENT:
			if (this->peer_auth_requested)
			{
				return send_certificate_verify(this, type, writer);
			}
			else
			{
				return INVALID_STATE;
			}
		case STATE_CIPHERSPEC_CHANGED_OUT:
			return send_finished(this, type, writer);
		default:
			return INVALID_STATE;
	}
}

METHOD(tls_handshake_t, cipherspec_changed, bool,
	private_tls_peer_t *this)
{
	if ((this->peer_auth_requested && this->state == STATE_VERIFY_SENT) ||
	   (!this->peer_auth_requested && this->state == STATE_KEY_EXCHANGE_SENT))
	{
		this->crypto->change_cipher(this->crypto, FALSE);
		this->state = STATE_CIPHERSPEC_CHANGED_OUT;
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_handshake_t, change_cipherspec, bool,
	private_tls_peer_t *this)
{
	if (this->state == STATE_FINISHED_SENT)
	{
		this->crypto->change_cipher(this->crypto, TRUE);
		this->state = STATE_CIPHERSPEC_CHANGED_IN;
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_handshake_t, finished, bool,
	private_tls_peer_t *this)
{
	return this->state == STATE_COMPLETE;
}

METHOD(tls_handshake_t, destroy, void,
	private_tls_peer_t *this)
{
	DESTROY_IF(this->private);
	this->peer_auth->destroy(this->peer_auth);
	this->server_auth->destroy(this->server_auth);
	free(this);
}

/**
 * See header
 */
tls_peer_t *tls_peer_create(tls_t *tls, tls_crypto_t *crypto,
							identification_t *peer, identification_t *server)
{
	private_tls_peer_t *this;

	INIT(this,
		.public = {
			.handshake = {
				.process = _process,
				.build = _build,
				.cipherspec_changed = _cipherspec_changed,
				.change_cipherspec = _change_cipherspec,
				.finished = _finished,
				.destroy = _destroy,
			},
		},
		.state = STATE_INIT,
		.tls = tls,
		.crypto = crypto,
		.peer = peer,
		.server = server,
		.peer_auth = auth_cfg_create(),
		.server_auth = auth_cfg_create(),
	);

	return &this->public;
}
