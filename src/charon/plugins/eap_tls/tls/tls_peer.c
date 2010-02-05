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
	STATE_CERT_SENT,
	STATE_KEY_EXCHANGE_SENT,
	STATE_VERIFY_SENT,
	STATE_CIPHERSPEC_CHANGED_OUT,
	STATE_FINISHED_SENT,
	STATE_CIPHERSPEC_CHANGED_IN,
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
	 * All handshake data concatentated
	 */
	chunk_t handshake;

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
};

/**
 * Append a handshake message to the handshake data buffer
 */
static void append_handshake(private_tls_peer_t *this,
							 tls_handshake_type_t type, chunk_t data)
{
	u_int32_t header;

	/* reconstruct handshake header */
	header = htonl(data.len | (type << 24));
	this->handshake = chunk_cat("mcc", this->handshake,
								chunk_from_thing(header), data);
}

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

	append_handshake(this, TLS_SERVER_HELLO, reader->peek(reader));

	if (!reader->read_uint16(reader, &version) ||
		!reader->read_data(reader, sizeof(this->server_random), &random) ||
		!reader->read_data8(reader, &session) ||
		!reader->read_uint16(reader, &cipher) ||
		!reader->read_uint8(reader, &compression) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_IKE, "received invalid ServerHello");
		return FAILED;
	}

	memcpy(this->server_random, random.ptr, sizeof(this->server_random));

	if (version < this->tls->get_version(this->tls))
	{
		this->tls->set_version(this->tls, version);
	}
	suite = cipher;
	if (!this->crypto->select_cipher_suite(this->crypto, &suite, 1))
	{
		DBG1(DBG_IKE, "received cipher suite inacceptable");
		return FAILED;
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
	bool first = TRUE;

	append_handshake(this, TLS_CERTIFICATE, reader->peek(reader));

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
									   AUTH_RULE_SUBJECT_CERT, cert);
				DBG1(DBG_IKE, "received TLS server certificate '%Y'",
					 cert->get_subject(cert));
				first = FALSE;
			}
			else
			{
				DBG1(DBG_IKE, "received TLS intermediate certificate '%Y'",
					 cert->get_subject(cert));
				this->server_auth->add(this->server_auth,
									   AUTH_RULE_IM_CERT, cert);
			}
		}
		else
		{
			DBG1(DBG_IKE, "parsing TLS certificate failed, skipped");
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
	certificate_t *cert;

	append_handshake(this, TLS_CERTIFICATE_REQUEST, reader->peek(reader));

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
		cert = charon->credentials->get_cert(charon->credentials,
											 CERT_X509, KEY_ANY, id, TRUE);
		if (cert)
		{
			DBG1(DBG_IKE, "received cert request for '%Y", id);
			this->peer_auth->add(this->peer_auth, AUTH_RULE_CA_CERT, cert);
		}
		else
		{
			DBG1(DBG_IKE, "received cert request for unknown CA '%Y'", id);
		}
		id->destroy(id);
	}
	authorities->destroy(authorities);
	return NEED_MORE;
}

/**
 * Process Hello Done message
 */
static status_t process_hello_done(private_tls_peer_t *this,
								   tls_reader_t *reader)
{
	append_handshake(this, TLS_SERVER_HELLO_DONE, reader->peek(reader));
	this->state = STATE_HELLO_DONE;
	return NEED_MORE;
}

/**
 * Process finished message
 */
static status_t process_finished(private_tls_peer_t *this, tls_reader_t *reader)
{
	return FAILED;
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
					return process_hello_done(this, reader);
				default:
					break;
			}
			break;
		case STATE_CIPHERSPEC_CHANGED_IN:
			switch (type)
			{
				case TLS_FINISHED:
					return process_finished(this, reader);
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

	htoun32(&this->client_random, time(NULL));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(this->client_random) - 4, this->client_random + 4);
	rng->destroy(rng);

	writer->write_uint16(writer, this->tls->get_version(this->tls));
	writer->write_data(writer, chunk_from_thing(this->client_random));
	/* session identifier => none */
	writer->write_data8(writer, chunk_empty);

	count = this->crypto->get_cipher_suites(this->crypto, &suite);
	writer->write_uint16(writer, count * 2);
	for (i = 0; i < count; i++)
	{
		writer->write_uint16(writer, suite[i]);
	}
	/* NULL compression only */
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 0);

	*type = TLS_CLIENT_HELLO;
	this->state = STATE_HELLO_SENT;
	append_handshake(this, *type, writer->get_buf(writer));
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

	this->private = charon->credentials->get_private(charon->credentials,
										KEY_ANY, this->peer, this->peer_auth);
	if (!this->private)
	{
		DBG1(DBG_IKE, "no TLS peer certificate found for '%Y'", this->peer);
		return FAILED;
	}

	/* generate certificate payload */
	certs = tls_writer_create(256);
	cert = this->peer_auth->get(this->peer_auth, AUTH_RULE_SUBJECT_CERT);
	if (cert)
	{
		DBG1(DBG_IKE, "sending TLS peer certificate '%Y'",
			 cert->get_subject(cert));
		data = cert->get_encoding(cert);
		certs->write_data24(certs, data);
		free(data.ptr);
	}
	enumerator = this->peer_auth->create_enumerator(this->peer_auth);
	while (enumerator->enumerate(enumerator, &rule, &cert))
	{
		if (rule == AUTH_RULE_IM_CERT)
		{
			DBG1(DBG_IKE, "sending TLS intermediate certificate '%Y'",
				 cert->get_subject(cert));
			data = cert->get_encoding(cert);
			certs->write_data24(certs, data);
			free(data.ptr);
		}
	}
	enumerator->destroy(enumerator);

	writer->write_data24(writer, certs->get_buf(certs));
	certs->destroy(certs);

	*type = TLS_CERTIFICATE;
	this->state = STATE_CERT_SENT;
	append_handshake(this, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send client key exchange
 */
static status_t send_key_exchange(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	public_key_t *public = NULL, *current;
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	rng_t *rng;
	char premaster[48];
	chunk_t encrypted;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_IKE, "no suitable RNG found for TLS premaster secret");
		return FAILED;
	}
	rng->get_bytes(rng, sizeof(premaster) - 2, premaster + 2);
	rng->destroy(rng);
	htoun16(premaster, TLS_1_2);

	this->crypto->derive_master_secret(this->crypto, chunk_from_thing(premaster),
									   chunk_from_thing(this->client_random),
									   chunk_from_thing(this->server_random));

	enumerator = charon->credentials->create_public_enumerator(
				charon->credentials, KEY_ANY, this->server, this->server_auth);
	while (enumerator->enumerate(enumerator, &current, &auth))
	{
		public = current->get_ref(current);
		break;
	}
	enumerator->destroy(enumerator);

	if (!public)
	{
		DBG1(DBG_IKE, "no TLS public key found for server '%Y'", this->server);
		return FAILED;
	}
	if (!public->encrypt(public, chunk_from_thing(premaster), &encrypted))
	{
		public->destroy(public);
		DBG1(DBG_IKE, "encrypting TLS premaster secret failed");
		return FAILED;
	}
	public->destroy(public);

	writer->write_data16(writer, encrypted);
	free(encrypted.ptr);

	*type = TLS_CLIENT_KEY_EXCHANGE;
	this->state = STATE_KEY_EXCHANGE_SENT;
	append_handshake(this, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send certificate verify
 */
static status_t send_certificate_verify(private_tls_peer_t *this,
							tls_handshake_type_t *type, tls_writer_t *writer)
{
	chunk_t signature;

	if (!this->private)
	{
		return FAILED;
	}

	if (this->tls->get_version(this->tls) >= TLS_1_2)
	{
		if (!this->private->sign(this->private, SIGN_RSA_EMSA_PKCS1_SHA1,
								 this->handshake, &signature))
		{
			DBG1(DBG_IKE, "creating TLS Certificate Verify signature failed");
			return FAILED;
		}
		/* TODO: signature scheme to hashsign algorithm mapping */
		writer->write_uint8(writer, 2);	/* sha1 */
		writer->write_uint8(writer, 1); /* RSA */
	}
	else
	{
		hasher_t *md5, *sha1;
		char buf[HASH_SIZE_MD5 + HASH_SIZE_SHA1];

		md5 = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
		if (!md5)
		{
			DBG1(DBG_IKE, "unable to sign %N Verify, MD5 not supported",
				 tls_version_names, this->tls->get_version(this->tls));
			return FAILED;
		}
		md5->get_hash(md5, this->handshake, buf);
		md5->destroy(md5);
		sha1 = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (!sha1)
		{
			DBG1(DBG_IKE, "unable to sign %N Verify, SHA1 not supported",
				 tls_version_names, this->tls->get_version(this->tls));
			return FAILED;
		}
		sha1->get_hash(sha1, this->handshake, buf + HASH_SIZE_MD5);
		sha1->destroy(sha1);

		if (!this->private->sign(this->private, SIGN_RSA_EMSA_PKCS1_NULL,
								 chunk_from_thing(buf), &signature))
		{
			DBG1(DBG_IKE, "creating TLS Certificate Verify signature failed");
			return FAILED;
		}
	}
	writer->write_data16(writer, signature);
	free(signature.ptr);

	*type = TLS_CERTIFICATE_VERIFY;
	this->state = STATE_VERIFY_SENT;
	append_handshake(this, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Finished
 */
static status_t send_finished(private_tls_peer_t *this,
							  tls_handshake_type_t *type, tls_writer_t *writer)
{
	chunk_t seed;
	tls_prf_t *prf;
	char data[12];

	if (this->tls->get_version(this->tls) >= TLS_1_2)
	{
		/* TODO: use hash of cipher suite only */
		seed = chunk_empty;
	}
	else
	{
		hasher_t *md5, *sha1;
		char buf[HASH_SIZE_MD5 + HASH_SIZE_SHA1];

		md5 = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
		if (!md5)
		{
			DBG1(DBG_IKE, "unable to create %N Finished, MD5 not supported",
				 tls_version_names, this->tls->get_version(this->tls));
			return FAILED;
		}
		md5->get_hash(md5, this->handshake, buf);
		md5->destroy(md5);
		sha1 = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (!sha1)
		{
			DBG1(DBG_IKE, "unable to sign %N Finished, SHA1 not supported",
				 tls_version_names, this->tls->get_version(this->tls));
			return FAILED;
		}
		sha1->get_hash(sha1, this->handshake, buf + HASH_SIZE_MD5);
		sha1->destroy(sha1);

		seed = chunk_clonea(chunk_from_thing(buf));
	}

	prf = this->crypto->get_prf(this->crypto);
	if (!prf)
	{
		return FAILED;
	}
	prf->get_bytes(prf, "client finished", seed, sizeof(data), data);

	writer->write_data(writer, chunk_from_thing(data));

	*type = TLS_FINISHED;
	this->state = STATE_FINISHED_SENT;
	append_handshake(this, *type, writer->get_buf(writer));
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, tls_writer_t *writer)
{
	switch (this->state)
	{
		case STATE_INIT:
			return send_hello(this, type, writer);
		case STATE_HELLO_DONE:
			return send_certificate(this, type, writer);
		case STATE_CERT_SENT:
			return send_key_exchange(this, type, writer);
		case STATE_KEY_EXCHANGE_SENT:
			return send_certificate_verify(this, type, writer);
		case STATE_CIPHERSPEC_CHANGED_OUT:
			return send_finished(this, type, writer);
		default:
			return INVALID_STATE;
	}
}

METHOD(tls_handshake_t, cipherspec_changed, bool,
	private_tls_peer_t *this)
{
	if (this->state == STATE_VERIFY_SENT)
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

METHOD(tls_handshake_t, destroy, void,
	private_tls_peer_t *this)
{
	DESTROY_IF(this->private);
	free(this->handshake.ptr);
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
		.public.handshake = {
			.process = _process,
			.build = _build,
			.cipherspec_changed = _cipherspec_changed,
			.change_cipherspec = _change_cipherspec,
			.destroy = _destroy,
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
