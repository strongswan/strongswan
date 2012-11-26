/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "pkcs7_signed_data.h"

#include <utils/debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <crypto/pkcs9.h>
#include <credentials/sets/mem_cred.h>

typedef struct private_pkcs7_signed_data_t private_pkcs7_signed_data_t;

/**
 * Private data of a PKCS#7 signed-data container.
 */
struct private_pkcs7_signed_data_t {

	/**
	 * Implements pkcs7_t.
	 */
	pkcs7_t public;

	/**
	 * Signed content data
	 */
	container_t *content;

	/**
	 * Encoded PKCS#7 signed-data
	 */
	chunk_t encoding;

	/**
	 * Attributes of first signerInfo
	 */
	pkcs9_t *attributes;

	/**
	 * Trustchain, if signature valid
	 */
	auth_cfg_t *auth;
};

/**
 * ASN.1 definition of the PKCS#7 signedData type
 */
static const asn1Object_t signedDataObjects[] = {
	{ 0, "signedData",						ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "version",						ASN1_INTEGER,		ASN1_BODY }, /*  1 */
	{ 1,   "digestAlgorithms",				ASN1_SET,			ASN1_LOOP }, /*  2 */
	{ 2,     "algorithm",					ASN1_EOC,			ASN1_RAW  }, /*  3 */
	{ 1,   "end loop",						ASN1_EOC,			ASN1_END  }, /*  4 */
	{ 1,   "contentInfo",					ASN1_EOC,			ASN1_RAW  }, /*  5 */
	{ 1,   "certificates",					ASN1_CONTEXT_C_0,	ASN1_OPT |
																ASN1_LOOP }, /*  6 */
	{ 2,      "certificate",				ASN1_SEQUENCE,		ASN1_OBJ  }, /*  7 */
	{ 1,   "end opt or loop",				ASN1_EOC,			ASN1_END  }, /*  8 */
	{ 1,   "crls",							ASN1_CONTEXT_C_1,	ASN1_OPT |
																ASN1_LOOP }, /*  9 */
	{ 2,	    "crl",						ASN1_SEQUENCE,		ASN1_OBJ  }, /* 10 */
	{ 1,   "end opt or loop",				ASN1_EOC,			ASN1_END  }, /* 11 */
	{ 1,   "signerInfos",					ASN1_SET,			ASN1_LOOP }, /* 12 */
	{ 2,     "signerInfo",					ASN1_SEQUENCE,		ASN1_NONE }, /* 13 */
	{ 3,       "version",					ASN1_INTEGER,		ASN1_BODY }, /* 14 */
	{ 3,       "issuerAndSerialNumber",		ASN1_SEQUENCE,		ASN1_BODY }, /* 15 */
	{ 4,         "issuer",					ASN1_SEQUENCE,		ASN1_OBJ  }, /* 16 */
	{ 4,         "serial",					ASN1_INTEGER,		ASN1_BODY }, /* 17 */
	{ 3,       "digestAlgorithm",			ASN1_EOC,			ASN1_RAW  }, /* 18 */
	{ 3,       "authenticatedAttributes",	ASN1_CONTEXT_C_0,	ASN1_OPT |
																ASN1_OBJ  }, /* 19 */
	{ 3,       "end opt",					ASN1_EOC,			ASN1_END  }, /* 20 */
	{ 3,       "digestEncryptionAlgorithm",	ASN1_EOC,			ASN1_RAW  }, /* 21 */
	{ 3,       "encryptedDigest",			ASN1_OCTET_STRING,	ASN1_BODY }, /* 22 */
	{ 3,       "unauthenticatedAttributes", ASN1_CONTEXT_C_1,	ASN1_OPT  }, /* 23 */
	{ 3,       "end opt",					ASN1_EOC,			ASN1_END  }, /* 24 */
	{ 1,   "end loop",						ASN1_EOC,			ASN1_END  }, /* 25 */
	{ 0, "exit",							ASN1_EOC,			ASN1_EXIT }
};
#define PKCS7_VERSION				 1
#define PKCS7_DIGEST_ALG			 3
#define PKCS7_CONTENT_INFO			 5
#define PKCS7_CERT					 7
#define PKCS7_SIGNER_INFO			13
#define PKCS7_SIGNER_INFO_VERSION	14
#define PKCS7_ISSUER				16
#define PKCS7_SERIAL_NUMBER			17
#define PKCS7_DIGEST_ALGORITHM		18
#define PKCS7_AUTH_ATTRIBUTES		19
#define PKCS7_DIGEST_ENC_ALGORITHM	21
#define PKCS7_ENCRYPTED_DIGEST		22

METHOD(container_t, get_type, container_type_t,
	private_pkcs7_signed_data_t *this)
{
	return CONTAINER_PKCS7_SIGNED_DATA;
}

METHOD(container_t, create_signature_enumerator, enumerator_t*,
	private_pkcs7_signed_data_t *this)
{
	if (this->auth)
	{
		return enumerator_create_single(this->auth, NULL);
	}
	return enumerator_create_empty();
}

METHOD(container_t, get_data, bool,
	private_pkcs7_signed_data_t *this, chunk_t *data)
{
	if (this->content)
	{
		return this->content->get_data(this->content, data);
	}
	return FALSE;
}

METHOD(container_t, get_encoding, bool,
	private_pkcs7_signed_data_t *this, chunk_t *data)
{
	*data = chunk_clone(this->encoding);
	return TRUE;
}

METHOD(container_t, destroy, void,
	private_pkcs7_signed_data_t *this)
{
	DESTROY_IF(this->auth);
	DESTROY_IF(this->attributes);
	DESTROY_IF(this->content);
	free(this->encoding.ptr);
	free(this);
}

/**
 * Create an empty PKCS#7 signed-data container.
 */
static private_pkcs7_signed_data_t* create_empty()
{
	private_pkcs7_signed_data_t *this;

	INIT(this,
		.public = {
			.container = {
				.get_type = _get_type,
				.create_signature_enumerator = _create_signature_enumerator,
				.get_data = _get_data,
				.get_encoding = _get_encoding,
				.destroy = _destroy,
			},
		},
	);

	return this;
}

/**
 * Verify signature
 */
static bool verify_signature(private_pkcs7_signed_data_t *this, int signerInfos,
							 identification_t *serial, identification_t *issuer,
							 chunk_t digest, int digest_alg, int enc_alg)
{
	signature_scheme_t scheme;
	enumerator_t *enumerator;
	certificate_t *cert;
	public_key_t *key;
	auth_cfg_t *auth;
	chunk_t chunk;

	scheme = signature_scheme_from_oid(digest_alg);
	if (scheme == SIGN_UNKNOWN)
	{
		DBG1(DBG_LIB, "unsupported signature scheme");
		return FALSE;
	}
	if (this->attributes == NULL)
	{
		DBG1(DBG_LIB, "no authenticatedAttributes object found");
		return FALSE;
	}
	if (enc_alg != OID_RSA_ENCRYPTION)
	{
		DBG1(DBG_LIB, "only RSA digest encryption supported");
		return FALSE;
	}
	if (signerInfos == 0)
	{
		DBG1(DBG_LIB, "no signerInfo object found");
		return FALSE;
	}
	else if (signerInfos > 1)
	{
		DBG1(DBG_LIB, "more than one signerInfo object found");
		return FALSE;
	}

	enumerator = lib->credmgr->create_trusted_enumerator(lib->credmgr,
													KEY_RSA, serial, FALSE);
	while (enumerator->enumerate(enumerator, &cert, &auth))
	{
		if (issuer->equals(issuer, cert->get_issuer(cert)))
		{
			key = cert->get_public_key(cert);
			if (key)
			{
				chunk = this->attributes->get_encoding(this->attributes);
				if (key->verify(key, scheme, chunk, digest))
				{
					this->auth = auth->clone(auth);
					break;
				}
			}
		}
	}
	enumerator->destroy(enumerator);

	if (this->content)
	{
		hash_algorithm_t algorithm;
		hasher_t *hasher;
		chunk_t hash, content;
		bool valid;

		chunk = this->attributes->get_attribute(this->attributes,
												OID_PKCS9_MESSAGE_DIGEST);
		if (chunk.ptr == NULL)
		{
			DBG1(DBG_LIB, "messageDigest attribute not found");
			return FALSE;
		}
		if (!this->content->get_data(this->content, &content))
		{
			return FALSE;
		}

		algorithm = hasher_algorithm_from_oid(digest_alg);
		hasher = lib->crypto->create_hasher(lib->crypto, algorithm);
		if (!hasher || !hasher->allocate_hash(hasher, content, &hash))
		{
			free(content.ptr);
			DESTROY_IF(hasher);
			DBG1(DBG_LIB, "hash algorithm %N not supported",
				 hash_algorithm_names, algorithm);
			return FALSE;
		}
		free(content.ptr);
		hasher->destroy(hasher);
		DBG3(DBG_LIB, "hash: %B", &hash);

		valid = chunk_equals(chunk, hash);
		free(hash.ptr);
		if (valid)
		{
			DBG2(DBG_LIB, "messageDigest is valid");
		}
		else
		{
			DBG1(DBG_LIB, "invalid messageDigest");
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Parse PKCS#7 signed data
 */
static bool parse(private_pkcs7_signed_data_t *this, chunk_t content)
{
	asn1_parser_t *parser;
	identification_t *issuer = NULL, *serial = NULL;
	chunk_t object, encrypted_digest = chunk_empty;
	int objectID, version, digest_alg = OID_UNKNOWN, enc_alg = OID_UNKNOWN;
	int signerInfos = 0;
	bool success = FALSE;
	mem_cred_t *creds;

	creds = mem_cred_create();

	parser = asn1_parser_create(signedDataObjects, content);
	parser->set_top_level(parser, 0);
	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
			case PKCS7_VERSION:
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				break;
			case PKCS7_DIGEST_ALG:
				digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_CONTENT_INFO:
				this->content = lib->creds->create(lib->creds,
										CRED_CONTAINER, CONTAINER_PKCS7,
										BUILD_BLOB_ASN1_DER, object, BUILD_END);
				break;
			case PKCS7_CERT:
			{
				certificate_t *cert;

				DBG2(DBG_LIB, "  parsing pkcs7-wrapped certificate");
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509,
										  BUILD_BLOB_ASN1_DER, object,
										  BUILD_END);
				if (cert)
				{
					creds->add_cert(creds, FALSE, cert);
				}
				break;
			}
			case PKCS7_SIGNER_INFO:
				signerInfos++;
				break;
			case PKCS7_SIGNER_INFO_VERSION:
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				break;
			case PKCS7_ISSUER:
				if (!issuer)
				{
					issuer = identification_create_from_encoding(ID_DER_ASN1_DN,
																 object);
				}
				break;
			case PKCS7_SERIAL_NUMBER:
				if (!serial)
				{
					serial = identification_create_from_encoding(ID_KEY_ID,
																 object);
				}
				break;
			case PKCS7_AUTH_ATTRIBUTES:
				*object.ptr = ASN1_SET;
				this->attributes = pkcs9_create_from_chunk(object, 1);
				*object.ptr = ASN1_CONTEXT_C_0;
				break;
			case PKCS7_DIGEST_ALGORITHM:
				digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_DIGEST_ENC_ALGORITHM:
				enc_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_ENCRYPTED_DIGEST:
				encrypted_digest = object;
				break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);

	if (issuer)
	{
		if (serial)
		{
			if (success)
			{
				lib->credmgr->add_local_set(lib->credmgr, &creds->set, FALSE);
				success = verify_signature(this, signerInfos, serial, issuer,
										encrypted_digest, digest_alg, enc_alg);
				lib->credmgr->remove_local_set(lib->credmgr, &creds->set);
			}
			serial->destroy(serial);
		}
		issuer->destroy(issuer);
	}
	creds->destroy(creds);

	return success;
}

/**
 * See header.
 */
pkcs7_t *pkcs7_signed_data_load(chunk_t encoding, chunk_t content)
{
	private_pkcs7_signed_data_t *this = create_empty();

	this->encoding = chunk_clone(encoding);
	if (!parse(this, content))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
