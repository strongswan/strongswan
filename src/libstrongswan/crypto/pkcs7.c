/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2002-2008 Andreas Steffen
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <library.h>
#include <debug.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <credentials/certificates/x509.h>
#include <credentials/keys/public_key.h>
#include <crypto/pkcs9.h>
#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>
#include <utils/linked_list.h>

#include "pkcs7.h"

typedef struct private_pkcs7_t private_pkcs7_t;

/**
 * Private data of a pkcs7_t object.
 */
struct private_pkcs7_t {
	/**
	 * Public interface for this certificate.
	 */
	pkcs7_t public;

	/**
	 * contentInfo type
	 */
	int type;

	/**
	 * ASN.1 encoded content
	 */
	chunk_t content;

	/**
	 * ASN.1 parsing start level
	 */
	u_int level;

	/**
	 * retrieved data
	 */
	chunk_t data;

	/**
	 * ASN.1 encoded attributes
	 */
	pkcs9_t *attributes;

	/**
	 * Linked list of X.509 certificates
	 */
	linked_list_t *certs;
};

METHOD(pkcs7_t, is_data, bool,
	private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_DATA;
}

METHOD(pkcs7_t, is_signedData, bool,
	private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_SIGNED_DATA;
}

METHOD(pkcs7_t, is_envelopedData, bool,
	private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_ENVELOPED_DATA;
}

/**
 * ASN.1 definition of the PKCS#7 ContentInfo type
 */
static const asn1Object_t contentInfoObjects[] = {
	{ 0, "contentInfo",		ASN1_SEQUENCE,		ASN1_NONE }, /* 0 */
	{ 1,   "contentType",	ASN1_OID,			ASN1_BODY }, /* 1 */
	{ 1,   "content",		ASN1_CONTEXT_C_0,	ASN1_OPT |
												ASN1_BODY }, /* 2 */
	{ 1,   "end opt",		ASN1_EOC,			ASN1_END  }, /* 3 */
	{ 0, "exit",			ASN1_EOC,			ASN1_EXIT }
};
#define PKCS7_INFO_TYPE		1
#define PKCS7_INFO_CONTENT	2

/**
 * Parse PKCS#7 contentInfo object
 */
static bool parse_contentInfo(private_pkcs7_t *this)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	if (!this->data.ptr)
	{
		return FALSE;
	}

	parser = asn1_parser_create(contentInfoObjects, this->data);
	parser->set_top_level(parser, this->level);

	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == PKCS7_INFO_TYPE)
		{
			this->type = asn1_known_oid(object);
			if (this->type < OID_PKCS7_DATA ||
				this->type > OID_PKCS7_ENCRYPTED_DATA)
			{
				DBG1(DBG_LIB, "unknown pkcs7 content type");
				goto end;
			}
		}
		else if (objectID == PKCS7_INFO_CONTENT && object.len > 0)
		{
			chunk_free(&this->content);
			this->content = chunk_clone(object);
		}
	}
	success = parser->success(parser);

	if (success)
	{
		this->level += 2;
		chunk_free(&this->data);
	}

end:
	parser->destroy(parser);
	return success;
}

/**
 * Check whether to abort the requested parsing
 */
static bool abort_parsing(private_pkcs7_t *this, int type)
{
	if (this->type != type)
	{
		DBG1(DBG_LIB, "pkcs7 content to be parsed is not of type '%s'",
			 oid_names[type].name);
		return TRUE;
	}
	return FALSE;
}

METHOD(pkcs7_t, parse_data, bool,
	private_pkcs7_t *this)
{
	chunk_t data;

	if (!parse_contentInfo(this) ||
		 abort_parsing(this, OID_PKCS7_DATA))
	{
		return FALSE;
	}
	data = this->content;
	if (data.len == 0)
	{
		this->data = chunk_empty;
		return TRUE;
	}
	if (asn1_parse_simple_object(&data, ASN1_OCTET_STRING,
								 this->level, "data"))
	{
		this->data = chunk_clone(data);
		return TRUE;
	}
	return FALSE;
}

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
#define PKCS7_SIGNED_VERSION		 1
#define PKCS7_DIGEST_ALG			 3
#define PKCS7_SIGNED_CONTENT_INFO	 5
#define PKCS7_SIGNED_CERT			 7
#define PKCS7_SIGNER_INFO			13
#define PKCS7_SIGNER_INFO_VERSION	14
#define PKCS7_SIGNED_ISSUER			16
#define PKCS7_SIGNED_SERIAL_NUMBER	17
#define PKCS7_DIGEST_ALGORITHM		18
#define PKCS7_AUTH_ATTRIBUTES		19
#define PKCS7_DIGEST_ENC_ALGORITHM	21
#define PKCS7_ENCRYPTED_DIGEST		22

METHOD(pkcs7_t, parse_signedData, bool,
	private_pkcs7_t *this, certificate_t *cacert)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID, version;
	int digest_alg = OID_UNKNOWN;
	int enc_alg    = OID_UNKNOWN;
	int signerInfos = 0;
	bool success = FALSE;

	chunk_t encrypted_digest = chunk_empty;

	if (!parse_contentInfo(this) ||
		 abort_parsing(this, OID_PKCS7_SIGNED_DATA))
	{
		return FALSE;
	}

	parser = asn1_parser_create(signedDataObjects, this->content);
	parser->set_top_level(parser, this->level);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
			case PKCS7_SIGNED_VERSION:
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				break;
			case PKCS7_DIGEST_ALG:
				digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_SIGNED_CONTENT_INFO:
			{
				pkcs7_t *data = pkcs7_create_from_chunk(object, level+1);

				if (!data || !data->parse_data(data))
				{
					DESTROY_IF(data);
					goto end;
				}
				this->data = chunk_clone(data->get_data(data));
				data->destroy(data);
				break;
			}
			case PKCS7_SIGNED_CERT:
			{
				certificate_t *cert;

				DBG2(DBG_LIB, "  parsing pkcs7-wrapped certificate");
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509,
										  BUILD_BLOB_ASN1_DER, object,
										  BUILD_END);
				if (cert)
				{
					this->certs->insert_last(this->certs, cert);
				}
				break;
			}
			case PKCS7_SIGNER_INFO:
				signerInfos++;
				DBG2(DBG_LIB, "  signer #%d", signerInfos);
				break;
			case PKCS7_SIGNER_INFO_VERSION:
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				break;
			case PKCS7_SIGNED_ISSUER:
			{
				identification_t *issuer;

				issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				DBG2(DBG_LIB, "  '%Y'", issuer);
				issuer->destroy(issuer);
				break;
			}
			case PKCS7_AUTH_ATTRIBUTES:
				*object.ptr = ASN1_SET;
				this->attributes = pkcs9_create_from_chunk(object, level+1);
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
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		return FALSE;
	}

	/* check the signature only if a cacert is available */
	if (cacert != NULL)
	{
		signature_scheme_t scheme;
		public_key_t *key;

		scheme = signature_scheme_from_oid(digest_alg);
		if (scheme == SIGN_UNKNOWN)
		{
			DBG1(DBG_LIB, "unsupported signature scheme");
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

		/* verify the signature */
		key = cacert->get_public_key(cacert);
		if (key == NULL)
		{
			DBG1(DBG_LIB, "no public key found in CA certificate");
			return FALSE;
		}
		if (key->verify(key, scheme,
			this->attributes->get_encoding(this->attributes), encrypted_digest))
		{
			DBG2(DBG_LIB, "signature is valid");
		}
		else
		{
			DBG1(DBG_LIB, "invalid signature");
			key->destroy(key);
			return FALSE;
		}
		key->destroy(key);

		if (this->data.ptr != NULL)
		{
			chunk_t messageDigest;

			messageDigest = this->attributes->get_attribute(this->attributes,
													OID_PKCS9_MESSAGE_DIGEST);
			if (messageDigest.ptr == NULL)
			{
				DBG1(DBG_LIB, "messageDigest attribute not found");
				return FALSE;
			}
			else
			{
				hash_algorithm_t algorithm;
				hasher_t *hasher;
				chunk_t hash;
				bool valid;

				algorithm = hasher_algorithm_from_oid(digest_alg);
				hasher = lib->crypto->create_hasher(lib->crypto, algorithm);
				if (!hasher || !hasher->allocate_hash(hasher, this->data, &hash))
				{
					DESTROY_IF(hasher);
					DBG1(DBG_LIB, "hash algorithm %N not supported",
						 hash_algorithm_names, algorithm);
					return FALSE;
				}
				hasher->destroy(hasher);
				DBG3(DBG_LIB, "hash: %B", &hash);

				valid = chunk_equals(messageDigest, hash);
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
		}
	}
	return TRUE;
}

/**
 * ASN.1 definition of the PKCS#7 envelopedData type
 */
static const asn1Object_t envelopedDataObjects[] = {
	{ 0, "envelopedData",					ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "version",						ASN1_INTEGER, 		ASN1_BODY }, /*  1 */
	{ 1,   "recipientInfos",				ASN1_SET,    		ASN1_LOOP }, /*  2 */
	{ 2,     "recipientInfo",				ASN1_SEQUENCE, 		ASN1_BODY }, /*  3 */
	{ 3,       "version",					ASN1_INTEGER, 		ASN1_BODY }, /*  4 */
	{ 3,       "issuerAndSerialNumber",		ASN1_SEQUENCE,		ASN1_BODY }, /*  5 */
	{ 4,         "issuer",					ASN1_SEQUENCE,		ASN1_OBJ  }, /*  6 */
	{ 4,         "serial",					ASN1_INTEGER,		ASN1_BODY }, /*  7 */
	{ 3,       "encryptionAlgorithm",		ASN1_EOC,			ASN1_RAW  }, /*  8 */
	{ 3,       "encryptedKey",				ASN1_OCTET_STRING,	ASN1_BODY }, /*  9 */
	{ 1,   "end loop",						ASN1_EOC,			ASN1_END  }, /* 10 */
	{ 1,   "encryptedContentInfo",			ASN1_SEQUENCE,		ASN1_OBJ  }, /* 11 */
	{ 2,     "contentType",					ASN1_OID,			ASN1_BODY }, /* 12 */
	{ 2,     "contentEncryptionAlgorithm",	ASN1_EOC,			ASN1_RAW  }, /* 13 */
	{ 2,     "encryptedContent",			ASN1_CONTEXT_S_0, 	ASN1_BODY }, /* 14 */
	{ 0, "exit",							ASN1_EOC,			ASN1_EXIT }
};
#define PKCS7_ENVELOPED_VERSION			 1
#define PKCS7_RECIPIENT_INFO_VERSION	 4
#define PKCS7_ISSUER					 6
#define PKCS7_SERIAL_NUMBER				 7
#define PKCS7_ENCRYPTION_ALG			 8
#define PKCS7_ENCRYPTED_KEY				 9
#define PKCS7_CONTENT_TYPE				12
#define PKCS7_CONTENT_ENC_ALGORITHM		13
#define PKCS7_ENCRYPTED_CONTENT			14

METHOD(pkcs7_t, parse_envelopedData, bool,
	private_pkcs7_t *this, chunk_t serialNumber, private_key_t *key)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID, version;
	bool success = FALSE;

	chunk_t iv                = chunk_empty;
	chunk_t symmetric_key     = chunk_empty;
	chunk_t encrypted_content = chunk_empty;

	crypter_t *crypter = NULL;

	if (!parse_contentInfo(this) ||
		 abort_parsing(this, OID_PKCS7_ENVELOPED_DATA))
	{
		return FALSE;
	}

	parser = asn1_parser_create(envelopedDataObjects, this->content);
	parser->set_top_level(parser, this->level);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
			case PKCS7_ENVELOPED_VERSION:
			{
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				if (version != 0)
				{
					DBG1(DBG_LIB, "envelopedData version is not 0");
					goto end;
				}
				break;
			}
			case PKCS7_RECIPIENT_INFO_VERSION:
			{
				version = object.len ? (int)*object.ptr : 0;
				DBG2(DBG_LIB, "  v%d", version);
				if (version != 0)
				{
					DBG1(DBG_LIB, "recipient info version is not 0");
					goto end;
				}
				break;
			}
			case PKCS7_ISSUER:
			{
				identification_t *issuer;

				issuer = identification_create_from_encoding(ID_DER_ASN1_DN,
															 object);
				DBG2(DBG_LIB, "  '%Y'", issuer);
				issuer->destroy(issuer);
				break;
			}
			case PKCS7_SERIAL_NUMBER:
			{
				if (!chunk_equals(serialNumber, object))
				{
					DBG1(DBG_LIB, "serial numbers do not match");
					goto end;
				}
				break;
			}
			case PKCS7_ENCRYPTION_ALG:
			{
				int alg;

				alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				if (alg != OID_RSA_ENCRYPTION)
				{
					DBG1(DBG_LIB, "only rsa encryption supported");
					goto end;
				}
				break;
			}
			case PKCS7_ENCRYPTED_KEY:
			{
				if (!key->decrypt(key, ENCRYPT_RSA_PKCS1, object, &symmetric_key))
				{
					DBG1(DBG_LIB, "symmetric key could not be decrypted with rsa");
					goto end;
				}
				DBG4(DBG_LIB, "symmetric key %B", &symmetric_key);
				break;
			}
			case PKCS7_CONTENT_TYPE:
			{
				if (asn1_known_oid(object) != OID_PKCS7_DATA)
				{
					DBG1(DBG_LIB, "encrypted content not of type pkcs7 data");
					goto end;
				}
				break;
			}
			case PKCS7_CONTENT_ENC_ALGORITHM:
			{
				encryption_algorithm_t enc_alg;
				size_t key_size;
				int alg;

				alg = asn1_parse_algorithmIdentifier(object, level, &iv);
				enc_alg = encryption_algorithm_from_oid(alg, &key_size);
				if (enc_alg == ENCR_UNDEFINED)
				{
					DBG1(DBG_LIB, "unsupported content encryption algorithm");
					goto end;
				}
				crypter = lib->crypto->create_crypter(lib->crypto, enc_alg,
													  key_size);
				if (crypter == NULL)
				{
					DBG1(DBG_LIB, "crypter %N not available",
						 encryption_algorithm_names, enc_alg);
					goto end;
				}
				if (symmetric_key.len != crypter->get_key_size(crypter))
				{
					DBG1(DBG_LIB, "symmetric key length %d is wrong",
						 symmetric_key.len);
					goto end;
				}
				if (!asn1_parse_simple_object(&iv, ASN1_OCTET_STRING,
											  level + 1, "IV"))
				{
					DBG1(DBG_LIB, "IV could not be parsed");
					goto end;
				}
				if (iv.len != crypter->get_iv_size(crypter))
				{
					DBG1(DBG_LIB, "IV length %d is wrong", iv.len);
					goto end;
				}
				break;
			}
			case PKCS7_ENCRYPTED_CONTENT:
			{
				encrypted_content = object;
				break;
			}
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		goto failed;
	}
	success = FALSE;

	/* decrypt the content */
	if (!crypter->set_key(crypter, symmetric_key) ||
		!crypter->decrypt(crypter, encrypted_content, iv, &this->data))
	{
		success = FALSE;
		goto failed;
	}
	DBG4(DBG_LIB, "decrypted content with padding: %B", &this->data);

	/* remove the padding */
	{
		u_char *pos = this->data.ptr + this->data.len - 1;
		u_char pattern = *pos;
		size_t padding = pattern;

		if (padding > this->data.len)
		{
			DBG1(DBG_LIB, "padding greater than data length");
			goto failed;
		}
		this->data.len -= padding;

		while (padding-- > 0)
		{
			if (*pos-- != pattern)
			{
				DBG1(DBG_LIB, "wrong padding pattern");
				goto failed;
			}
		}
	}
	success = TRUE;

failed:
	DESTROY_IF(crypter);
	chunk_clear(&symmetric_key);
	if (!success)
	{
		chunk_free(&this->data);
	}
	return success;
}

METHOD(pkcs7_t, get_data, chunk_t,
	private_pkcs7_t *this)
{
	return this->data;
}

METHOD(pkcs7_t, get_contentInfo, chunk_t,
	private_pkcs7_t *this)
{
	chunk_t content_type;

	/* create DER-encoded OID for pkcs7_contentInfo type */
	switch(this->type)
	{
		case OID_PKCS7_DATA:
		case OID_PKCS7_SIGNED_DATA:
		case OID_PKCS7_ENVELOPED_DATA:
		case OID_PKCS7_SIGNED_ENVELOPED_DATA:
		case OID_PKCS7_DIGESTED_DATA:
		case OID_PKCS7_ENCRYPTED_DATA:
			content_type = asn1_build_known_oid(this->type);
			break;
		case OID_UNKNOWN:
		default:
			DBG1(DBG_LIB, "invalid pkcs7 contentInfo type");
			return chunk_empty;
	}

	return this->content.ptr == NULL
				? asn1_wrap(ASN1_SEQUENCE, "m", content_type)
				: asn1_wrap(ASN1_SEQUENCE, "mm", content_type,
					asn1_simple_object(ASN1_CONTEXT_C_0, this->content));
}

METHOD(pkcs7_t, create_certificate_enumerator, enumerator_t*,
	private_pkcs7_t *this)
{
	return this->certs->create_enumerator(this->certs);
}

METHOD(pkcs7_t, set_certificate, void,
	private_pkcs7_t *this, certificate_t *cert)
{
	if (cert)
	{
		this->certs->insert_last(this->certs, cert);
	}
}

METHOD(pkcs7_t, set_attributes, void,
	private_pkcs7_t *this, pkcs9_t *attributes)
{
	this->attributes = attributes;
}

METHOD(pkcs7_t, get_attributes, pkcs9_t*,
	private_pkcs7_t *this)
{
	return this->attributes;
}

/**
 * build a DER-encoded issuerAndSerialNumber object
 */
chunk_t pkcs7_build_issuerAndSerialNumber(certificate_t *cert)
{
	identification_t *issuer = cert->get_issuer(cert);
	chunk_t serial = chunk_empty;

	if (cert->get_type(cert) == CERT_X509)
	{
		x509_t *x509 = (x509_t*)cert;
		serial = x509->get_serial(x509);
	}

	return asn1_wrap(ASN1_SEQUENCE, "cm",
					 issuer->get_encoding(issuer),
					 asn1_integer("c", serial));
}

METHOD(pkcs7_t, build_envelopedData, bool,
	private_pkcs7_t *this, certificate_t *cert, encryption_algorithm_t alg,
	size_t key_size)
{
	chunk_t iv, symmetricKey, protectedKey, in, out;
	crypter_t *crypter;
	int alg_oid;

	/* select OID of symmetric encryption algorithm */
	alg_oid = encryption_algorithm_to_oid(alg, key_size);
	if (alg_oid == OID_UNKNOWN)
	{
		DBG1(DBG_LIB, "  encryption algorithm %N not supported",
			 encryption_algorithm_names, alg);
		return FALSE;
	}
	crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size / 8);
	if (crypter == NULL)
	{
		DBG1(DBG_LIB, "  could not create crypter for algorithm %N",
			 encryption_algorithm_names, alg);
		return FALSE;
	}

	/* generate a true random symmetric encryption key
	 * and a pseudo-random iv
	 */
	{
		rng_t *rng;

		rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
		if (!rng || !rng->allocate_bytes(rng, crypter->get_key_size(crypter),
										 &symmetricKey))
		{
			DBG1(DBG_LIB, "  failed to allocate symmetric encryption key");
			DESTROY_IF(rng);
			return FALSE;
		}
		DBG4(DBG_LIB, "  symmetric encryption key: %B", &symmetricKey);
		rng->destroy(rng);

		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!rng || !rng->allocate_bytes(rng, crypter->get_iv_size(crypter),
										 &iv))
		{
			DBG1(DBG_LIB, "  failed to allocate initialization vector");
			DESTROY_IF(rng);
			return FALSE;
		}
		DBG4(DBG_LIB, "  initialization vector: %B", &iv);
		rng->destroy(rng);
	}

	/* pad the data so that the total length becomes
	 * a multiple of the block size
	 */
	{
		size_t block_size = crypter->get_block_size(crypter);
		size_t padding = block_size - this->data.len % block_size;

		in.len = this->data.len + padding;
		in.ptr = malloc(in.len);

		DBG2(DBG_LIB, "  padding %d bytes of data to multiple block size of %d bytes",
			(int)this->data.len, (int)in.len);

		/* copy data */
		memcpy(in.ptr, this->data.ptr, this->data.len);
		/* append padding */
		memset(in.ptr + this->data.len, padding, padding);
	}
	DBG3(DBG_LIB, "  padded unencrypted data: %B", &in);

	/* symmetric encryption of data object */
	if (!crypter->set_key(crypter, symmetricKey) ||
		!crypter->encrypt(crypter, in, iv, &out))
	{
		crypter->destroy(crypter);
		chunk_clear(&in);
		chunk_clear(&symmetricKey);
		chunk_free(&iv);
		return FALSE;
	}
	crypter->destroy(crypter);
	chunk_clear(&in);
	DBG3(DBG_LIB, "  encrypted data: %B", &out);

	/* protect symmetric key by public key encryption */
	{
		public_key_t *key = cert->get_public_key(cert);

		if (key == NULL)
		{
			DBG1(DBG_LIB, "  public key not found in encryption certificate");
			chunk_clear(&symmetricKey);
			chunk_free(&iv);
			chunk_free(&out);
			return FALSE;
		}
		key->encrypt(key, ENCRYPT_RSA_PKCS1, symmetricKey, &protectedKey);
		key->destroy(key);
		chunk_clear(&symmetricKey);
	}

	/* build pkcs7 enveloped data object */
	{
		chunk_t contentEncryptionAlgorithm = asn1_wrap(ASN1_SEQUENCE, "mm",
					asn1_build_known_oid(alg_oid),
					asn1_wrap(ASN1_OCTET_STRING, "m", iv));

		chunk_t encryptedContentInfo = asn1_wrap(ASN1_SEQUENCE, "mmm",
					asn1_build_known_oid(OID_PKCS7_DATA),
					contentEncryptionAlgorithm,
					asn1_wrap(ASN1_CONTEXT_S_0, "m", out));

		chunk_t encryptedKey = asn1_wrap(ASN1_OCTET_STRING, "m", protectedKey);

		chunk_t recipientInfo = asn1_wrap(ASN1_SEQUENCE, "cmmm",
					ASN1_INTEGER_0,
					pkcs7_build_issuerAndSerialNumber(cert),
					asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
					encryptedKey);

		this->content = asn1_wrap(ASN1_SEQUENCE, "cmm",
					ASN1_INTEGER_0,
					asn1_wrap(ASN1_SET, "m", recipientInfo),
					encryptedContentInfo);
		chunk_free(&this->data);
		this->type = OID_PKCS7_ENVELOPED_DATA;
		this->data = get_contentInfo(this);
	}
	return TRUE;
}

METHOD(pkcs7_t, build_signedData, bool,
	private_pkcs7_t *this, private_key_t *private_key, hash_algorithm_t alg)
{
	chunk_t authenticatedAttributes = chunk_empty;
	chunk_t encryptedDigest = chunk_empty;
	chunk_t signerInfo, encoding = chunk_empty;
	signature_scheme_t scheme;
	int digest_oid;
	certificate_t *cert;

	if (this->certs->get_first(this->certs, (void**)&cert) != SUCCESS)
	{
		DBG1(DBG_LIB, "  no pkcs7 signer certificate found");
		return FALSE;
	}
	digest_oid = hasher_algorithm_to_oid(alg);
	scheme = signature_scheme_from_oid(digest_oid);

	if (this->attributes != NULL)
	{
		if (this->data.ptr != NULL)
		{
			chunk_t messageDigest, signingTime, attributes;
			hasher_t *hasher;
			time_t now;

			hasher = lib->crypto->create_hasher(lib->crypto, alg);
			if (!hasher ||
				!hasher->allocate_hash(hasher, this->data, &messageDigest))
			{
				DESTROY_IF(hasher);
				DBG1(DBG_LIB, "  hash algorithm %N not support",
					 hash_algorithm_names, alg);
				return FALSE;
			}
			hasher->destroy(hasher);
			this->attributes->set_attribute(this->attributes,
									OID_PKCS9_MESSAGE_DIGEST,
									messageDigest);
			free(messageDigest.ptr);

			/* take the current time as signingTime */
			now = time(NULL);
			signingTime = asn1_from_time(&now, ASN1_UTCTIME);
			this->attributes->set_attribute_raw(this->attributes,
									OID_PKCS9_SIGNING_TIME, signingTime);
			this->attributes->set_attribute_raw(this->attributes,
									OID_PKCS9_CONTENT_TYPE,
									asn1_build_known_oid(OID_PKCS7_DATA));

			attributes = this->attributes->get_encoding(this->attributes);

			private_key->sign(private_key, scheme, attributes, &encryptedDigest);
			authenticatedAttributes = chunk_clone(attributes);
			*authenticatedAttributes.ptr = ASN1_CONTEXT_C_0;
		}
	}
	else if (this->data.ptr != NULL)
	{
		private_key->sign(private_key, scheme, this->data, &encryptedDigest);
	}
	if (encryptedDigest.ptr)
	{
		encryptedDigest = asn1_wrap(ASN1_OCTET_STRING, "m", encryptedDigest);
	}
	signerInfo = asn1_wrap(ASN1_SEQUENCE, "cmmmmm",
					ASN1_INTEGER_1,
					pkcs7_build_issuerAndSerialNumber(cert),
					asn1_algorithmIdentifier(digest_oid),
					authenticatedAttributes,
					asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
					encryptedDigest);

	if (this->data.ptr != NULL)
	{
		chunk_free(&this->content);
		this->content = asn1_simple_object(ASN1_OCTET_STRING, this->data);
		chunk_free(&this->data);
	}
	this->type = OID_PKCS7_DATA;
	this->data = get_contentInfo(this);
	chunk_free(&this->content);

	cert->get_encoding(cert, CERT_ASN1_DER, &encoding);

	this->content = asn1_wrap(ASN1_SEQUENCE, "cmcmm",
			ASN1_INTEGER_1,
			asn1_wrap(ASN1_SET, "m", asn1_algorithmIdentifier(digest_oid)),
			this->data,
			asn1_wrap(ASN1_CONTEXT_C_0, "m", encoding),
			asn1_wrap(ASN1_SET, "m", signerInfo));
	chunk_free(&this->data);
	this->type = OID_PKCS7_SIGNED_DATA;
	this->data = get_contentInfo(this);

	return TRUE;
}

METHOD(pkcs7_t, destroy, void,
	private_pkcs7_t *this)
{
	DESTROY_IF(this->attributes);
	this->certs->destroy_offset(this->certs, offsetof(certificate_t, destroy));
	free(this->content.ptr);
	free(this->data.ptr);
	free(this);
}

/**
 * Generic private constructor
 */
static private_pkcs7_t *pkcs7_create_empty(void)
{
	private_pkcs7_t *this;

	INIT(this,
		.public = {
			.is_data = _is_data,
			.is_signedData = _is_signedData,
			.is_envelopedData = _is_envelopedData,
			.parse_data = _parse_data,
			.parse_signedData = _parse_signedData,
			.parse_envelopedData = _parse_envelopedData,
			.get_data = _get_data,
			.get_contentInfo = _get_contentInfo,
			.create_certificate_enumerator = _create_certificate_enumerator,
			.set_certificate = _set_certificate,
			.set_attributes = _set_attributes,
			.get_attributes = _get_attributes,
			.build_envelopedData = _build_envelopedData,
			.build_signedData = _build_signedData,
			.destroy = _destroy,
		},
		.type = OID_UNKNOWN,
		.certs = linked_list_create(),
	);

	return this;
}

/*
 * Described in header.
 */
pkcs7_t *pkcs7_create_from_chunk(chunk_t chunk, u_int level)
{
	private_pkcs7_t *this = pkcs7_create_empty();

	this->level = level;
	this->data = chunk_clone(chunk);

	return &this->public;
}

/*
 * Described in header.
 */
pkcs7_t *pkcs7_create_from_data(chunk_t data)
{
	private_pkcs7_t *this = pkcs7_create_empty();

	this->data = chunk_clone(data);

	return &this->public;
}

