/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2008 Andreas Steffen
 *
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
 *
 * $Id$
 */

#include <stdlib.h>
#include <string.h>

#include <library.h>
#include "debug.h"

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
	 * Has the content already been parsed?
	 */
	bool parsed;

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

/**
 * PKCS7 contentInfo OIDs
 */
static u_char ASN1_pkcs7_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};

static u_char ASN1_pkcs7_signed_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};

static u_char ASN1_pkcs7_enveloped_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
};

static u_char ASN1_pkcs7_signed_enveloped_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04
};

static u_char ASN1_pkcs7_digested_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05
};

static char ASN1_pkcs7_encrypted_data_oid_str[] = {
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06
};

static const chunk_t ASN1_pkcs7_data_oid = 
						chunk_from_buf(ASN1_pkcs7_data_oid_str);
static const chunk_t ASN1_pkcs7_signed_data_oid =
						chunk_from_buf(ASN1_pkcs7_signed_data_oid_str);
static const chunk_t ASN1_pkcs7_enveloped_data_oid =
						chunk_from_buf(ASN1_pkcs7_enveloped_data_oid_str);
static const chunk_t ASN1_pkcs7_signed_enveloped_data_oid = 
						chunk_from_buf(ASN1_pkcs7_signed_enveloped_data_oid_str);
static const chunk_t ASN1_pkcs7_digested_data_oid =
						chunk_from_buf(ASN1_pkcs7_digested_data_oid_str);
static const chunk_t ASN1_pkcs7_encrypted_data_oid =
						chunk_from_buf(ASN1_pkcs7_encrypted_data_oid_str);

/**
 * 3DES and DES encryption OIDs
 */
static u_char ASN1_3des_ede_cbc_oid_str[] = {
	0x06, 0x08,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07
};

static u_char ASN1_des_cbc_oid_str[] = {
	0x06, 0x05,
		  0x2B, 0x0E, 0x03, 0x02, 0x07
};

static const chunk_t ASN1_3des_ede_cbc_oid = 
						chunk_from_buf(ASN1_3des_ede_cbc_oid_str);
static const chunk_t ASN1_des_cbc_oid =
						chunk_from_buf(ASN1_des_cbc_oid_str);

/**
 * Implements pkcs7_t.is_data.
 */
static bool is_data(private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_DATA;
}

/**
 * Implements pkcs7_t.is_signedData.
 */
static bool is_signedData(private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_SIGNED_DATA;
}

/**
 * Implements pkcs7_t.is_envelopedData.
 */
static bool is_envelopedData(private_pkcs7_t *this)
{
	return this->type == OID_PKCS7_ENVELOPED_DATA;
}

/**
 * Check whether to abort the requested parsing
 */
static bool abort_parsing(private_pkcs7_t *this, int type)
{
	if (this->type != type)
	{
		DBG1("pkcs7 content to be parsed is not of type '%s'",
			 oid_names[type]);
		return TRUE;
	}
	if (this->parsed)
	{
		DBG1("pkcs7 content has already been parsed");
		return TRUE;
	}
	this->parsed = TRUE;
	return FALSE;
}

/**
 * Implements pkcs7_t.parse_data.
 */
static bool parse_data(private_pkcs7_t *this)
{
	chunk_t data = this->content;

	if (abort_parsing(this, OID_PKCS7_DATA))
	{
		return FALSE;
	}
	if (data.len == 0)
	{
		this->data = chunk_empty;
		return TRUE;
	}
	if (asn1_parse_simple_object(&data, ASN1_OCTET_STRING, this->level, "data"))
	{
		this->data = chunk_clone(data);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
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
	{ 1,   "end loop",						ASN1_EOC,			ASN1_END  }  /* 25 */
};
#define PKCS7_DIGEST_ALG	 		 3
#define PKCS7_SIGNED_CONTENT_INFO	 5
#define PKCS7_SIGNED_CERT	 		 7
#define PKCS7_SIGNER_INFO			13
#define PKCS7_SIGNED_ISSUER			16
#define PKCS7_SIGNED_SERIAL_NUMBER	17
#define PKCS7_DIGEST_ALGORITHM		18
#define PKCS7_AUTH_ATTRIBUTES		19
#define PKCS7_DIGEST_ENC_ALGORITHM	21
#define PKCS7_ENCRYPTED_DIGEST		22
#define PKCS7_SIGNED_ROOF			26

/**
 * Implements pkcs7_t.parse_signedData.
 */
static bool parse_signedData(private_pkcs7_t *this, x509_t *cacert)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int digest_alg = OID_UNKNOWN;
	int enc_alg    = OID_UNKNOWN;
	int signerInfos = 0;
	bool success = FALSE;

	chunk_t encrypted_digest = chunk_empty;

	if (abort_parsing(this, OID_PKCS7_SIGNED_DATA))
	{
		return FALSE;
	}

	parser = asn1_parser_create(signedDataObjects, PKCS7_SIGNED_ROOF,
								this->content);
	parser->set_top_level(parser, this->level);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
			case PKCS7_DIGEST_ALG:
				digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_SIGNED_CONTENT_INFO:
			{
				chunk_t pureData;
				pkcs7_t *data = pkcs7_create_from_chunk(object, level+1);

				if (data == NULL)
				{
					goto end;
				}
				if (!data->parse_data(data))
				{
					data->destroy(data);
					goto end;
				}
				pureData = data->get_data(data);
				this->data = (pureData.len)? chunk_clone(pureData) : chunk_empty;
				data->destroy(data);
				break;
			}
			case PKCS7_SIGNED_CERT:
			{
				x509_t *cert = x509_create_from_chunk(chunk_clone(object), level+1);

				if (cert)
				{
					this->certs->insert_last(this->certs, (void*)cert);
				}
				break;
			}
			case PKCS7_SIGNER_INFO:
				signerInfos++;
				DBG2("  signer #%d", signerInfos);
				break;
			case PKCS7_SIGNED_ISSUER:
			{
				identification_t *issuer;

				issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				DBG2("  '%D'", issuer);
				issuer->destroy(issuer);
				break;
			}
			case PKCS7_AUTH_ATTRIBUTES:
				*object.ptr = ASN1_SET;
				this->attributes = pkcs9_create_from_chunk(object, level+1);
				*object.ptr = ASN1_CONTEXT_C_0;
				break;
			case PKCS7_DIGEST_ALGORITHM:
				digest_alg = parse_algorithmIdentifier(object, level, NULL);
				break;
			case PKCS7_DIGEST_ENC_ALGORITHM:
				enc_alg = parse_algorithmIdentifier(object, level, NULL);
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
		hash_algorithm_t algorithm = hasher_algorithm_from_oid(digest_alg);
		rsa_public_key_t *signer = cacert->get_public_key(cacert);

		if (signerInfos == 0)
		{
			DBG1("no signerInfo object found");
			return FALSE;
		}
		else if (signerInfos > 1)
		{
			DBG1("more than one signerInfo object found");
			return FALSE;
		}
		if (this->attributes == NULL)
		{
			DBG1("no authenticatedAttributes object found");
			return FALSE;
		}
		if (enc_alg != OID_RSA_ENCRYPTION)
		{
			DBG1("only RSA digest encryption supported");
			return FALSE;
		}
		if (signer->verify_emsa_pkcs1_signature(signer, algorithm,
				this->attributes->get_encoding(this->attributes), encrypted_digest) != SUCCESS)
		{
			DBG1("invalid digest signature");
			return FALSE;
		}
		else
		{
			DBG2("digest signature is valid");
		}
		if (this->data.ptr != NULL)
		{
			chunk_t messageDigest = this->attributes->get_messageDigest(this->attributes);

			if (messageDigest.ptr == NULL)
			{
				DBG1("messageDigest attribute not found");
				return FALSE;
			}
			else
			{
				hasher_t *hasher;
				chunk_t hash;
				bool valid;

				hasher = lib->crypto->create_hasher(lib->crypto, algorithm)
				if (hasher == NULL)
				{
					DBG1("hash algorithm %N not supported",
						 hash_algorithm_names, algorithm);
					free(messageDigest.ptr);
					return FALSE;
				}
				hasher->allocate_hash(hasher, this->data, &hash);
				hasher->destroy(hasher);
				DBG3("hash: %B", &hash);

				valid = chunk_equals(messageDigest, hash);
				free(messageDigest.ptr);
				free(hash.ptr);
				if (valid)
				{
					DBG2("messageDigest is valid");
				}
				else
				{
					DBG1("invalid messageDigest");
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
	{ 2,     "encryptedContent",			ASN1_CONTEXT_S_0, 	ASN1_BODY }  /* 14 */
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
#define PKCS7_ENVELOPED_ROOF			15

/**
 * Parse PKCS#7 envelopedData content
 */
static bool parse_envelopedData(private_pkcs7_t *this, chunk_t serialNumber,
								rsa_private_key_t *key)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	chunk_t iv                = chunk_empty;
	chunk_t symmetric_key     = chunk_empty;
	chunk_t encrypted_content = chunk_empty;

	crypter_t *crypter = NULL;

	if (abort_parsing(this, OID_PKCS7_ENVELOPED_DATA))
	{
		return FALSE;
	}

	parser = asn1_parser_create(envelopedDataObjects, PKCS7_ENVELOPED_ROOF,
								this->content);
	parser->set_top_level(parser, this->level);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PKCS7_ENVELOPED_VERSION:
				if (*object.ptr != 0)
				{
					DBG1("envelopedData version is not 0");
					goto end;
				}
				break;
			case PKCS7_RECIPIENT_INFO_VERSION:
				if (*object.ptr != 0)
				{
					DBG1("recipient info version is not 0");
					goto end;
				}
				break;
			case PKCS7_ISSUER:
				{
					identification_t *issuer;

					issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
					DBG2("  '%D'", issuer);
					issuer->destroy(issuer);
				}
				break;
			case PKCS7_SERIAL_NUMBER:
				if (!chunk_equals(serialNumber, object))
				{
					DBG1("serial numbers do not match");
					goto end;
				}
				break;
			case PKCS7_ENCRYPTION_ALG:
				{
					int alg = parse_algorithmIdentifier(object, level, NULL);

					if (alg != OID_RSA_ENCRYPTION)
					{
						DBG1("only rsa encryption supported");
						goto end;
					}
				}
				break;
			case PKCS7_ENCRYPTED_KEY:
				if (key->pkcs1_decrypt(key, object, &symmetric_key) != SUCCESS)
				{
					DBG1("symmetric key could not be decrypted with rsa");
					goto end;
				}
				DBG4("symmetric key : %B", &symmetric_key);
				break;
			case PKCS7_CONTENT_TYPE:
				if (known_oid(object) != OID_PKCS7_DATA)
				{
					DBG1("encrypted content not of type pkcs7 data");
		 			goto end;
				}
				break;
			case PKCS7_CONTENT_ENC_ALGORITHM:
				{
					int alg = parse_algorithmIdentifier(object, level, &iv);

					switch (alg)
					{
						case OID_DES_CBC:
							crypter = crypter_create(ENCR_DES, 0);
							break;
						case OID_3DES_EDE_CBC:
							crypter = crypter_create(ENCR_3DES, 0);
							break;
						default:
							DBG1("Only DES and 3DES supported for symmetric encryption");
							goto end;
					}
					if (symmetric_key.len != crypter->get_key_size(crypter))
					{
						DBG1("symmetric key has wrong length");
						goto end;
					}
					if (!parse_asn1_simple_object(&iv, ASN1_OCTET_STRING, level+1, "IV"))
					{
						DBG1("IV could not be parsed");
						goto end;
					}
					if (iv.len != crypter->get_block_size(crypter))
					{
						DBG1("IV has wrong length");
						goto end;
					}
				}
				break;
			case PKCS7_ENCRYPTED_CONTENT:
				encrypted_content = object;
				break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		goto failed;
	}

	/* decrypt the content */
	crypter->set_key(crypter, symmetric_key);
	crypter->decrypt(crypter, encrypted_content, iv, &this->data);
	DBG3("decrypted content with padding: %B", &this->data);

	/* remove the padding */
	{
		u_char *pos = this->data.ptr + this->data.len - 1;
		u_char pattern = *pos;
		size_t padding = pattern;

		if (padding > this->data.len)
		{
			DBG1("padding greater than data length");
			goto failed;
		}
		this->data.len -= padding;

		while (padding-- > 0)
		{
			if (*pos-- != pattern)
			{
				DBG1("wrong padding pattern");
				goto failed;
			}
		}
	}
	crypter->destroy(crypter);
	free(symmetric_key.ptr);
	return TRUE;

failed:
	DESTROY_IF(crypter);
	free(symmetric_key.ptr);
	chunk_free(&this->data);
	return FALSE;
}

/**
 * Implements pkcs7_t.get_data.
 */
static chunk_t get_data(private_pkcs7_t *this)
{
	return this->data;
}

/**
 * Implements pkcs7_t.get_contentInfo.
 */
static chunk_t get_contentInfo(private_pkcs7_t *this)
{
	chunk_t content_type;

	/* select DER-encoded OID for pkcs7_contentInfo type */
	switch(this->type)
	{
		case OID_PKCS7_DATA:
			content_type = ASN1_pkcs7_data_oid;
			break;
		case OID_PKCS7_SIGNED_DATA:
			content_type = ASN1_pkcs7_signed_data_oid;
			break;
		case OID_PKCS7_ENVELOPED_DATA:
			content_type = ASN1_pkcs7_enveloped_data_oid;
			break;
		case OID_PKCS7_SIGNED_ENVELOPED_DATA:
			content_type = ASN1_pkcs7_signed_enveloped_data_oid;
			break;
		case OID_PKCS7_DIGESTED_DATA:
			content_type = ASN1_pkcs7_digested_data_oid;
			break;
		case OID_PKCS7_ENCRYPTED_DATA:
			content_type = ASN1_pkcs7_encrypted_data_oid;
			break;
		case OID_UNKNOWN:
		default:
			DBG1("invalid pkcs7 contentInfo type");
			return chunk_empty;
	}

	return (this->content.ptr == NULL)
			? asn1_simple_object(ASN1_SEQUENCE, content_type)
			: asn1_wrap(ASN1_SEQUENCE, "cm",
					content_type,
					asn1_simple_object(ASN1_CONTEXT_C_0, this->content)
			  );
}

/**
 * Implements pkcs7_t.create_certificate_iterator
 */
static iterator_t *create_certificate_iterator(const private_pkcs7_t *this)
{
	return this->certs->create_iterator(this->certs, TRUE);
}

/**
 * Implements pkcs7_t.set_certificate
 */
static void set_certificate(private_pkcs7_t *this, x509_t *cert)
{
	if (cert)
	{
		/* TODO the certificate is currently not cloned */
		this->certs->insert_last(this->certs, cert);
	}
}

/**
 * Implements pkcs7_t.set_attributes
 */
static void set_attributes(private_pkcs7_t *this, pkcs9_t *attributes)
{
	this->attributes = attributes;
}

/**
 * build a DER-encoded issuerAndSerialNumber object
 */
chunk_t pkcs7_build_issuerAndSerialNumber(x509_t *cert)
{
	identification_t *issuer = cert->get_issuer(cert);

    return asn1_wrap(ASN1_SEQUENCE, "cm",
			issuer->get_encoding(issuer),
			asn1_simple_object(ASN1_INTEGER, cert->get_serialNumber(cert)));
}

/**
 * Implements pkcs7_t.build_envelopedData.
 */
bool build_envelopedData(private_pkcs7_t *this, x509_t *cert,
						 encryption_algorithm_t alg)
{
	chunk_t iv, symmetricKey, in, out, alg_oid;
	crypter_t *crypter;

	/* select OID of symmetric encryption algorithm */
	switch (alg)
	{
		case ENCR_DES:
			alg_oid = ASN1_des_cbc_oid;
			break;
		case ENCR_3DES:
			alg_oid = ASN1_3des_ede_cbc_oid;
			break;
		default:
			DBG1("  encryption algorithm %N not supported",
				  encryption_algorithm_names, alg);
			return FALSE;
	}

	crypter = crypter_create(alg, 0);
	if (crypter == NULL)
	{
		DBG1("  could not create crypter for algorithm %N",
			 encryption_algorithm_names, alg);
		return FALSE;
	}

	/* generate a true random symmetric encryption key
	 * and a pseudo-random iv
	 */
	{
		rng_t *rng;
		
		rng = lib->crypto->create_rng(lib->crypto, RNG_REAL);
		rng->allocate_bytes(rng, crypter->get_key_size(crypter), &symmetricKey);
		DBG4("  symmetric encryption key: %B", &symmetricKey);
		rng->destroy(rng);

		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		rng->allocate_bytes(rng, crypter->get_block_size(crypter), &iv);
		DBG4("  initialization vector: %B", &iv);
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

		DBG2("  padding %d bytes of data to multiple block size of %d bytes",
		 	(int)this->data.len, (int)in.len);

		/* copy data */
		memcpy(in.ptr, this->data.ptr, this->data.len);
		/* append padding */
		memset(in.ptr + this->data.len, padding, padding);
	}
	DBG3("  padded unencrypted data: %B", &in);

	/* symmetric encryption of data object */
	crypter->set_key(crypter, symmetricKey);
	crypter->encrypt(crypter, in, iv, &out);
	crypter->destroy(crypter);
	chunk_clear(&in);
    DBG3("  encrypted data: %B", &out);

	/* build pkcs7 enveloped data object */ 
	{
		chunk_t contentEncryptionAlgorithm = asn1_wrap(ASN1_SEQUENCE, "cm",
					alg_oid,
					asn1_wrap(ASN1_OCTET_STRING, "m", iv));
	
		chunk_t encryptedContentInfo = asn1_wrap(ASN1_SEQUENCE, "cmm",
					ASN1_pkcs7_data_oid,
					contentEncryptionAlgorithm,
					asn1_wrap(ASN1_CONTEXT_S_0, "m", out));

		chunk_t wrappedKey, encryptedKey, recipientInfo;

		rsa_public_key_t *public_key = cert->get_public_key(cert);

		public_key->pkcs1_encrypt(public_key, symmetricKey, &wrappedKey);
		chunk_clear(&symmetricKey);

		encryptedKey = asn1_wrap(ASN1_OCTET_STRING, "m", wrappedKey);

		recipientInfo = asn1_wrap(ASN1_SEQUENCE, "cmcm",
					ASN1_INTEGER_0,
					pkcs7_build_issuerAndSerialNumber(cert),
					asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
					encryptedKey);

		this->content = asn1_wrap(ASN1_SEQUENCE, "cmm",
					ASN1_INTEGER_0,
					asn1_wrap(ASN1_SET, "m", recipientInfo),
					encryptedContentInfo);
		this->type = OID_PKCS7_ENVELOPED_DATA;
    }
	return TRUE;
}

/**
 * Implements pkcs7_t.build_signedData.
 */
bool build_signedData(private_pkcs7_t *this, rsa_private_key_t *private_key,
					  hash_algorithm_t alg)
{
	int signature_oid = hasher_signature_algorithm_to_oid(alg);
	chunk_t authenticatedAttributes = chunk_empty;
	chunk_t encryptedDigest = chunk_empty;
	chunk_t signerInfo;
	x509_t *cert;

	if (this->certs->get_first(this->certs, (void**)&cert) != SUCCESS)
	{
		DBG1("  no pkcs7 signer certificate found");
		return FALSE;
	}

	if (this->attributes != NULL)
	{
		if(this->data.ptr != NULL)
		{
			hasher_t *hasher;
		
			hasher = lib->crypto->create_hasher(lib->crypto, alg);
			if (hasher == NULL)
			{
				DBG1("  hash algorithm %N not support",
					 hash_algorithm_names, alg);
				return FALSE;
			}
		
			/* take the current time as signingTime */
			time_t now = time(NULL);
			chunk_t	signingTime = asn1_from_time(&now, ASN1_UTCTIME);

			chunk_t messageDigest, attributes;
	
			hasher->allocate_hash(hasher, this->data, &messageDigest);
			hasher->destroy(hasher);
			this->attributes->set_attribute(this->attributes,
								OID_PKCS9_CONTENT_TYPE, ASN1_pkcs7_data_oid);
			this->attributes->set_messageDigest(this->attributes,
								messageDigest);
			this->attributes->set_attribute(this->attributes,
					 			OID_PKCS9_SIGNING_TIME, signingTime);
			attributes = this->attributes->get_encoding(this->attributes);

			free(messageDigest.ptr);
			free(signingTime.ptr);

			private_key->build_emsa_pkcs1_signature(private_key, alg,
							attributes, &encryptedDigest);
			authenticatedAttributes = chunk_clone(attributes);
			*authenticatedAttributes.ptr = ASN1_CONTEXT_C_0;
		}
	}
	else if (this->data.ptr != NULL)
	{
		private_key->build_emsa_pkcs1_signature(private_key, alg,
						this->data, &encryptedDigest);
	}
	if (encryptedDigest.ptr)
	{
		encryptedDigest = asn1_wrap(ASN1_OCTET_STRING, "m", encryptedDigest);
	}

	signerInfo = asn1_wrap(ASN1_SEQUENCE, "cmcmcm",
					ASN1_INTEGER_1,
					pkcs7_build_issuerAndSerialNumber(cert),
					asn1_algorithmIdentifier(signature_oid),
					authenticatedAttributes,
					asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
					encryptedDigest);

	if (this->data.ptr != NULL)
	{
		this->content = asn1_simple_object(ASN1_OCTET_STRING, this->data);
		chunk_free(&this->data);
	}
	this->type = OID_PKCS7_DATA;
	this->data = get_contentInfo(this);
	chunk_free(&this->content);

	this->type = OID_PKCS7_SIGNED_DATA;

	this->content = asn1_wrap(ASN1_SEQUENCE, "cmcmm",
			ASN1_INTEGER_1,
			asn1_simple_object(ASN1_SET, asn1_algorithmIdentifier(signature_oid)),
			this->data,
			asn1_simple_object(ASN1_CONTEXT_C_0, cert->get_certificate(cert)),
			asn1_wrap(ASN1_SET, "m", signerInfo));

	return TRUE;
}

/**
 * Implements pkcs7_t.destroy
 */
static void destroy(private_pkcs7_t *this)
{
	DESTROY_IF(this->attributes);
	this->certs->destroy_offset(this->certs, offsetof(x509_t, destroy));
	free(this->content.ptr);
	free(this->data.ptr);
	free(this);
}

/**
 * ASN.1 definition of the PKCS#7 ContentInfo type
 */
static const asn1Object_t contentInfoObjects[] = {
	{ 0, "contentInfo",		ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "contentType",	ASN1_OID,			ASN1_BODY }, /*  1 */
	{ 1,   "content",		ASN1_CONTEXT_C_0,	ASN1_OPT |
												ASN1_BODY }, /*  2 */
	{ 1,   "end opt",		ASN1_EOC,			ASN1_END  }  /*  3 */
};
#define PKCS7_INFO_TYPE		1
#define PKCS7_INFO_CONTENT	2
#define PKCS7_INFO_ROOF		4

/**
 * Parse PKCS#7 contentInfo object
 */
static bool parse_contentInfo(chunk_t blob, u_int level0, private_pkcs7_t *cInfo)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	parser = asn1_parser_create(contentInfoObjects, PKCS7_INFO_TYPE, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == PKCS7_INFO_TYPE)
		{
			cInfo->type = known_oid(object);
			if (cInfo->type < OID_PKCS7_DATA
			||  cInfo->type > OID_PKCS7_ENCRYPTED_DATA)
			{
				DBG1("unknown pkcs7 content type");
				goto end;
			}
		}
		else if (objectID == PKCS7_INFO_CONTENT && object.len > 0)
		{
			cInfo->content = chunk_clone(object);
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * Generic private constructor
 */
static private_pkcs7_t *pkcs7_create_empty(void)
{
	private_pkcs7_t *this = malloc_thing(private_pkcs7_t);
	
	/* initialize */
	this->type = OID_UNKNOWN;
	this->content = chunk_empty;
	this->parsed = FALSE;
	this->level = 0;
	this->data = chunk_empty;
	this->attributes = NULL;
	this->certs = linked_list_create();

	/*public functions */
	this->public.is_data = (bool (*) (pkcs7_t*))is_data;
	this->public.is_signedData = (bool (*) (pkcs7_t*))is_signedData;
	this->public.is_envelopedData = (bool (*) (pkcs7_t*))is_envelopedData;
	this->public.parse_data = (bool (*) (pkcs7_t*))parse_data;
	this->public.parse_signedData = (bool (*) (pkcs7_t*,x509_t*))parse_signedData;
	this->public.parse_envelopedData = (bool (*) (pkcs7_t*,chunk_t,rsa_private_key_t*))parse_envelopedData;
	this->public.get_data = (chunk_t (*) (pkcs7_t*))get_data;
	this->public.get_contentInfo = (chunk_t (*) (pkcs7_t*))get_contentInfo;
	this->public.create_certificate_iterator = (iterator_t* (*) (pkcs7_t*))create_certificate_iterator;
	this->public.set_certificate = (void (*) (pkcs7_t*,x509_t*))set_certificate;
	this->public.set_attributes = (void (*) (pkcs7_t*,pkcs9_t*))set_attributes;
	this->public.build_envelopedData = (bool (*) (pkcs7_t*,x509_t*,encryption_algorithm_t))build_envelopedData;
	this->public.build_signedData = (bool (*) (pkcs7_t*,rsa_private_key_t*,hash_algorithm_t))build_signedData;
	this->public.destroy = (void (*) (pkcs7_t*))destroy;

	return this;
}

/*
 * Described in header.
 */
pkcs7_t *pkcs7_create_from_chunk(chunk_t chunk, u_int level)
{
	private_pkcs7_t *this = pkcs7_create_empty();
	
	this->level = level + 2;
	if (!parse_contentInfo(chunk, level, this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/*
 * Described in header.
 */
pkcs7_t *pkcs7_create_from_data(chunk_t data)
{
	private_pkcs7_t *this = pkcs7_create_empty();

	this->data = chunk_clone(data);
	this->parsed = TRUE;

	return &this->public;
}

/*
 * Described in header.
 */
pkcs7_t *pkcs7_create_from_file(const char *filename, const char *label)
{
	bool pgp = FALSE;
	chunk_t chunk = chunk_empty;
	char cert_label[BUF_LEN];
	pkcs7_t *pkcs7;

	snprintf(cert_label, BUF_LEN, "%s pkcs7", label);

	if (!pem_asn1_load_file(filename, NULL, cert_label, &chunk, &pgp))
	{
		return NULL;
	}

	pkcs7 = pkcs7_create_from_chunk(chunk, 0);
	free(chunk.ptr);
	return pkcs7;
}
