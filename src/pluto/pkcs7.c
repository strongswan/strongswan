/* Support of PKCS#7 data structures
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2005 Andreas Steffen
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

#include <freeswan.h>

#include <library.h>
#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/rngs/rng.h>
#include <crypto/crypters/crypter.h>

#include "constants.h"
#include "defs.h"
#include "x509.h"
#include "certs.h"
#include "pkcs7.h"

const contentInfo_t empty_contentInfo = {
	OID_UNKNOWN , /* type */
	{ NULL, 0 }   /* content */
};

/**
 * ASN.1 definition of the PKCS#7 ContentInfo type
 */
static const asn1Object_t contentInfoObjects[] = {
	{ 0, "contentInfo",                     ASN1_SEQUENCE,     ASN1_NONE          }, /*  0 */
	{ 1,   "contentType",                   ASN1_OID,          ASN1_BODY          }, /*  1 */
	{ 1,   "content",                       ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_BODY }, /*  2 */
	{ 1,   "end opt",                       ASN1_EOC,          ASN1_END           }, /*  3 */
	{ 0, "exit",                            ASN1_EOC,          ASN1_EXIT          }
};
#define PKCS7_INFO_TYPE         1
#define PKCS7_INFO_CONTENT      2

/**
 * ASN.1 definition of the PKCS#7 signedData type
 */
static const asn1Object_t signedDataObjects[] = {
	{ 0, "signedData",                      ASN1_SEQUENCE,     ASN1_NONE          }, /*  0 */
	{ 1,   "version",                       ASN1_INTEGER,      ASN1_BODY          }, /*  1 */
	{ 1,   "digestAlgorithms",              ASN1_SET,          ASN1_LOOP          }, /*  2 */
	{ 2,     "algorithm",                   ASN1_EOC,          ASN1_RAW           }, /*  3 */
	{ 1,   "end loop",                      ASN1_EOC,          ASN1_END           }, /*  4 */
	{ 1,   "contentInfo",                   ASN1_EOC,          ASN1_RAW           }, /*  5 */
	{ 1,   "certificates",                  ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_LOOP }, /*  6 */
	{ 2,      "certificate",                ASN1_SEQUENCE,     ASN1_OBJ           }, /*  7 */
	{ 1,   "end opt or loop",               ASN1_EOC,          ASN1_END           }, /*  8 */
	{ 1,   "crls",                          ASN1_CONTEXT_C_1,  ASN1_OPT|ASN1_LOOP }, /*  9 */
	{ 2,      "crl",                        ASN1_SEQUENCE,     ASN1_OBJ           }, /* 10 */
	{ 1,   "end opt or loop",               ASN1_EOC,          ASN1_END           }, /* 11 */
	{ 1,   "signerInfos",                   ASN1_SET,          ASN1_LOOP          }, /* 12 */
	{ 2,     "signerInfo",                  ASN1_SEQUENCE,     ASN1_NONE          }, /* 13 */
	{ 3,       "version",                   ASN1_INTEGER,      ASN1_BODY          }, /* 14 */
	{ 3,       "issuerAndSerialNumber",     ASN1_SEQUENCE,     ASN1_BODY          }, /* 15 */
	{ 4,         "issuer",                  ASN1_SEQUENCE,     ASN1_OBJ           }, /* 16 */
	{ 4,         "serial",                  ASN1_INTEGER,      ASN1_BODY          }, /* 17 */
	{ 3,       "digestAlgorithm",           ASN1_EOC,          ASN1_RAW           }, /* 18 */
	{ 3,       "authenticatedAttributes",   ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_OBJ  }, /* 19 */
	{ 3,       "end opt",                   ASN1_EOC,          ASN1_END           }, /* 20 */
	{ 3,       "digestEncryptionAlgorithm", ASN1_EOC,          ASN1_RAW           }, /* 21 */
	{ 3,       "encryptedDigest",           ASN1_OCTET_STRING, ASN1_BODY          }, /* 22 */
	{ 3,       "unauthenticatedAttributes", ASN1_CONTEXT_C_1,  ASN1_OPT           }, /* 23 */
	{ 3,       "end opt",                   ASN1_EOC,          ASN1_END           }, /* 24 */
	{ 1,   "end loop",                      ASN1_EOC,          ASN1_END           }, /* 25 */
	{ 0, "exit",                            ASN1_EOC,          ASN1_EXIT          }
};
#define PKCS7_DIGEST_ALG                 3
#define PKCS7_SIGNED_CONTENT_INFO        5
#define PKCS7_SIGNED_CERT                7
#define PKCS7_SIGNER_INFO               13
#define PKCS7_SIGNED_ISSUER             16
#define PKCS7_SIGNED_SERIAL_NUMBER      17
#define PKCS7_DIGEST_ALGORITHM          18
#define PKCS7_AUTH_ATTRIBUTES           19
#define PKCS7_DIGEST_ENC_ALGORITHM      21
#define PKCS7_ENCRYPTED_DIGEST          22

/**
 * ASN.1 definition of the PKCS#7 envelopedData type
 */
static const asn1Object_t envelopedDataObjects[] = {
	{ 0, "envelopedData",                  ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1,   "version",                      ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1,   "recipientInfos",               ASN1_SET,          ASN1_LOOP }, /*  2 */
	{ 2,     "recipientInfo",              ASN1_SEQUENCE,     ASN1_BODY }, /*  3 */
	{ 3,       "version",                  ASN1_INTEGER,      ASN1_BODY }, /*  4 */
	{ 3,       "issuerAndSerialNumber",    ASN1_SEQUENCE,     ASN1_BODY }, /*  5 */
	{ 4,         "issuer",                 ASN1_SEQUENCE,     ASN1_OBJ  }, /*  6 */
	{ 4,         "serial",                 ASN1_INTEGER,      ASN1_BODY }, /*  7 */
	{ 3,       "encryptionAlgorithm",      ASN1_EOC,          ASN1_RAW  }, /*  8 */
	{ 3,       "encryptedKey",             ASN1_OCTET_STRING, ASN1_BODY }, /*  9 */
	{ 1,   "end loop",                     ASN1_EOC,          ASN1_END  }, /* 10 */
	{ 1,   "encryptedContentInfo",         ASN1_SEQUENCE,     ASN1_OBJ  }, /* 11 */
	{ 2,     "contentType",                ASN1_OID,          ASN1_BODY }, /* 12 */
	{ 2,     "contentEncryptionAlgorithm", ASN1_EOC,          ASN1_RAW  }, /* 13 */
	{ 2,     "encryptedContent",           ASN1_CONTEXT_S_0,  ASN1_BODY }, /* 14 */
	{ 0, "exit",                           ASN1_EOC,          ASN1_EXIT }
};
#define PKCS7_ENVELOPED_VERSION          1
#define PKCS7_RECIPIENT_INFO_VERSION     4
#define PKCS7_ISSUER                     6
#define PKCS7_SERIAL_NUMBER              7
#define PKCS7_ENCRYPTION_ALG             8
#define PKCS7_ENCRYPTED_KEY              9
#define PKCS7_CONTENT_TYPE              12
#define PKCS7_CONTENT_ENC_ALGORITHM     13
#define PKCS7_ENCRYPTED_CONTENT         14
#define PKCS7_ENVELOPED_ROOF            15

/**
 * PKCS7 contentInfo OIDs
 */

static u_char ASN1_pkcs7_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};

static u_char ASN1_pkcs7_signed_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};

static u_char ASN1_pkcs7_enveloped_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
};

static u_char ASN1_pkcs7_signed_enveloped_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04
};

static u_char ASN1_pkcs7_digested_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05
};

static char ASN1_pkcs7_encrypted_data_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06
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
	0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07
};

static u_char ASN1_des_cbc_oid_str[] = {
	0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x07
};

static const chunk_t ASN1_3des_ede_cbc_oid = 
						chunk_from_buf(ASN1_3des_ede_cbc_oid_str);
static const chunk_t ASN1_des_cbc_oid =
						chunk_from_buf(ASN1_des_cbc_oid_str);

/**
 * PKCS#7 attribute type OIDs
 */

static u_char ASN1_contentType_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03
};

static u_char ASN1_messageDigest_oid_str[] = {
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04
};

static const chunk_t ASN1_contentType_oid =
						chunk_from_buf(ASN1_contentType_oid_str);
static const chunk_t ASN1_messageDigest_oid =
						chunk_from_buf(ASN1_messageDigest_oid_str);

/**
 * Parse PKCS#7 ContentInfo object
 */
bool pkcs7_parse_contentInfo(chunk_t blob, u_int level0, contentInfo_t *cInfo)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	parser = asn1_parser_create(contentInfoObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == PKCS7_INFO_TYPE)
		{
			cInfo->type = asn1_known_oid(object);
			if (cInfo->type < OID_PKCS7_DATA
			||  cInfo->type > OID_PKCS7_ENCRYPTED_DATA)
			{
				DBG1("unknown pkcs7 content type");
				goto end;
			}
		}
		else if (objectID == PKCS7_INFO_CONTENT)
		{
			cInfo->content = object;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * Parse a PKCS#7 signedData object
 */
bool pkcs7_parse_signedData(chunk_t blob, contentInfo_t *data, x509cert_t **cert,
							chunk_t *attributes, const x509cert_t *cacert)
{
	u_char buf[BUF_LEN];
	asn1_parser_t *parser;
	chunk_t object;
	int digest_alg = OID_UNKNOWN;
	int enc_alg    = OID_UNKNOWN;
	int signerInfos = 0;
	int objectID;
	bool success = FALSE;

	contentInfo_t cInfo = empty_contentInfo;
	chunk_t encrypted_digest = chunk_empty;

	if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	{
		return FALSE;
	}
	if (cInfo.type != OID_PKCS7_SIGNED_DATA)
	{
		DBG1("pkcs7 content type is not signedData");
		return FALSE;
	}

	parser = asn1_parser_create(signedDataObjects, blob);
	parser->set_top_level(parser, 2);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
		case PKCS7_DIGEST_ALG:
			digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case PKCS7_SIGNED_CONTENT_INFO:
			if (data != NULL)
			{
				pkcs7_parse_contentInfo(object, level, data);
			}
			break;
		case PKCS7_SIGNED_CERT:
			if (cert != NULL)
			{
				chunk_t cert_blob = chunk_clone(object);
				x509cert_t *newcert = malloc_thing(x509cert_t);

				*newcert = empty_x509cert;

				DBG2("  parsing pkcs7-wrapped certificate");
				if (parse_x509cert(cert_blob, level+1, newcert))
				{
					newcert->next = *cert;
					*cert = newcert;
				}
				else
				{
					free_x509cert(newcert);
				}
			}
			break;
		case PKCS7_SIGNER_INFO:
			signerInfos++;
			DBG2("  signer #%d", signerInfos);
			break;      
		case PKCS7_SIGNED_ISSUER:
			dntoa(buf, BUF_LEN, object);
			DBG2("  '%s'",buf);
			break;
		case PKCS7_AUTH_ATTRIBUTES:
			if (attributes != NULL)
			{
				*attributes = object;
				*attributes->ptr = ASN1_SET;
			}
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
	parser->destroy(parser);
	if (!success)
	{
		return FALSE;
	}

	/* check the signature only if a cacert is available */
	if (cacert != NULL)
	{
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
		if (attributes->ptr == NULL)
		{
			DBG1("no authenticatedAttributes object found");
			return FALSE;
		}
		if (!check_signature(*attributes, encrypted_digest, digest_alg,
							 enc_alg, cacert))
		{
			DBG1("invalid signature");
			return FALSE;
		}
		else
		{
			DBG2("signature is valid");
		}
	}
	return TRUE;
}

/**
 * Parse a PKCS#7 envelopedData object
 */
bool pkcs7_parse_envelopedData(chunk_t blob, chunk_t *data,
							   chunk_t serialNumber,
							   const RSA_private_key_t *key)
{
	asn1_parser_t *parser;
	chunk_t object;
	chunk_t iv                = chunk_empty;
	chunk_t symmetric_key     = chunk_empty;
	chunk_t encrypted_content = chunk_empty;

	crypter_t *crypter = NULL;

	u_char buf[BUF_LEN];
	int enc_alg         = OID_UNKNOWN;
	int content_enc_alg = OID_UNKNOWN;
	int objectID;
	bool success = FALSE;

	contentInfo_t cInfo = empty_contentInfo;
	*data = chunk_empty;

	if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	{
		goto failed;
	}
	if (cInfo.type != OID_PKCS7_ENVELOPED_DATA)
	{
		DBG1("pkcs7 content type is not envelopedData");
		goto failed;
	}

	parser = asn1_parser_create(envelopedDataObjects, cInfo.content);
	parser->set_top_level(parser, 2);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

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
				plog("recipient info version is not 0");
				goto end;
			}
			break;
		case PKCS7_ISSUER:
			dntoa(buf, BUF_LEN, object);
			DBG2("  '%s'", buf);
			break;      
		case PKCS7_SERIAL_NUMBER:
			if (!chunk_equals(serialNumber, object))
			{
				DBG1("serial numbers do not match");
				goto end;
			}   
			break;      
		case PKCS7_ENCRYPTION_ALG:
			enc_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			if (enc_alg != OID_RSA_ENCRYPTION)
			{
				DBG1("only rsa encryption supported");
				goto end;
			} 
			break;
		case PKCS7_ENCRYPTED_KEY:
			if (!RSA_decrypt(key, object, &symmetric_key))
			{
				DBG1("symmetric key could not be decrypted with rsa");
				goto end;
			}
			DBG4("symmetric key %B", &symmetric_key);
			break;
		case PKCS7_CONTENT_TYPE:
			if (asn1_known_oid(object) != OID_PKCS7_DATA)
			{
				 DBG1("encrypted content not of type pkcs7 data");
				 goto end;
			}
			break;
		case PKCS7_CONTENT_ENC_ALGORITHM:
			content_enc_alg = asn1_parse_algorithmIdentifier(object, level, &iv);
	
			if (content_enc_alg == OID_UNKNOWN)
			{
				DBG1("unknown content encryption algorithm");
				goto end;
			}
			if (!asn1_parse_simple_object(&iv, ASN1_OCTET_STRING, level+1, "IV"))
			{
				DBG1("IV could not be parsed");
				goto end;
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
	success = FALSE;

	/* decrypt the content */
	{
		encryption_algorithm_t alg;
		size_t key_size;
		crypter_t *crypter;

		alg = encryption_algorithm_from_oid(content_enc_alg, &key_size);
		if (alg == ENCR_UNDEFINED)
		{
			DBG1("unsupported content encryption algorithm");
			goto failed;
		}
		crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size);
		if (crypter == NULL)
		{
			DBG1("crypter %N not available", encryption_algorithm_names, alg);
			goto failed;
		}
		if (symmetric_key.len != crypter->get_key_size(crypter))
		{
			DBG1("symmetric key length %d is wrong", symmetric_key.len);
			goto failed;
		}
		if (iv.len != crypter->get_block_size(crypter))
		{
			DBG1("IV length %d is wrong", iv.len);
			goto failed;
		}
		crypter->set_key(crypter, symmetric_key);
		crypter->decrypt(crypter, encrypted_content, iv, data);
		DBG4("decrypted content with padding: %B", data);
	}

	/* remove the padding */
	{
		u_char *pos = data->ptr + data->len - 1;
		u_char pattern = *pos;
		size_t padding = pattern;

		if (padding > data->len)
		{
			DBG1("padding greater than data length");
			goto failed;
		}
		data->len -= padding;

		while (padding-- > 0)
		{
			if (*pos-- != pattern)
			{
				DBG1("wrong padding pattern");
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
		free(data->ptr);
	}
	return success;
}

/**
 * @brief Builds a contentType attribute
 *
 * @return ASN.1 encoded contentType attribute
 */
chunk_t pkcs7_contentType_attribute(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_contentType_oid
				, asn1_simple_object(ASN1_SET, ASN1_pkcs7_data_oid));
}

/**
 * @brief Builds a messageDigest attribute
 * 
 * 
 * @param[in] blob content to create digest of
 * @param[in] digest_alg digest algorithm to be used
 * @return ASN.1 encoded messageDigest attribute
 * 
 */
chunk_t pkcs7_messageDigest_attribute(chunk_t content, int digest_alg)
{
	u_char digest_buf[MAX_DIGEST_LEN];
	chunk_t digest = { digest_buf, MAX_DIGEST_LEN };

	compute_digest(content, digest_alg, &digest);

	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_messageDigest_oid
				, asn1_wrap(ASN1_SET, "m"
					, asn1_simple_object(ASN1_OCTET_STRING, digest)
				  )
		   );
}

/**
 * build a DER-encoded contentInfo object
 */
static chunk_t pkcs7_build_contentInfo(contentInfo_t *cInfo)
{
	chunk_t content_type;

	/* select DER-encoded OID for pkcs7 contentInfo type */
	switch(cInfo->type)
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

	return (cInfo->content.ptr == NULL)
		? asn1_simple_object(ASN1_SEQUENCE, content_type)
		: asn1_wrap(ASN1_SEQUENCE, "cm"
			, content_type
			, asn1_simple_object(ASN1_CONTEXT_C_0, cInfo->content)
		  );
}

/**
 * build issuerAndSerialNumber object
 */
chunk_t pkcs7_build_issuerAndSerialNumber(const x509cert_t *cert)
{
	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, cert->issuer
				, asn1_simple_object(ASN1_INTEGER, cert->serialNumber));
}

/**
 * create a signed pkcs7 contentInfo object
 */
chunk_t pkcs7_build_signedData(chunk_t data, chunk_t attributes,
							   const x509cert_t *cert, int digest_alg,
							   const RSA_private_key_t *key)
{
	contentInfo_t pkcs7Data, signedData;
	chunk_t authenticatedAttributes, encryptedDigest, signerInfo, cInfo;

	chunk_t digestAlgorithm = asn1_algorithmIdentifier(digest_alg);

	if (attributes.ptr != NULL)
	{
		encryptedDigest = pkcs1_build_signature(attributes, digest_alg
								, key, FALSE);
		authenticatedAttributes = chunk_clone(attributes);
		*authenticatedAttributes.ptr = ASN1_CONTEXT_C_0;
	}
	else
	{
		encryptedDigest = (data.ptr == NULL)? chunk_empty
				: pkcs1_build_signature(data, digest_alg, key, FALSE);
		authenticatedAttributes = chunk_empty;
	}

	signerInfo = asn1_wrap(ASN1_SEQUENCE, "cmcmcm"
				, ASN1_INTEGER_1
				, pkcs7_build_issuerAndSerialNumber(cert)
				, digestAlgorithm
				, authenticatedAttributes
				, asn1_algorithmIdentifier(OID_RSA_ENCRYPTION)
				, encryptedDigest);

	pkcs7Data.type    = OID_PKCS7_DATA;
	pkcs7Data.content = (data.ptr == NULL)? chunk_empty
				: asn1_simple_object(ASN1_OCTET_STRING, data);

	signedData.type = OID_PKCS7_SIGNED_DATA;
	signedData.content = asn1_wrap(ASN1_SEQUENCE, "cmmmm"
				, ASN1_INTEGER_1
				, asn1_simple_object(ASN1_SET, digestAlgorithm)
				, pkcs7_build_contentInfo(&pkcs7Data)
				, asn1_simple_object(ASN1_CONTEXT_C_0, cert->certificate)
				, asn1_wrap(ASN1_SET, "m", signerInfo));

	cInfo = pkcs7_build_contentInfo(&signedData);
	DBG3("signedData %B", &cInfo);

	free(pkcs7Data.content.ptr);
	free(signedData.content.ptr);
	return cInfo;
}

/**
 * create a symmetrically encrypted pkcs7 contentInfo object
 */
chunk_t pkcs7_build_envelopedData(chunk_t data, const x509cert_t *cert, int enc_alg)
{
	encryption_algorithm_t alg;
	size_t alg_key_size;
	RSA_public_key_t public_key;
	chunk_t symmetricKey, iv, in, out;
	crypter_t *crypter;

	alg = encryption_algorithm_from_oid(enc_alg, &alg_key_size);
	crypter = lib->crypto->create_crypter(lib->crypto, alg,
										  alg_key_size/BITS_PER_BYTE);
	if (crypter == NULL)
	{
		DBG1("crypter for %N not available", encryption_algorithm_names, alg);
		return chunk_empty;
	}

	/* generate a true random symmetric encryption key and a pseudo-random iv */
	{
		rng_t *rng;
		
		rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
		rng->allocate_bytes(rng, crypter->get_key_size(crypter), &symmetricKey);
		DBG4("symmetric encryption key %B", &symmetricKey);
		rng->destroy(rng);

		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		rng->allocate_bytes(rng, crypter->get_block_size(crypter), &iv);
		DBG4("initialization vector: %B", &iv);
		rng->destroy(rng);
	}

	/* pad the data to a multiple of the block size */
	{
		size_t block_size = crypter->get_block_size(crypter);
		size_t padding = block_size - data.len % block_size;

		in.len = data.len + padding;
		in.ptr = malloc(in.len);

		DBG2("padding %u bytes of data to multiple block size of %u bytes",
		 	 data.len, in.len);

		/* copy data */
		memcpy(in.ptr, data.ptr, data.len);
		/* append padding */
		memset(in.ptr + data.len, padding, padding);
	}
	DBG3("padded unencrypted data %B", &in);

	/* symmetric encryption of data object */
	crypter->set_key(crypter, symmetricKey);
	crypter->encrypt(crypter, in, iv, &out);
	crypter->destroy(crypter);
    DBG3("encrypted data %B", &out);
	free(in.ptr);
	free(iv.ptr);

	init_RSA_public_key(&public_key, cert->publicExponent, cert->modulus);
	
	/* build pkcs7 enveloped data object */ 
	{
		chunk_t contentEncryptionAlgorithm = asn1_wrap(ASN1_SEQUENCE, "mm"
					, asn1_build_known_oid(enc_alg)
					, asn1_simple_object(ASN1_OCTET_STRING, iv));
		
		chunk_t encryptedContentInfo = asn1_wrap(ASN1_SEQUENCE, "cmm"
					, ASN1_pkcs7_data_oid
					, contentEncryptionAlgorithm
					, asn1_wrap(ASN1_CONTEXT_S_0, "m", out));

		chunk_t encryptedKey = asn1_wrap(ASN1_OCTET_STRING, "m"
					, RSA_encrypt(&public_key, symmetricKey));

		chunk_t recipientInfo = asn1_wrap(ASN1_SEQUENCE, "cmcm"
					, ASN1_INTEGER_0
					, pkcs7_build_issuerAndSerialNumber(cert)
					, asn1_algorithmIdentifier(OID_RSA_ENCRYPTION)
					, encryptedKey);

		chunk_t cInfo;
		contentInfo_t envelopedData;

		envelopedData.type = OID_PKCS7_ENVELOPED_DATA;
		envelopedData.content = asn1_wrap(ASN1_SEQUENCE, "cmm"
					, ASN1_INTEGER_0
					, asn1_wrap(ASN1_SET, "m", recipientInfo)
					, encryptedContentInfo);

		cInfo = pkcs7_build_contentInfo(&envelopedData);
		DBG3("envelopedData %B", &cInfo);

		free_RSA_public_content(&public_key);
		free(envelopedData.content.ptr);
		free(symmetricKey.ptr);
		return cInfo;
	}
}
