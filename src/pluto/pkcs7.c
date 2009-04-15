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
 *
 * RCSID $Id$
 */

#include <stdlib.h>
#include <string.h>
#include <libdes/des.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "asn1.h"
#include <asn1/oid.h>
#include "log.h"
#include "x509.h"
#include "certs.h"
#include "pkcs7.h"
#include "rnd.h"

const contentInfo_t empty_contentInfo = {
    OID_UNKNOWN , /* type */
    { NULL, 0 }   /* content */
};

/* ASN.1 definition of the PKCS#7 ContentInfo type */

static const asn1Object_t contentInfoObjects[] = {
  { 0, "contentInfo",			ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "contentType",			ASN1_OID,          ASN1_BODY }, /*  1 */
  { 1,   "content",			ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 1,   "end opt",			ASN1_EOC,	   ASN1_END  }  /*  3 */
};

#define PKCS7_INFO_TYPE		1
#define PKCS7_INFO_CONTENT	2
#define PKCS7_INFO_ROOF		4

/* ASN.1 definition of the PKCS#7 signedData type */

static const asn1Object_t signedDataObjects[] = {
  { 0, "signedData",			  ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "version",			  ASN1_INTEGER,      ASN1_BODY }, /*  1 */
  { 1,   "digestAlgorithms",		  ASN1_SET,          ASN1_LOOP }, /*  2 */
  { 2,     "algorithm",			  ASN1_EOC,          ASN1_RAW  }, /*  3 */
  { 1,   "end loop",			  ASN1_EOC,          ASN1_END  }, /*  4 */
  { 1,   "contentInfo",			  ASN1_EOC,          ASN1_RAW  }, /*  5 */
  { 1,   "certificates",		  ASN1_CONTEXT_C_0,  ASN1_OPT |
							     ASN1_LOOP }, /*  6 */
  { 2,      "certificate",		  ASN1_SEQUENCE,     ASN1_OBJ  }, /*  7 */
  { 1,   "end opt or loop",		  ASN1_EOC,	     ASN1_END  }, /*  8 */
  { 1,   "crls",			  ASN1_CONTEXT_C_1,  ASN1_OPT |
							     ASN1_LOOP }, /*  9 */
  { 2,	    "crl",			  ASN1_SEQUENCE,     ASN1_OBJ  }, /* 10 */
  { 1,   "end opt or loop",		  ASN1_EOC,	     ASN1_END  }, /* 11 */
  { 1,   "signerInfos",			  ASN1_SET,	     ASN1_LOOP }, /* 12 */
  { 2,     "signerInfo",		  ASN1_SEQUENCE,     ASN1_NONE }, /* 13 */
  { 3,       "version",			  ASN1_INTEGER,	     ASN1_BODY }, /* 14 */
  { 3,       "issuerAndSerialNumber",	  ASN1_SEQUENCE,     ASN1_BODY }, /* 15 */
  { 4,         "issuer",	          ASN1_SEQUENCE,     ASN1_OBJ  }, /* 16 */
  { 4,         "serial",	          ASN1_INTEGER,	     ASN1_BODY }, /* 17 */
  { 3,       "digestAlgorithm",		  ASN1_EOC,	     ASN1_RAW  }, /* 18 */
  { 3,       "authenticatedAttributes",	  ASN1_CONTEXT_C_0,  ASN1_OPT |
							     ASN1_OBJ  }, /* 19 */
  { 3,       "end opt",			  ASN1_EOC,	     ASN1_END  }, /* 20 */
  { 3,       "digestEncryptionAlgorithm", ASN1_EOC,	     ASN1_RAW  }, /* 21 */
  { 3,       "encryptedDigest",		  ASN1_OCTET_STRING, ASN1_BODY }, /* 22 */
  { 3,       "unauthenticatedAttributes", ASN1_CONTEXT_C_1,  ASN1_OPT  }, /* 23 */
  { 3,       "end opt",			  ASN1_EOC,	     ASN1_END  }, /* 24 */
  { 1,   "end loop",			  ASN1_EOC,	     ASN1_END  }  /* 25 */
};

#define PKCS7_DIGEST_ALG	 	 3
#define PKCS7_SIGNED_CONTENT_INFO	 5
#define PKCS7_SIGNED_CERT	 	 7
#define PKCS7_SIGNER_INFO		13
#define PKCS7_SIGNED_ISSUER		16
#define PKCS7_SIGNED_SERIAL_NUMBER	17
#define PKCS7_DIGEST_ALGORITHM		18
#define PKCS7_AUTH_ATTRIBUTES		19
#define PKCS7_DIGEST_ENC_ALGORITHM	21
#define PKCS7_ENCRYPTED_DIGEST		22
#define PKCS7_SIGNED_ROOF		26

/* ASN.1 definition of the PKCS#7 envelopedData type */

static const asn1Object_t envelopedDataObjects[] = {
  { 0, "envelopedData",				ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
  { 1,   "version",				ASN1_INTEGER, 		ASN1_BODY }, /*  1 */
  { 1,   "recipientInfos",			ASN1_SET,    		ASN1_LOOP }, /*  2 */
  { 2,     "recipientInfo",			ASN1_SEQUENCE, 		ASN1_BODY }, /*  3 */
  { 3,       "version",				ASN1_INTEGER, 		ASN1_BODY }, /*  4 */
  { 3,       "issuerAndSerialNumber",	        ASN1_SEQUENCE,		ASN1_BODY }, /*  5 */
  { 4,         "issuer",	        	ASN1_SEQUENCE,		ASN1_OBJ  }, /*  6 */
  { 4,         "serial",	        	ASN1_INTEGER,		ASN1_BODY }, /*  7 */
  { 3,       "encryptionAlgorithm",	       	ASN1_EOC,		ASN1_RAW  }, /*  8 */
  { 3,       "encryptedKey",		       	ASN1_OCTET_STRING,	ASN1_BODY }, /*  9 */
  { 1,   "end loop",				ASN1_EOC,		ASN1_END  }, /* 10 */
  { 1,   "encryptedContentInfo",		ASN1_SEQUENCE,		ASN1_OBJ  }, /* 11 */
  { 2,     "contentType",			ASN1_OID,		ASN1_BODY }, /* 12 */
  { 2,     "contentEncryptionAlgorithm",	ASN1_EOC,		ASN1_RAW  }, /* 13 */
  { 2,     "encryptedContent",			ASN1_CONTEXT_S_0, 	ASN1_BODY }  /* 14 */
};

#define PKCS7_ENVELOPED_VERSION		 1
#define PKCS7_RECIPIENT_INFO_VERSION	 4
#define PKCS7_ISSUER			 6
#define PKCS7_SERIAL_NUMBER		 7
#define PKCS7_ENCRYPTION_ALG		 8
#define PKCS7_ENCRYPTED_KEY		 9
#define PKCS7_CONTENT_TYPE		12
#define PKCS7_CONTENT_ENC_ALGORITHM	13
#define PKCS7_ENCRYPTED_CONTENT		14
#define PKCS7_ENVELOPED_ROOF		15

/* PKCS7 contentInfo OIDs */

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
			strchunk(ASN1_pkcs7_data_oid_str);
static const chunk_t ASN1_pkcs7_signed_data_oid =
			strchunk(ASN1_pkcs7_signed_data_oid_str);
static const chunk_t ASN1_pkcs7_enveloped_data_oid =
			strchunk(ASN1_pkcs7_enveloped_data_oid_str);
static const chunk_t ASN1_pkcs7_signed_enveloped_data_oid = 
			strchunk(ASN1_pkcs7_signed_enveloped_data_oid_str);
static const chunk_t ASN1_pkcs7_digested_data_oid =
			strchunk(ASN1_pkcs7_digested_data_oid_str);
static const chunk_t ASN1_pkcs7_encrypted_data_oid =
			strchunk(ASN1_pkcs7_encrypted_data_oid_str);

/* 3DES and DES encryption OIDs */

static u_char ASN1_3des_ede_cbc_oid_str[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07
};

static u_char ASN1_des_cbc_oid_str[] = {
    0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x07
};

static const chunk_t ASN1_3des_ede_cbc_oid = 
			strchunk(ASN1_3des_ede_cbc_oid_str);
static const chunk_t ASN1_des_cbc_oid =
			strchunk(ASN1_des_cbc_oid_str);

/* PKCS#7 attribute type OIDs */

static u_char ASN1_contentType_oid_str[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03
};

static u_char ASN1_messageDigest_oid_str[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04
};

static const chunk_t ASN1_contentType_oid =
			strchunk(ASN1_contentType_oid_str);
static const chunk_t ASN1_messageDigest_oid =
			strchunk(ASN1_messageDigest_oid_str);

/*
 * Parse PKCS#7 ContentInfo object
 */
bool
pkcs7_parse_contentInfo(chunk_t blob, u_int level0, contentInfo_t *cInfo)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < PKCS7_INFO_ROOF)
    {
	if (!extract_object(contentInfoObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	if (objectID == PKCS7_INFO_TYPE)
	{
	    cInfo->type = asn1_known_oid(object);
	    if (cInfo->type < OID_PKCS7_DATA
	    ||  cInfo->type > OID_PKCS7_ENCRYPTED_DATA)
	    {
		plog("unknown pkcs7 content type");
		return FALSE;
	    }
	}
	else if (objectID == PKCS7_INFO_CONTENT)
	{
	    cInfo->content = object;
	}
	objectID++;
    }
    return TRUE;
}

/*
 * Parse a PKCS#7 signedData object
 */
bool
pkcs7_parse_signedData(chunk_t blob, contentInfo_t *data, x509cert_t **cert
, chunk_t *attributes, const x509cert_t *cacert)
{
    u_char buf[BUF_LEN];
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int digest_alg = OID_UNKNOWN;
    int enc_alg    = OID_UNKNOWN;
    int signerInfos = 0;
    int objectID = 0;

    contentInfo_t cInfo = empty_contentInfo;
    chunk_t encrypted_digest = empty_chunk;

    if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	return FALSE;

    if (cInfo.type != OID_PKCS7_SIGNED_DATA)
    {
	plog("pkcs7 content type is not signedData");
	return FALSE;
    }

    asn1_init(&ctx, cInfo.content, 2, FALSE, DBG_RAW);

    while (objectID < PKCS7_SIGNED_ROOF)
   {
	if (!extract_object(signedDataObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	switch (objectID)
	{
	case PKCS7_DIGEST_ALG:
	    digest_alg = parse_algorithmIdentifier(object, level, NULL);
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
		chunk_t cert_blob;

		x509cert_t *newcert = alloc_thing(x509cert_t
					, "pkcs7 wrapped x509cert");

		clonetochunk(cert_blob, object.ptr, object.len
			    , "pkcs7 cert blob");
		*newcert = empty_x509cert;

		DBG(DBG_CONTROL | DBG_PARSING,
		    DBG_log("parsing pkcs7-wrapped certificate")
		)
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
	    DBG(DBG_PARSING,
		DBG_log("  signer #%d", signerInfos)
	    )
	    break;	
	case PKCS7_SIGNED_ISSUER:
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'",buf)
	    )
	    break;
	case PKCS7_AUTH_ATTRIBUTES:
	    if (attributes != NULL)
	    {
		*attributes = object;
		*attributes->ptr = ASN1_SET;
	    }
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
	objectID++;
    }

    /* check the signature only if a cacert is available */
    if (cacert != NULL)
    {
	if (signerInfos == 0)
	{
	    plog("no signerInfo object found");
	    return FALSE;
	}
	else if (signerInfos > 1)
	{
	    plog("more than one signerInfo object found");
	    return FALSE;
	}
	if (attributes->ptr == NULL)
	{
	    plog("no authenticatedAttributes object found");
	    return FALSE;
	}
	if (!check_signature(*attributes, encrypted_digest, digest_alg
	   , enc_alg, cacert))
	{
	    plog("invalid signature");
	    return FALSE;
	}
	else
	{
	    DBG(DBG_CONTROL,
		DBG_log("signature is valid")
	    )
	}
    }
    return TRUE;
}

/*
 * Parse a PKCS#7 envelopedData object
 */
bool
pkcs7_parse_envelopedData(chunk_t blob, chunk_t *data
, chunk_t serialNumber, const RSA_private_key_t *key)
{
    asn1_ctx_t ctx;
    chunk_t object;
    chunk_t iv                = empty_chunk;
    chunk_t symmetric_key     = empty_chunk;
    chunk_t encrypted_content = empty_chunk;

    u_char buf[BUF_LEN];
    u_int level;
    u_int total_keys = 3;
    int enc_alg         = OID_UNKNOWN;
    int content_enc_alg = OID_UNKNOWN;
    int objectID = 0;

    contentInfo_t cInfo = empty_contentInfo;
    *data = empty_chunk;

    if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	goto failed;

    if (cInfo.type != OID_PKCS7_ENVELOPED_DATA)
    {
	plog("pkcs7 content type is not envelopedData");
	return FALSE;
    }

    asn1_init(&ctx, cInfo.content, 2, FALSE, DBG_RAW);

    while (objectID < PKCS7_ENVELOPED_ROOF)
    {
	if (!extract_object(envelopedDataObjects, &objectID, &object, &level, &ctx))
	     goto failed;

	switch (objectID)
	{
	case PKCS7_ENVELOPED_VERSION:
	if (*object.ptr != 0)
	{
	    plog("envelopedData version is not 0");
	    goto failed;
	}
	break;
	case PKCS7_RECIPIENT_INFO_VERSION:
	    if (*object.ptr != 0)
	    {
		plog("recipient info version is not 0");
		goto failed;
	    }
	    break;
	case PKCS7_ISSUER:
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'", buf)
	    )
	    break;	
	case PKCS7_SERIAL_NUMBER:
	    if (!same_chunk(serialNumber, object))
	    {
		plog("serial numbers do not match");
		goto failed;
	    }	
	    break;	
	case PKCS7_ENCRYPTION_ALG:
	    enc_alg = parse_algorithmIdentifier(object, level, NULL);
	    if (enc_alg != OID_RSA_ENCRYPTION)
	    {
		plog("only rsa encryption supported");
		goto failed;
	    } 
	    break;
	case PKCS7_ENCRYPTED_KEY:
	    if (!RSA_decrypt(key, object, &symmetric_key))
	    {
		plog("symmetric key could not be decrypted with rsa");
		goto failed;
	    }
	    DBG(DBG_PRIVATE,
		DBG_dump_chunk("symmetric key :", symmetric_key)
	    )
	    break;
	case PKCS7_CONTENT_TYPE:
	    if (asn1_known_oid(object) != OID_PKCS7_DATA)
	    {
		 plog("encrypted content not of type pkcs7 data");
		 goto failed;
	    }
	    break;
	case PKCS7_CONTENT_ENC_ALGORITHM:
	    content_enc_alg = parse_algorithmIdentifier(object, level, &iv);

	    switch (content_enc_alg)
	    {
	    case OID_DES_CBC:
		total_keys = 1;
		break;
	    case OID_3DES_EDE_CBC:
		total_keys = 3;
		break;
	    default:
		plog("Only DES and 3DES supported for symmetric encryption");
		goto failed;
	    }
	    if (symmetric_key.len != (total_keys * DES_CBC_BLOCK_SIZE))
	    {
		plog("key length is not %d",(total_keys * DES_CBC_BLOCK_SIZE));
		goto failed;
	    }
	    if (!parse_asn1_simple_object(&iv, ASN1_OCTET_STRING, level+1, "IV"))
	    {
		plog("IV could not be parsed");
		goto failed;
	    }
	    if (iv.len != DES_CBC_BLOCK_SIZE)
	    {
		plog("IV has wrong length");
		goto failed;
	    }
	    break;
	case PKCS7_ENCRYPTED_CONTENT:
	    encrypted_content = object;
	    break;
	}
	objectID++;
    }

    /* decrypt the content */
    {
	u_int i;
	des_cblock des_key[3], des_iv;
	des_key_schedule key_s[3];

	memcpy((char *)des_key, symmetric_key.ptr, symmetric_key.len);
	memcpy((char *)des_iv, iv.ptr, iv.len);

	for (i = 0; i < total_keys; i++)
	{
	    if (des_set_key(&des_key[i], key_s[i]))
	    {
		plog("des key schedule failed");
		goto failed;
	    }
	}

	data->len = encrypted_content.len;
	data->ptr = alloc_bytes(data->len, "decrypted data");

	switch (content_enc_alg)
	{
	case OID_DES_CBC:
	    des_cbc_encrypt((des_cblock*)encrypted_content.ptr
			  , (des_cblock*)data->ptr, data->len
			  , key_s[0], &des_iv, DES_DECRYPT);
	    break;
	case OID_3DES_EDE_CBC:
	    des_ede3_cbc_encrypt( (des_cblock*)encrypted_content.ptr
				, (des_cblock*)data->ptr, data->len
				, key_s[0], key_s[1], key_s[2]
				, &des_iv, DES_DECRYPT);
	}
	DBG(DBG_PRIVATE,
	    DBG_dump_chunk("decrypted content with padding:\n", *data)
	)
    }
 
    /* remove the padding */
    {
	u_char *pos = data->ptr + data->len - 1;
	u_char pattern = *pos;
	size_t padding = pattern;

	if (padding > data->len)
	{
	    plog("padding greater than data length");
	    goto failed;
	}
	data->len -= padding;

	while (padding-- > 0)
	{
	    if (*pos-- != pattern)
	    {
		plog("wrong padding pattern");
		goto failed;
	    }
	}
    }
    freeanychunk(symmetric_key);
    return TRUE;

failed:
    freeanychunk(symmetric_key);
    pfreeany(data->ptr);
    return FALSE;
}

/**
 * @brief Builds a contentType attribute
 *
 * @return ASN.1 encoded contentType attribute
 */
chunk_t
pkcs7_contentType_attribute(void)
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
chunk_t
pkcs7_messageDigest_attribute(chunk_t content, int digest_alg)
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
/*
 * build a DER-encoded contentInfo object
 */
static chunk_t
pkcs7_build_contentInfo(contentInfo_t *cInfo)
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
	fprintf(stderr, "invalid pkcs7 contentInfo type");
	return empty_chunk;
    }

    return (cInfo->content.ptr == NULL)
	? asn1_simple_object(ASN1_SEQUENCE, content_type)
	: asn1_wrap(ASN1_SEQUENCE, "cm"
	    , content_type
	    , asn1_simple_object(ASN1_CONTEXT_C_0, cInfo->content)
          );
}

/*
 * build issuerAndSerialNumber object
 */
chunk_t
pkcs7_build_issuerAndSerialNumber(const x509cert_t *cert)
{
    return asn1_wrap(ASN1_SEQUENCE, "cm"
		, cert->issuer
		, asn1_simple_object(ASN1_INTEGER, cert->serialNumber));
}

/*
 * create a signed pkcs7 contentInfo object
 */
chunk_t
pkcs7_build_signedData(chunk_t data, chunk_t attributes, const x509cert_t *cert
, int digest_alg, const RSA_private_key_t *key)
{
    contentInfo_t pkcs7Data, signedData;
    chunk_t authenticatedAttributes, encryptedDigest, signerInfo, cInfo;

    chunk_t digestAlgorithm = asn1_algorithmIdentifier(digest_alg);

    if (attributes.ptr != NULL)
    {
	encryptedDigest = pkcs1_build_signature(attributes, digest_alg
				, key, FALSE);
	clonetochunk(authenticatedAttributes, attributes.ptr, attributes.len
	    , "authenticatedAttributes");
	*authenticatedAttributes.ptr = ASN1_CONTEXT_C_0;
    }
    else
    {
	encryptedDigest = (data.ptr == NULL)? empty_chunk
		: pkcs1_build_signature(data, digest_alg, key, FALSE);
	authenticatedAttributes = empty_chunk;
    }

    signerInfo = asn1_wrap(ASN1_SEQUENCE, "cmcmcm"
		, ASN1_INTEGER_1
		, pkcs7_build_issuerAndSerialNumber(cert)
		, digestAlgorithm
		, authenticatedAttributes
		, ASN1_rsaEncryption_id
		, encryptedDigest);

    pkcs7Data.type    = OID_PKCS7_DATA;
    pkcs7Data.content = (data.ptr == NULL)? empty_chunk
		: asn1_simple_object(ASN1_OCTET_STRING, data);

    signedData.type = OID_PKCS7_SIGNED_DATA;
    signedData.content = asn1_wrap(ASN1_SEQUENCE, "cmmmm"
		, ASN1_INTEGER_1
		, asn1_simple_object(ASN1_SET, digestAlgorithm)
		, pkcs7_build_contentInfo(&pkcs7Data)
		, asn1_simple_object(ASN1_CONTEXT_C_0, cert->certificate)
		, asn1_wrap(ASN1_SET, "m", signerInfo));

    cInfo = pkcs7_build_contentInfo(&signedData);
    DBG(DBG_RAW,
	DBG_dump_chunk("signedData:\n", cInfo)
    )

    freeanychunk(pkcs7Data.content);
    freeanychunk(signedData.content);
    return cInfo;
}

/*
 * create a symmetrically encrypted pkcs7 contentInfo object
 */
chunk_t
pkcs7_build_envelopedData(chunk_t data, const x509cert_t *cert, int cipher)
{
    bool des_check_key_save;
    des_key_schedule ks[3];
    des_cblock key[3], des_iv, des_iv_buf;

    chunk_t iv = { (u_char *)des_iv_buf, DES_CBC_BLOCK_SIZE };
    chunk_t out;
    chunk_t cipher_oid;

    u_int total_keys, i;
    size_t padding = pad_up(data.len, DES_CBC_BLOCK_SIZE);

    RSA_public_key_t public_key;

    init_RSA_public_key(&public_key, cert->publicExponent
				   , cert->modulus);

    if (padding == 0)
	padding += DES_CBC_BLOCK_SIZE;

    out.len = data.len + padding;
    out.ptr = alloc_bytes(out.len, "DES-encrypted output");

    DBG(DBG_CONTROL,
	DBG_log("padding %d bytes of data to multiple DES block size of %d bytes"
		, (int)data.len, (int)out.len)
    )

    /* copy data */
    memcpy(out.ptr, data.ptr, data.len);
    /* append padding */
    memset(out.ptr + data.len, padding, padding);

    DBG(DBG_RAW,
	DBG_dump_chunk("Padded unencrypted data:\n", out)
    )

    /* select OID and keylength for specified cipher */
    switch (cipher)
    {
    case OID_DES_CBC:
	 total_keys = 1;
	 cipher_oid = ASN1_des_cbc_oid;
	 break;
    case OID_3DES_EDE_CBC:
    default:
	total_keys = 3;
	cipher_oid = ASN1_3des_ede_cbc_oid;
    }
    DBG(DBG_CONTROLMORE,
	DBG_log("pkcs7 encryption cipher: %s", oid_names[cipher].name)
    )

    /* generate a strong random key for DES/3DES */
    des_check_key_save = des_check_key;
    des_check_key = TRUE;
    for (i = 0; i < total_keys;i++)
    {
	for (;;)
	{
	    get_rnd_bytes((char*)key[i], DES_CBC_BLOCK_SIZE);
	    des_set_odd_parity(&key[i]);
	    if (!des_set_key(&key[i], ks[i]))
		break;
	    plog("weak DES key discarded - we try again");
	}
	DBG(DBG_PRIVATE,
	    DBG_dump("DES key:", key[i], 8)
	)
    }
    des_check_key = des_check_key_save;

    /* generate an iv for DES/3DES CBC */
    get_rnd_bytes(des_iv, DES_CBC_BLOCK_SIZE);
    memcpy(iv.ptr, des_iv, DES_CBC_BLOCK_SIZE);
    DBG(DBG_RAW,
	DBG_dump_chunk("DES IV :", iv)
    )

    /* encryption using specified cipher */
    switch (cipher)
    {
    case OID_DES_CBC:
	des_cbc_encrypt((des_cblock*)out.ptr, (des_cblock*)out.ptr, out.len
		       , ks[0], &des_iv, DES_ENCRYPT);
	break;
    case OID_3DES_EDE_CBC:
    default:
	des_ede3_cbc_encrypt((des_cblock*)out.ptr, (des_cblock*)out.ptr, out.len
			    , ks[0], ks[1], ks[2], &des_iv, DES_ENCRYPT);	
    }
    DBG(DBG_RAW,
	DBG_dump_chunk("Encrypted data:\n", out));
	
    /* build pkcs7 enveloped data object */ 
    {
	chunk_t contentEncryptionAlgorithm = asn1_wrap(ASN1_SEQUENCE, "cm"
		    , cipher_oid
		    , asn1_simple_object(ASN1_OCTET_STRING, iv));
	
	chunk_t encryptedContentInfo = asn1_wrap(ASN1_SEQUENCE, "cmm"
		    , ASN1_pkcs7_data_oid
		    , contentEncryptionAlgorithm
		    , asn1_wrap(ASN1_CONTEXT_S_0, "m", out));

        chunk_t plainKey = { (u_char *)key, DES_CBC_BLOCK_SIZE * total_keys };

	chunk_t encryptedKey = asn1_wrap(ASN1_OCTET_STRING, "m"
		    , RSA_encrypt(&public_key, plainKey));

	chunk_t recipientInfo = asn1_wrap(ASN1_SEQUENCE, "cmcm"
		    , ASN1_INTEGER_0
		    , pkcs7_build_issuerAndSerialNumber(cert)
		    , ASN1_rsaEncryption_id
		    , encryptedKey);

        chunk_t cInfo;
	contentInfo_t envelopedData;

        envelopedData.type = OID_PKCS7_ENVELOPED_DATA;
	envelopedData.content = asn1_wrap(ASN1_SEQUENCE, "cmm"
		    , ASN1_INTEGER_0
		    , asn1_wrap(ASN1_SET, "m", recipientInfo)
		    , encryptedContentInfo);

	cInfo = pkcs7_build_contentInfo(&envelopedData);
	DBG(DBG_RAW,
	    DBG_dump_chunk("envelopedData:\n", cInfo)
	)

	free_RSA_public_content(&public_key);
	freeanychunk(envelopedData.content);
	return cInfo;
    }
}
