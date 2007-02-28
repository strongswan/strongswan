/**
 * @file ocsp.c
 * 
 * @brief Implementation of ocsp_t.
 * 
 */

/* Support of the Online Certificate Status Protocol (OCSP)
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Zuercher Hochschule Winterthur
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
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>

#include "certinfo.h"
#include "x509.h"
#include "ocsp.h"

#define NONCE_LENGTH		16

static const char *const response_status_names[] = {
    "successful",
    "malformed request",
    "internal error",
    "try later",
    "signature required",
    "unauthorized"
};

/* response container */
typedef struct response_t response_t;

struct response_t {
    chunk_t  tbs;
    chunk_t  responder_id_name;
    chunk_t  responder_id_key;
    time_t   produced_at;
    chunk_t  responses;
    chunk_t  nonce;
    int      algorithm;
    chunk_t  signature;
};

const response_t empty_response = {
    { NULL, 0 }   ,	/* tbs */
    { NULL, 0 }   ,	/* responder_id_name */
    { NULL, 0 }   ,	/* responder_id_key */
    UNDEFINED_TIME,	/* produced_at */
    { NULL, 0 }   ,	/* single_response */
    { NULL, 0 }   ,	/* nonce */
    OID_UNKNOWN   ,	/* signature_algorithm */
    { NULL, 0 }		/* signature */
};

/* single response container */
typedef struct single_response single_response_t;

struct single_response {
    single_response_t *next;
    int               hash_algorithm;
    chunk_t           issuer_name_hash;
    chunk_t           issuer_key_hash;
    chunk_t           serialNumber;
    cert_status_t     status;
    time_t            revocationTime;
    crl_reason_t      revocationReason;
    time_t            thisUpdate;
    time_t            nextUpdate;
};

const single_response_t empty_single_response = {
      NULL            ,	/* *next */
    OID_UNKNOWN       ,	/* hash_algorithm */
    { NULL, 0 }       ,	/* issuer_name_hash */
    { NULL, 0 }       ,	/* issuer_key_hash */
    { NULL, 0 }       ,	/* serial_number */
    CERT_UNDEFINED    ,	/* status */
    UNDEFINED_TIME    ,	/* revocationTime */
    REASON_UNSPECIFIED,	/* revocationReason */
    UNDEFINED_TIME    ,	/* this_update */
    UNDEFINED_TIME	/* next_update */
};


/* list of single requests */
typedef struct request_list request_list_t;
struct request_list {
    chunk_t request;
    request_list_t *next;
};

/* some OCSP specific prefabricated ASN.1 constants */

static u_char ASN1_nonce_oid_str[] = {
	0x06, 0x09,
		  0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
};

static u_char ASN1_response_oid_str[] = {
	0x06, 0x09,
		  0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04
};

static u_char ASN1_response_content_str[] = {
	0x04, 0x0D,
		  0x30, 0x0B,
				0x06, 0x09,
				0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
};

static const chunk_t ASN1_nonce_oid = chunk_from_buf(ASN1_nonce_oid_str);
static const chunk_t ASN1_response_oid = chunk_from_buf(ASN1_response_oid_str);
static const chunk_t ASN1_response_content = chunk_from_buf(ASN1_response_content_str);

/* asn.1 definitions for parsing */

static const asn1Object_t ocspResponseObjects[] = {
	{ 0, "OCSPResponse",			ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "responseStatus",		ASN1_ENUMERATED,	ASN1_BODY }, /*  1 */
	{ 1,   "responseBytesContext",	ASN1_CONTEXT_C_0,	ASN1_OPT  }, /*  2 */
	{ 2,     "responseBytes",		ASN1_SEQUENCE,		ASN1_NONE }, /*  3 */
	{ 3,       "responseType",		ASN1_OID,			ASN1_BODY }, /*  4 */
	{ 3,       "response",			ASN1_OCTET_STRING,	ASN1_BODY }, /*  5 */
	{ 1,   "end opt",				ASN1_EOC,			ASN1_END  }  /*  6 */
};

#define OCSP_RESPONSE_STATUS	1
#define OCSP_RESPONSE_TYPE		4
#define OCSP_RESPONSE			5
#define OCSP_RESPONSE_ROOF		7

static const asn1Object_t basicResponseObjects[] = {
	{ 0, "BasicOCSPResponse",				ASN1_SEQUENCE,			ASN1_NONE }, /*  0 */
	{ 1,   "tbsResponseData",				ASN1_SEQUENCE,			ASN1_OBJ  }, /*  1 */
	{ 2,     "versionContext",				ASN1_CONTEXT_C_0,		ASN1_NONE |
																	ASN1_DEF  }, /*  2 */
	{ 3,       "version",					ASN1_INTEGER,			ASN1_BODY }, /*  3 */
	{ 2,     "responderIdContext",			ASN1_CONTEXT_C_1,		ASN1_OPT  }, /*  4 */
	{ 3,       "responderIdByName",			ASN1_SEQUENCE,			ASN1_OBJ  }, /*  5 */
	{ 2,     "end choice",					ASN1_EOC,				ASN1_END  }, /*  6 */
	{ 2,     "responderIdContext",			ASN1_CONTEXT_C_2,		ASN1_OPT  }, /*  7 */
	{ 3,       "responderIdByKey",			ASN1_OCTET_STRING,		ASN1_BODY }, /*  8 */
	{ 2,     "end choice",					ASN1_EOC,				ASN1_END  }, /*  9 */
	{ 2,     "producedAt",					ASN1_GENERALIZEDTIME,	ASN1_BODY }, /* 10 */
	{ 2,     "responses",					ASN1_SEQUENCE,			ASN1_OBJ  }, /* 11 */
	{ 2,     "responseExtensionsContext",	ASN1_CONTEXT_C_1,		ASN1_OPT  }, /* 12 */
	{ 3,       "responseExtensions",		ASN1_SEQUENCE,			ASN1_LOOP }, /* 13 */
	{ 4,         "extension",				ASN1_SEQUENCE,			ASN1_NONE }, /* 14 */
	{ 5,           "extnID",				ASN1_OID,				ASN1_BODY }, /* 15 */
	{ 5,           "critical",				ASN1_BOOLEAN,			ASN1_BODY |
																	ASN1_DEF  }, /* 16 */
	{ 5,           "extnValue",				ASN1_OCTET_STRING,		ASN1_BODY }, /* 17 */
	{ 4,         "end loop",				ASN1_EOC,				ASN1_END  }, /* 18 */
	{ 2,     "end opt",						ASN1_EOC,				ASN1_END  }, /* 19 */
	{ 1,   "signatureAlgorithm",			ASN1_EOC,				ASN1_RAW  }, /* 20 */
	{ 1,   "signature",						ASN1_BIT_STRING,		ASN1_BODY }, /* 21 */
	{ 1,   "certsContext",					ASN1_CONTEXT_C_0,		ASN1_OPT  }, /* 22 */
	{ 2,     "certs",						ASN1_SEQUENCE,			ASN1_LOOP }, /* 23 */
	{ 3,       "certificate",				ASN1_SEQUENCE,			ASN1_OBJ  }, /* 24 */
	{ 2,     "end loop",					ASN1_EOC,				ASN1_END  }, /* 25 */
	{ 1,   "end opt",						ASN1_EOC,				ASN1_END  }  /* 26 */
};

#define BASIC_RESPONSE_TBS_DATA		 1
#define BASIC_RESPONSE_VERSION		 3
#define BASIC_RESPONSE_ID_BY_NAME	 5
#define BASIC_RESPONSE_ID_BY_KEY	 8
#define BASIC_RESPONSE_PRODUCED_AT	10
#define BASIC_RESPONSE_RESPONSES	11
#define BASIC_RESPONSE_EXT_ID		15
#define BASIC_RESPONSE_CRITICAL		16
#define BASIC_RESPONSE_EXT_VALUE	17
#define BASIC_RESPONSE_ALGORITHM	20
#define BASIC_RESPONSE_SIGNATURE	21
#define BASIC_RESPONSE_CERTIFICATE	24
#define BASIC_RESPONSE_ROOF			27

static const asn1Object_t responsesObjects[] = {
	{ 0, "responses",			ASN1_SEQUENCE,	ASN1_LOOP }, /*  0 */
	{ 1,   "singleResponse",	ASN1_EOC,		ASN1_RAW  }, /*  1 */
	{ 0, "end loop",			ASN1_EOC,		ASN1_END  }  /*  2 */
};

#define RESPONSES_SINGLE_RESPONSE	1
#define RESPONSES_ROOF				3

static const asn1Object_t singleResponseObjects[] = {
	{ 0, "singleResponse",				ASN1_SEQUENCE,			ASN1_BODY }, /*  0 */
	{ 1,   "certID",					ASN1_SEQUENCE,			ASN1_NONE }, /*  1 */
	{ 2,     "algorithm",				ASN1_EOC,				ASN1_RAW  }, /*  2 */
	{ 2,     "issuerNameHash",			ASN1_OCTET_STRING,		ASN1_BODY }, /*  3 */
	{ 2,     "issuerKeyHash",			ASN1_OCTET_STRING,		ASN1_BODY }, /*  4 */
	{ 2,     "serialNumber",			ASN1_INTEGER,			ASN1_BODY }, /*  5 */
	{ 1,   "certStatusGood",			ASN1_CONTEXT_S_0,		ASN1_OPT  }, /*  6 */
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }, /*  7 */
	{ 1,   "certStatusRevoked",			ASN1_CONTEXT_C_1,		ASN1_OPT  }, /*  8 */
	{ 2,     "revocationTime",			ASN1_GENERALIZEDTIME,	ASN1_BODY }, /*  9 */
	{ 2,     "revocationReason",		ASN1_CONTEXT_C_0,		ASN1_OPT  }, /* 10 */
	{ 3,       "crlReason",				ASN1_ENUMERATED,		ASN1_BODY }, /* 11 */
	{ 2,     "end opt",					ASN1_EOC,				ASN1_END  }, /* 12 */
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }, /* 13 */
	{ 1,   "certStatusUnknown",			ASN1_CONTEXT_S_2,		ASN1_OPT  }, /* 14 */
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }, /* 15 */
	{ 1,   "thisUpdate",				ASN1_GENERALIZEDTIME,	ASN1_BODY }, /* 16 */
	{ 1,   "nextUpdateContext",			ASN1_CONTEXT_C_0,		ASN1_OPT  }, /* 17 */
	{ 2,     "nextUpdate",				ASN1_GENERALIZEDTIME,	ASN1_BODY }, /* 18 */
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }, /* 19 */
	{ 1,   "singleExtensionsContext",	ASN1_CONTEXT_C_1,		ASN1_OPT  }, /* 20 */
	{ 2,     "singleExtensions",		ASN1_SEQUENCE,			ASN1_LOOP }, /* 21 */
	{ 3,       "extension",				ASN1_SEQUENCE,			ASN1_NONE }, /* 22 */
	{ 4,         "extnID",				ASN1_OID,				ASN1_BODY }, /* 23 */
	{ 4,         "critical",			ASN1_BOOLEAN,			ASN1_BODY |
																ASN1_DEF  }, /* 24 */
	{ 4,         "extnValue",			ASN1_OCTET_STRING,		ASN1_BODY }, /* 25 */
	{ 2,     "end loop",				ASN1_EOC,				ASN1_END  }, /* 26 */
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }  /* 27 */
};

#define SINGLE_RESPONSE_ALGORITHM					 2
#define SINGLE_RESPONSE_ISSUER_NAME_HASH			 3
#define SINGLE_RESPONSE_ISSUER_KEY_HASH				 4
#define SINGLE_RESPONSE_SERIAL_NUMBER				 5
#define SINGLE_RESPONSE_CERT_STATUS_GOOD			 6
#define SINGLE_RESPONSE_CERT_STATUS_REVOKED			 8
#define SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME	 9
#define SINGLE_RESPONSE_CERT_STATUS_CRL_REASON		11
#define SINGLE_RESPONSE_CERT_STATUS_UNKNOWN			14
#define SINGLE_RESPONSE_THIS_UPDATE					16
#define SINGLE_RESPONSE_NEXT_UPDATE					18
#define SINGLE_RESPONSE_EXT_ID						23
#define SINGLE_RESPONSE_CRITICAL					24
#define SINGLE_RESPONSE_EXT_VALUE					25
#define SINGLE_RESPONSE_ROOF						28


