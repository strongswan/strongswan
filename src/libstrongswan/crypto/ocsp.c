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
#include <utils/identification.h>
#include <utils/randomizer.h>
#include <debug.h>

#include "hashers/hasher.h"
#include "certinfo.h"
#include "x509.h"
#include "ocsp.h"

#define NONCE_LENGTH		16

typedef struct private_ocsp_t private_ocsp_t;

/**
 * Private data of a ocsp_t object.
 */
struct private_ocsp_t {
	/**
	 * Public interface for this ocsp object.
	 */
	ocsp_t public;

	/**
	 * CA certificate.
	 */
	x509_t *cacert;

	/**
	 * Requestor certificate
	 */
	x509_t *requestor_cert;

	/**
	 * Linked list of ocsp uris
	 */
	linked_list_t *uris;

	/**
	 * Linked list of certinfos to be requested
	 */
	linked_list_t *certinfos;

	/**
	 * Nonce required for ocsp request and response
	 */
	chunk_t nonce;

	/**
	 * SHA-1 hash over issuer distinguished name
	 */
	chunk_t authNameID;
};

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

/**
 * build requestorName (into TBSRequest)
 */
static chunk_t build_requestor_name(private_ocsp_t *this)
{
	identification_t *requestor_name = this->requestor_cert->get_subject(this->requestor_cert);

	return asn1_wrap(ASN1_CONTEXT_C_1, "m",
				asn1_simple_object(ASN1_CONTEXT_C_4,
					requestor_name->get_encoding(requestor_name)));
}

/**
 * build request (into requestList)
 * no singleRequestExtensions used
 */
static chunk_t build_request(private_ocsp_t *this, certinfo_t *certinfo)
{
	chunk_t authKeyID = this->cacert->get_subjectKeyID(this->cacert);
	chunk_t serialNumber = certinfo->get_serialNumber(certinfo);

	chunk_t reqCert = asn1_wrap(ASN1_SEQUENCE, "cmmm",
		ASN1_sha1_id,
		asn1_simple_object(ASN1_OCTET_STRING, this->authNameID),
		asn1_simple_object(ASN1_OCTET_STRING, authKeyID),
		asn1_simple_object(ASN1_INTEGER, serialNumber));

	return asn1_wrap(ASN1_SEQUENCE, "m", reqCert);
}

/**
 * build requestList (into TBSRequest)
 */
static chunk_t build_request_list(private_ocsp_t *this)
{
	chunk_t requestList;
	size_t datalen = 0;
	linked_list_t *request_list = linked_list_create();

	{
		iterator_t *iterator = this->certinfos->create_iterator(this->certinfos, TRUE);
		certinfo_t *certinfo;

		while (iterator->iterate(iterator, (void**)&certinfo))
		{
			chunk_t *request = malloc_thing(chunk_t);

 			*request = build_request(this, certinfo);
			request_list->insert_last(request_list, (void*)request);
			datalen += request->len;
		}
		iterator->destroy(iterator);
	}
	{
		iterator_t *iterator = request_list->create_iterator(request_list, TRUE);
		chunk_t *request;

    	u_char *pos = build_asn1_object(&requestList, ASN1_SEQUENCE, datalen);

		while (iterator->iterate(iterator, (void**)&request))
		{
			memcpy(pos, request->ptr, request->len); 
			pos += request->len;
			free(request->ptr);
			free(request);
		}
		iterator->destroy(iterator);
		request_list->destroy(request_list);
	}
	return requestList;
}

/**
 * build nonce extension (into requestExtensions)
 */
static chunk_t build_nonce_extension(private_ocsp_t *this)
{
	randomizer_t *randomizer = randomizer_create();

    /* generate a random nonce */
	randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_LENGTH, &this->nonce);
	randomizer->destroy(randomizer);

    return asn1_wrap(ASN1_SEQUENCE, "cm",
		ASN1_nonce_oid,
		asn1_simple_object(ASN1_OCTET_STRING, this->nonce));
}

/**
 * build requestExtensions (into TBSRequest)
 */
static chunk_t build_request_ext(private_ocsp_t *this)
{
    return asn1_wrap(ASN1_CONTEXT_C_2, "m",
		asn1_wrap(ASN1_SEQUENCE, "mm",
			build_nonce_extension(this),
		    asn1_wrap(ASN1_SEQUENCE, "cc",
				ASN1_response_oid,
				ASN1_response_content
			)
		)
	);
}

/**
 * build TBSRequest (into OCSPRequest)
 */
static chunk_t build_tbs_request(private_ocsp_t *this, bool has_requestor_cert)
{
	/* version is skipped since the default is ok */
	return asn1_wrap(ASN1_SEQUENCE, "mmm",
		(has_requestor_cert)? build_requestor_name(this): chunk_empty,
		build_request_list(this),
		build_request_ext(this));
}

/**
 * build signature into ocsp request
 * gets built only if a request cert with a corresponding private key is found
 */
static chunk_t build_signature(private_ocsp_t *this, chunk_t tbsRequest)
{
	return chunk_empty;
}

/**
 * assembles an ocsp request and sets the nonce field in private_ocsp_t to the sent nonce
 */
static chunk_t ocsp_build_request(private_ocsp_t *this)
{
	bool has_requestor_cert;
	chunk_t keyid = this->cacert->get_keyid(this->cacert);
	chunk_t tbsRequest, signature;

	DBG2("assembling ocsp request");
	DBG2("issuer: '%D'", this->cacert->get_subject(this->cacert));
	DBG2("keyid:   %#B", &keyid);

	/* looks for requestor cert and matching private key */
	has_requestor_cert = FALSE;

    /* has_requestor_cert = get_ocsp_requestor_cert(location); */

    /* build content */
	tbsRequest = build_tbs_request(this, has_requestor_cert);

    /* sign tbsReuqest */
	signature = (has_requestor_cert)? build_signature(this, tbsRequest): chunk_empty;

    return asn1_wrap(ASN1_SEQUENCE, "mm",
		tbsRequest,
		signature);

	return signature;
}

/**
 * Implements ocsp_t.fetch.
 */
static void fetch(private_ocsp_t *this, certinfo_t *certinfo)
{
	chunk_t request;

	if (this->uris->get_count(this->uris) == 0)
	{
		return;
	}
	this->certinfos->insert_last(this->certinfos, (void*)certinfo);

	request = ocsp_build_request(this);
	DBG3("ocsp request: %B", &request);
	{
		iterator_t *iterator = this->uris->create_iterator(this->uris, TRUE);
		identification_t *uri;

		while (iterator->iterate(iterator, (void**)&uri))
		{
			DBG1("sending ocsp request to location '%D'", uri);
		}
		iterator->destroy(iterator);
	}
	free(request.ptr);
}

/**
 * Implements ocsp_t.destroy.
 */
static void destroy(private_ocsp_t *this)
{
	this->certinfos->destroy(this->certinfos);
	free(this->authNameID.ptr);
	free(this->nonce.ptr);
	free(this);
}

/*
 * Described in header.
 */
ocsp_t *ocsp_create(x509_t *cacert, linked_list_t *uris)
{
	private_ocsp_t *this = malloc_thing(private_ocsp_t);
	
	/* initialize */
	this->cacert = cacert;
	this->uris = uris;
	this->certinfos = linked_list_create();
	this->nonce = chunk_empty;
	{
		hasher_t *hasher = hasher_create(HASH_SHA1);
		identification_t *issuer = cacert->get_subject(cacert);

		hasher->allocate_hash(hasher, issuer->get_encoding(issuer),
									  &this->authNameID);
		hasher->destroy(hasher);
	}

	/* public functions */
	this->public.fetch = (void (*) (ocsp_t*,certinfo_t*))fetch;
	this->public.destroy = (void (*) (ocsp_t*))destroy;

	return &this->public;
}
