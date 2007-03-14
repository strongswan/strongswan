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
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <utils/identification.h>
#include <utils/randomizer.h>
#include <utils/fetcher.h>
#include <debug.h>

#include "hashers/hasher.h"
#include "rsa/rsa_public_key.h"
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

	/**
	 * SHA-1 hash over issuer public key
	 */
	chunk_t authKeyID;
};

ENUM(response_status_names, STATUS_SUCCESSFUL, STATUS_UNAUTHORIZED,
	"successful",
	"malformed request",
	"internal error",
	"try later",
	"signature required",
	"unauthorized"
);

/* response container */
typedef struct response_t response_t;

struct response_t {
	chunk_t           chunk;
	chunk_t           tbs;
	identification_t *responder_id_name;
	chunk_t           responder_id_key;
	time_t            produced_at;
	chunk_t           responses;
	chunk_t           nonce;
	int               algorithm;
	chunk_t           signature;
	x509_t           *responder_cert;

	/**
	 * @brief Destroys the response_t object
	 * 
	 * @param this		response_t to destroy
	 */
	void (*destroy) (response_t *this);
};

/**
 * Implements response_t.destroy.
 */
static void response_destroy(response_t *this)
{
	DESTROY_IF(this->responder_id_name);
	DESTROY_IF(this->responder_cert);
	free(this->chunk.ptr);
	free(this);
}

/**
 * Creates a response_t object
 */
static response_t* response_create_from_chunk(chunk_t chunk)
{
	response_t *this = malloc_thing(response_t);

	this->chunk             = chunk;
	this->tbs               = chunk_empty;
	this->responder_id_name = NULL;
	this->responder_id_key  = chunk_empty;
	this->produced_at       = UNDEFINED_TIME;
	this->responses         = chunk_empty;
	this->nonce             = chunk_empty;
	this->algorithm         = OID_UNKNOWN;
	this->signature         = chunk_empty;
	this->responder_cert    = NULL;

	this->destroy = (void (*) (response_t*))response_destroy;

	return this;
}

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
	{ 3,       "certificate",				ASN1_SEQUENCE,			ASN1_RAW  }, /* 24 */
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
	chunk_t serialNumber = certinfo->get_serialNumber(certinfo);

	chunk_t reqCert = asn1_wrap(ASN1_SEQUENCE, "cmmm",
		ASN1_sha1_id,
		asn1_simple_object(ASN1_OCTET_STRING, this->authNameID),
		asn1_simple_object(ASN1_OCTET_STRING, this->authKeyID),
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
	/* TODO */
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

    /* TODO has_requestor_cert = get_ocsp_requestor_cert(location); */

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
 * parse a basic OCSP response
 */
static bool ocsp_parse_basic_response(chunk_t blob, int level0, response_t *res)
{
	u_int level, version;
	u_int extn_oid = OID_UNKNOWN;
	asn1_ctx_t ctx;
	bool critical;
	chunk_t object;
	int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, FALSE);

	while (objectID < BASIC_RESPONSE_ROOF)
	{
		if (!extract_object(basicResponseObjects, &objectID, &object, &level, &ctx))
		{
			return FALSE;
		}

		switch (objectID)
		{
			case BASIC_RESPONSE_TBS_DATA:
				res->tbs = object;
				break;
			case BASIC_RESPONSE_VERSION:
				version = (object.len)? (1 + (u_int)*object.ptr) : 1;
				if (version != OCSP_BASIC_RESPONSE_VERSION)
				{
					DBG1("wrong ocsp basic response version (version= %i)",  version);
					return FALSE;
				}
				break;
			case BASIC_RESPONSE_ID_BY_NAME:
				res->responder_id_name = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				DBG2("  '%D'", res->responder_id_name);
				break;
			case BASIC_RESPONSE_ID_BY_KEY:
				res->responder_id_key = object;
				break;
			case BASIC_RESPONSE_PRODUCED_AT:
				res->produced_at = asn1totime(&object, ASN1_GENERALIZEDTIME);
				break;
			case BASIC_RESPONSE_RESPONSES:
				res->responses = object;
				break;
			case BASIC_RESPONSE_EXT_ID:
				extn_oid = known_oid(object);
				break;
			case BASIC_RESPONSE_CRITICAL:
				critical = object.len && *object.ptr;
				DBG2("  %s", critical? "TRUE" : "FALSE");
				break;
			case BASIC_RESPONSE_EXT_VALUE:
				if (extn_oid == OID_NONCE)
					res->nonce = object;
				break;
			case BASIC_RESPONSE_ALGORITHM:
				res->algorithm = parse_algorithmIdentifier(object, level+1, NULL);
				break;
			case BASIC_RESPONSE_SIGNATURE:
				res->signature = object;
				break;
			case BASIC_RESPONSE_CERTIFICATE:
				{
					chunk_t blob = chunk_clone(object);

					res->responder_cert = x509_create_from_chunk(blob, level+1);
				}
				break;
		}
		objectID++;
	}
	return TRUE;
}

/**
 * parse an ocsp response and return the result as a response_t struct
 */
static response_status ocsp_parse_response(response_t *res)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;

	response_status rStatus = STATUS_INTERNALERROR;
	u_int ocspResponseType = OID_UNKNOWN;

	asn1_init(&ctx, res->chunk, 0, FALSE, FALSE);

	while (objectID < OCSP_RESPONSE_ROOF)
	{
		if (!extract_object(ocspResponseObjects, &objectID, &object, &level, &ctx))
		{
	    	return STATUS_INTERNALERROR;
		}

		switch (objectID)
		{
			case OCSP_RESPONSE_STATUS:
				rStatus = (response_status) *object.ptr;
				DBG2("  '%N'", response_status_names, rStatus);
 
				switch (rStatus)
	    		{
	    			case STATUS_SUCCESSFUL:
						break;
					case STATUS_MALFORMEDREQUEST:
					case STATUS_INTERNALERROR:
					case STATUS_TRYLATER:
					case STATUS_SIGREQUIRED:
					case STATUS_UNAUTHORIZED:
						DBG1("unsuccessful ocsp response: server said '%N'",
							 response_status_names, rStatus);
						return rStatus;
					default:
						return STATUS_INTERNALERROR;
				}
	    		break;
			case OCSP_RESPONSE_TYPE:
				ocspResponseType = known_oid(object);
				break;
			case OCSP_RESPONSE:
				{
					switch (ocspResponseType)
					{
						case OID_BASIC:
							if (!ocsp_parse_basic_response(object, level+1, res))
							{
								return STATUS_INTERNALERROR;
							}
							break;
						default:
							DBG1("ocsp response is not of type BASIC");
							DBG1("ocsp response OID: %#B", &object);
							return STATUS_INTERNALERROR;
					}
				}
				break;
		}
		objectID++;
	}
	return rStatus;
}

/**
 * Check if the OCSP response has a valid signature
 */
static bool ocsp_valid_response(response_t *res, x509_t *ocsp_cert)
{
	rsa_public_key_t *public_key;
	time_t until = UNDEFINED_TIME;
	err_t ugh;

	DBG2("verifying ocsp response signature:");
	DBG2("signer:  '%D'", ocsp_cert->get_subject(ocsp_cert));
	DBG2("issuer:  '%D'", ocsp_cert->get_issuer(ocsp_cert));

	ugh = ocsp_cert->is_valid(ocsp_cert, &until);
	if (ugh != NULL)
	{
		DBG1("ocsp signer certificate %s", ugh);
		return FALSE;
	}
	public_key = ocsp_cert->get_public_key(ocsp_cert);

	return public_key->verify_emsa_pkcs1_signature(public_key, res->tbs, res->signature) == SUCCESS;
}

/**
 * parse a single OCSP response
 */
static bool ocsp_parse_single_response(private_ocsp_t *this, chunk_t blob, int level0)
{
	u_int level, extn_oid;
	asn1_ctx_t ctx;
	bool critical;
	chunk_t object;
	int objectID = 0;

	certinfo_t *certinfo = NULL;

	asn1_init(&ctx, blob, level0, FALSE, FALSE);

	while (objectID < SINGLE_RESPONSE_ROOF)
	{
		if (!extract_object(singleResponseObjects, &objectID, &object, &level, &ctx))
		{
			return FALSE;
		}

		switch (objectID)
		{
			case SINGLE_RESPONSE_ALGORITHM:
				if (parse_algorithmIdentifier(object, level+1, NULL) != OID_SHA1)
				{
					DBG1("only sha-1 hash supported in ocsp single response");
					return FALSE;
				}
				break;
			case SINGLE_RESPONSE_ISSUER_NAME_HASH:
    			if (!chunk_equals(object, this->authNameID))
				{
					DBG1("ocsp single response has wrong issuer name hash");
					return FALSE;
				}
				break;
			case SINGLE_RESPONSE_ISSUER_KEY_HASH:
    			if (!chunk_equals(object, this->authKeyID))
				{
					DBG1("ocsp single response has wrong issuer key hash");
					return FALSE;
				}
				break;
			case SINGLE_RESPONSE_SERIAL_NUMBER:
				{
					iterator_t *iterator = this->certinfos->create_iterator(this->certinfos, TRUE);
					certinfo_t *current_certinfo;

					while (iterator->iterate(iterator, (void**)&current_certinfo))
					{
						if (chunk_equals(object, current_certinfo->get_serialNumber(current_certinfo)))
						{
							certinfo = current_certinfo;
						}
					}
					iterator->destroy(iterator);
					if (certinfo == NULL)
					{
						DBG1("unrequested serial number in ocsp single response");
						return FALSE;
					}
				}
				break;
			case SINGLE_RESPONSE_CERT_STATUS_GOOD:
				certinfo->set_status(certinfo, CERT_GOOD);
				break;
			case SINGLE_RESPONSE_CERT_STATUS_REVOKED:
				certinfo->set_status(certinfo, CERT_REVOKED);
				break;
			case SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME:
				certinfo->set_revocationTime(certinfo,
								 asn1totime(&object, ASN1_GENERALIZEDTIME));
				break;
			case SINGLE_RESPONSE_CERT_STATUS_CRL_REASON:
				certinfo->set_revocationReason(certinfo,
								(object.len == 1) ? *object.ptr : REASON_UNSPECIFIED);
	    		break;
			case SINGLE_RESPONSE_CERT_STATUS_UNKNOWN:
				certinfo->set_status(certinfo, CERT_UNKNOWN);
				break;
			case SINGLE_RESPONSE_THIS_UPDATE:
				certinfo->set_thisUpdate(certinfo,
								asn1totime(&object, ASN1_GENERALIZEDTIME));
				break;
			case SINGLE_RESPONSE_NEXT_UPDATE:
				certinfo->set_nextUpdate(certinfo,
								asn1totime(&object, ASN1_GENERALIZEDTIME));
	    		break;
			case SINGLE_RESPONSE_EXT_ID:
				extn_oid = known_oid(object);
				break;
			case SINGLE_RESPONSE_CRITICAL:
				critical = object.len && *object.ptr;
				DBG2("  %s", critical ? "TRUE" : "FALSE");
			case SINGLE_RESPONSE_EXT_VALUE:
				break;
		}
		objectID++;
	}
	return TRUE;
}

/**
 *  verify and process ocsp response and update the ocsp cache
 */
static void ocsp_process_response(private_ocsp_t *this, response_t *res, credential_store_t *credentials)
{
	x509_t *ocsp_cert = NULL;

	/* parse the ocsp response without looking at the single responses yet */
	response_status status = ocsp_parse_response(res);

	if (status != STATUS_SUCCESSFUL)
	{
		DBG1("error in ocsp response");
		return;
	}

	/* check if there was a nonce in the request */
	if (this->nonce.ptr != NULL && res->nonce.ptr == NULL)
	{
		DBG1("ocsp response contains no nonce, replay attack possible");
	}

	/* check if the nonces are identical */
	if (res->nonce.ptr != NULL && !chunk_equals(res->nonce, this->nonce))
    {
		DBG1("invalid nonce in ocsp response");
		return;
	}

	/* check if we received a trusted responder certificate */
	if (res->responder_cert)
	{
		if (res->responder_cert->is_ocsp_signer(res->responder_cert))
		{
			DBG2("received certificate is ocsp signer");
			if (credentials->is_trusted(credentials, res->responder_cert))
			{
				DBG1("received ocsp signer certificate is trusted");
				ocsp_cert = credentials->add_auth_certificate(credentials,
									res->responder_cert, AUTH_OCSP);
				res->responder_cert = NULL;
			}
			else
			{
				DBG1("received ocsp signer certificate is not trusted - rejected");
			}
		}
		else
		{
			DBG1("received certificate is no ocsp signer - rejected");
		}
	}

	/* if we didn't receive a trusted responder cert, search the credential store */
	if (ocsp_cert == NULL)
	{
		ocsp_cert = credentials->get_auth_certificate(credentials,
							AUTH_OCSP|AUTH_CA, res->responder_id_name);
		if (ocsp_cert == NULL)
		{
			DBG1("no ocsp signer certificate found");
			return;
		}
	}

	/* check the response signature */
	if (!ocsp_valid_response(res, ocsp_cert))
	{
		DBG1("ocsp response signature is invalid");
		return;
	}
	DBG2("ocsp response signature is valid");

    /* now parse the single responses one at a time */
    {
		u_int level;
		asn1_ctx_t ctx;
		chunk_t object;
		int objectID = 0;

		asn1_init(&ctx, res->responses, 0, FALSE, FALSE);

		while (objectID < RESPONSES_ROOF)
		{
			if (!extract_object(responsesObjects, &objectID, &object, &level, &ctx))
			{
				return;
			}
			if (objectID == RESPONSES_SINGLE_RESPONSE)
			{
				ocsp_parse_single_response(this, object, level+1);
			}
			objectID++;
		}
	}
}

/**
 * Implements ocsp_t.fetch.
 */
static void fetch(private_ocsp_t *this, certinfo_t *certinfo, credential_store_t *credentials)
{
	chunk_t request;
	response_t *response = NULL;

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
			fetcher_t *fetcher;
			char uri_string[BUF_LEN];
			chunk_t uri_chunk = uri->get_encoding(uri);
			chunk_t response_chunk;

			snprintf(uri_string, BUF_LEN, "%.*s", uri_chunk.len, uri_chunk.ptr);
			fetcher = fetcher_create(uri_string);
			
			response_chunk = fetcher->post(fetcher, "application/ocsp-request", request);
			fetcher->destroy(fetcher);
			if (response_chunk.ptr != NULL)
			{
				response = response_create_from_chunk(response_chunk);
				break;
			}
		}
		iterator->destroy(iterator);
	}
	free(request.ptr);

	if (response == NULL)
	{
		return;
	}
	DBG3("ocsp response: %B", &response->chunk);
	ocsp_process_response(this, response, credentials);
	response->destroy(response);
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
	this->authKeyID = cacert->get_subjectKeyID(cacert);
	{
		hasher_t *hasher = hasher_create(HASH_SHA1);
		identification_t *issuer = cacert->get_subject(cacert);

		hasher->allocate_hash(hasher, issuer->get_encoding(issuer),
									  &this->authNameID);
		hasher->destroy(hasher);
	}

	/* public functions */
	this->public.fetch = (void (*) (ocsp_t*,certinfo_t*,credential_store_t*))fetch;
	this->public.destroy = (void (*) (ocsp_t*))destroy;

	return &this->public;
}
