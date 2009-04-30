/**
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
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

#include "x509_ocsp_response.h"

#include <time.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <debug.h>

#include <library.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>

/**
 * how long do we use an OCSP response without a nextUpdate
 */
#define OCSP_DEFAULT_LIFETIME 30

typedef struct private_x509_ocsp_response_t private_x509_ocsp_response_t;

/**
 * Private data of a ocsp_t object.
 */
struct private_x509_ocsp_response_t {
	/**
	 * Public interface for this ocsp object.
	 */
	x509_ocsp_response_t public;
	
	/**
	 * complete encoded OCSP response
	 */
	chunk_t encoding;
	
	/**
	 * data for signature verficiation
	 */
	chunk_t tbsResponseData;
	
	/**
	 * signature algorithm (OID)
	 */
	int signatureAlgorithm;
	
	/**
	 * signature
	 */
	chunk_t signature;
	
	/**
	 * name or keyid of the responder
	 */
	identification_t *responderId;
	
	/**
	 * time of response production
	 */
	time_t producedAt;
	
	/**
	 * latest nextUpdate in this OCSP response
	 */
	time_t usableUntil;
	
	/**
	 * list of included certificates
	 */
	linked_list_t *certs;

	/**
	 * Linked list of OCSP responses, single_response_t
	 */
	linked_list_t *responses;

	/**
	 * Nonce required for ocsp request and response
	 */
	chunk_t nonce;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * single response contained in OCSP response
 */
typedef struct {
	/** hash algorithm OID to for the two hashes */
	int hashAlgorithm;
	/** hash of issuer DN */
	chunk_t issuerNameHash;
	/** issuerKeyID */
	chunk_t issuerKeyHash;
	/** serial number of certificate */
	chunk_t serialNumber;
	/** OCSP certificate status */
	cert_validation_t status;
	/** time of revocation, if revoked */
	time_t revocationTime;
	/** revocation reason, if revoked */
	crl_reason_t revocationReason;
	/** creation of associated CRL */
	time_t thisUpdate;
	/** creation of next CRL */
	time_t nextUpdate;
} single_response_t;

/* our OCSP response version implementation */
#define OCSP_BASIC_RESPONSE_VERSION 1

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

/**
 * Implementaiton of ocsp_response_t.get_status
 */
static cert_validation_t get_status(private_x509_ocsp_response_t *this,
									x509_t *subject, x509_t *issuer,
									time_t *revocation_time,
									crl_reason_t *revocation_reason,
									time_t *this_update, time_t *next_update)
{
	enumerator_t *enumerator;
	single_response_t *response;
	cert_validation_t status = VALIDATION_FAILED;
	certificate_t *issuercert = &issuer->interface;
	
	enumerator = this->responses->create_enumerator(this->responses);
	while (enumerator->enumerate(enumerator, &response))
	{
		hasher_t *hasher;
		identification_t *id;
		chunk_t hash;
		
		/* check serial first, is cheaper */
		if (!chunk_equals(subject->get_serial(subject), response->serialNumber))
		{
			continue;
		}
		/* check issuerKeyHash if available */
		if (response->issuerKeyHash.ptr)
		{
			public_key_t *public;
			
			public = issuercert->get_public_key(issuercert);
			if (!public)
			{
				continue;
			}
			switch (response->hashAlgorithm)
			{	/* TODO: generic mapper function */
				case OID_SHA1:
					id = public->get_id(public, ID_PUBKEY_SHA1);
					break;
				default:
					public->destroy(public);
					continue;
			}
			if (!chunk_equals(response->issuerKeyHash, id->get_encoding(id)))
			{
				public->destroy(public);
				continue;
			}
			public->destroy(public);
		}
		/* check issuerNameHash, if available */
		else if (response->issuerNameHash.ptr)
		{
			hasher = lib->crypto->create_hasher(lib->crypto, 
							hasher_algorithm_from_oid(response->hashAlgorithm));
			if (!hasher)
			{
				continue;
			}
			id = issuercert->get_subject(issuercert);
			hasher->allocate_hash(hasher, id->get_encoding(id), &hash);
			hasher->destroy(hasher);
			if (!chunk_equals(hash, response->issuerNameHash))
			{
				continue;
			}
		}
		else
		{
			continue;
		}
		/* got a match */
		status = response->status;
		*revocation_time = response->revocationTime;
		*revocation_reason = response->revocationReason;
		*this_update = response->thisUpdate;
		*next_update = response->nextUpdate;
		
		break;
	}
	enumerator->destroy(enumerator);
	return status;
}

/**
 * Implementation of ocsp_response_t.create_cert_enumerator.
 */
static enumerator_t* create_cert_enumerator(private_x509_ocsp_response_t *this)
{
	return this->certs->create_enumerator(this->certs);
}

/**
 * ASN.1 definition of singleResponse
 */
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
	{ 1,   "end opt",					ASN1_EOC,				ASN1_END  }, /* 27 */
	{ 0, "exit",						ASN1_EOC,				ASN1_EXIT }
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

/**
 * Parse a single OCSP response
 */
static bool parse_singleResponse(private_x509_ocsp_response_t *this,
								 chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	single_response_t *response;
	
	response = malloc_thing(single_response_t);
	response->hashAlgorithm = OID_UNKNOWN;
	response->issuerNameHash = chunk_empty;
	response->issuerKeyHash = chunk_empty;
	response->serialNumber = chunk_empty;
	response->status = VALIDATION_FAILED;
	response->revocationTime = 0;
	response->revocationReason = CRL_UNSPECIFIED;
	response->thisUpdate = UNDEFINED_TIME;
	/* if nextUpdate is missing, we give it a short lifetime */
	response->nextUpdate = this->producedAt + OCSP_DEFAULT_LIFETIME;

	parser = asn1_parser_create(singleResponseObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case SINGLE_RESPONSE_ALGORITHM:
				response->hashAlgorithm = asn1_parse_algorithmIdentifier(object,
											parser->get_level(parser)+1, NULL);
				break;
			case SINGLE_RESPONSE_ISSUER_NAME_HASH:
				response->issuerNameHash = object;
				break;
			case SINGLE_RESPONSE_ISSUER_KEY_HASH:
				response->issuerKeyHash = object;
				break;
			case SINGLE_RESPONSE_SERIAL_NUMBER:
				response->serialNumber = object;
				break;
			case SINGLE_RESPONSE_CERT_STATUS_GOOD:
				response->status = VALIDATION_GOOD;
				break;
			case SINGLE_RESPONSE_CERT_STATUS_REVOKED:
				response->status = VALIDATION_REVOKED;
				break;
			case SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME:
				response->revocationTime = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				break;
			case SINGLE_RESPONSE_CERT_STATUS_CRL_REASON:
				if (object.len == 1)
				{
					response->revocationReason = *object.ptr;
				}
	    		break;
			case SINGLE_RESPONSE_CERT_STATUS_UNKNOWN:
				response->status = VALIDATION_FAILED;
				break;
			case SINGLE_RESPONSE_THIS_UPDATE:
				response->thisUpdate = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				break;
			case SINGLE_RESPONSE_NEXT_UPDATE:
				response->nextUpdate = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				if (response->nextUpdate > this->usableUntil)
				{
					this->usableUntil = response->nextUpdate;
				}
	    		break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	if (success)
	{
		if (this->usableUntil == UNDEFINED_TIME)
		{
			this->usableUntil = this->producedAt + OCSP_DEFAULT_LIFETIME;
		}
		this->responses->insert_last(this->responses, response);
	}
	return success;
}

/**
 * ASN.1 definition of responses
 */
static const asn1Object_t responsesObjects[] = {
	{ 0, "responses",			ASN1_SEQUENCE,	ASN1_LOOP }, /* 0 */
	{ 1,   "singleResponse",	ASN1_EOC,		ASN1_RAW  }, /* 1 */
	{ 0, "end loop",			ASN1_EOC,		ASN1_END  }, /* 2 */
	{ 0, "exit",				ASN1_EOC,		ASN1_EXIT }
};
#define RESPONSES_SINGLE_RESPONSE	1

/**
 * Parse all responses
 */
static bool parse_responses(private_x509_ocsp_response_t *this, 
							chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;
	
	parser = asn1_parser_create(responsesObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case RESPONSES_SINGLE_RESPONSE:
				if (!parse_singleResponse(this, object,
										  parser->get_level(parser)+1))
				{
					goto end;
				}
				break;
			default:
				break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * ASN.1 definition of basicResponse
 */
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
	{ 1,   "end opt",						ASN1_EOC,				ASN1_END  }, /* 26 */
	{ 0, "exit",							ASN1_EOC,				ASN1_EXIT }
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

/**
 * Parse a basicOCSPResponse
 */
static bool parse_basicOCSPResponse(private_x509_ocsp_response_t *this, 
									chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	chunk_t responses = chunk_empty;
	int objectID;
	int extn_oid = OID_UNKNOWN;
	u_int responses_level = level0;
	certificate_t *cert;
	bool success = FALSE;
	bool critical;
	
	parser = asn1_parser_create(basicResponseObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case BASIC_RESPONSE_TBS_DATA:
				this->tbsResponseData = object;
				break;
			case BASIC_RESPONSE_VERSION:
			{
				u_int version = (object.len)? (1 + (u_int)*object.ptr) : 1;

				if (version != OCSP_BASIC_RESPONSE_VERSION)
				{
					DBG1("  ocsp ResponseData version %d not supported", version);
					goto end;
				}
				break;
			}
			case BASIC_RESPONSE_ID_BY_NAME:
				this->responderId = identification_create_from_encoding(
													ID_DER_ASN1_DN, object);
				DBG2("  '%Y'", this->responderId);
				break;
			case BASIC_RESPONSE_ID_BY_KEY:
				this->responderId = identification_create_from_encoding(
													ID_PUBKEY_INFO_SHA1, object);
				DBG2("  '%Y'", this->responderId);
				break;
			case BASIC_RESPONSE_PRODUCED_AT:
				this->producedAt = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				break;
			case BASIC_RESPONSE_RESPONSES:
				responses = object;
				responses_level = parser->get_level(parser)+1;
				break;
			case BASIC_RESPONSE_EXT_ID:
				extn_oid = asn1_known_oid(object);
				break;
			case BASIC_RESPONSE_CRITICAL:
				critical = object.len && *object.ptr;
				DBG2("  %s", critical ? "TRUE" : "FALSE");
				break;
			case BASIC_RESPONSE_EXT_VALUE:
				if (extn_oid == OID_NONCE)
				{
					this->nonce = object;
				}
				break;
			case BASIC_RESPONSE_ALGORITHM:
				this->signatureAlgorithm = asn1_parse_algorithmIdentifier(object,
												parser->get_level(parser)+1, NULL);
				break;
			case BASIC_RESPONSE_SIGNATURE:
				this->signature = object;
				break;
			case BASIC_RESPONSE_CERTIFICATE:
			{
				cert = lib->creds->create(lib->creds, CRED_CERTIFICATE,CERT_X509,
										  BUILD_BLOB_ASN1_DER, object,
										  BUILD_END);
				if (cert)
				{
					this->certs->insert_last(this->certs, cert);
				}
				break;
			}
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (success)
	{
		if (!this->responderId)
		{
			this->responderId = identification_create_from_encoding(ID_ANY,
									chunk_empty);
		}
		success = parse_responses(this, responses, responses_level);
	}
	return success;
}

/**
 * ASN.1 definition of ocspResponse
 */
static const asn1Object_t ocspResponseObjects[] = {
	{ 0, "OCSPResponse",			ASN1_SEQUENCE,		ASN1_NONE }, /* 0 */
	{ 1,   "responseStatus",		ASN1_ENUMERATED,	ASN1_BODY }, /* 1 */
	{ 1,   "responseBytesContext",	ASN1_CONTEXT_C_0,	ASN1_OPT  }, /* 2 */
	{ 2,     "responseBytes",		ASN1_SEQUENCE,		ASN1_NONE }, /* 3 */
	{ 3,       "responseType",		ASN1_OID,			ASN1_BODY }, /* 4 */
	{ 3,       "response",			ASN1_OCTET_STRING,	ASN1_BODY }, /* 5 */
	{ 1,   "end opt",				ASN1_EOC,			ASN1_END  }, /* 6 */
	{ 0, "exit",					ASN1_EOC,			ASN1_EXIT }
};
#define OCSP_RESPONSE_STATUS	1
#define OCSP_RESPONSE_TYPE		4
#define OCSP_RESPONSE			5

/**
 * Parse OCSPResponse object
 */
static bool parse_OCSPResponse(private_x509_ocsp_response_t *this)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int responseType = OID_UNKNOWN;
	bool success = FALSE;
	ocsp_status_t status;

	parser = asn1_parser_create(ocspResponseObjects, this->encoding);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case OCSP_RESPONSE_STATUS:
				status = (ocsp_status_t)*object.ptr;
				switch (status)
	    		{
	    			case OCSP_SUCCESSFUL:
						break;
					default:
						DBG1("  ocsp response status: %N",
							 ocsp_status_names, status);
						goto end;
				}
	    		break;
			case OCSP_RESPONSE_TYPE:
				responseType = asn1_known_oid(object);
				break;
			case OCSP_RESPONSE:
				switch (responseType)
				{
					case OID_BASIC:
						success = parse_basicOCSPResponse(this, object,
												parser->get_level(parser)+1);
						break;
					default:
						DBG1("  ocsp response type %#B not supported", &object);
						goto end;
				}
				break;
		}
	}
	success &= parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_x509_ocsp_response_t *this)
{
	return CERT_X509_OCSP_RESPONSE;
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_x509_ocsp_response_t *this)
{
	return this->responderId;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_issuer(private_x509_ocsp_response_t *this,
							 identification_t *issuer)
{
	return this->responderId->matches(this->responderId, issuer);
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_x509_ocsp_response_t *this, certificate_t *issuer)
{
	public_key_t *key;
	signature_scheme_t scheme;
	bool valid;
	x509_t *x509 = (x509_t*)issuer;
	
	if (issuer->get_type(issuer) != CERT_X509)
	{
		return FALSE;
	}
	if (this->responderId->get_type(this->responderId) == ID_DER_ASN1_DN)
	{
		if (!this->responderId->equals(this->responderId,
									   issuer->get_subject(issuer)))
		{
			return FALSE;
		}
	}
	else
	{
		bool equal;
		public_key_t *public = issuer->get_public_key(issuer);

		if (public == NULL)
		{
			return FALSE;
		}
		equal = this->responderId->equals(this->responderId,
										  public->get_id(public, ID_PUBKEY_SHA1));
		public->destroy(public);
		if (!equal)
		{
				return FALSE;
		}
	}
	if (!(x509->get_flags(x509) & X509_OCSP_SIGNER) &&
		!(x509->get_flags(x509) & X509_CA))
	{
		return FALSE;
	}
	/* TODO: generic OID to scheme mapper? */
	switch (this->signatureAlgorithm)
	{
		case OID_MD5_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_MD5;
			break;
		case OID_SHA1_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			break;
		case OID_SHA256_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA256;
			break;
		case OID_SHA384_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA384;
			break;
		case OID_SHA512_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA512;
			break;
		case OID_ECDSA_WITH_SHA1:
			scheme = SIGN_ECDSA_WITH_SHA1;
			break;
		default:
			return FALSE;
	}
	key = issuer->get_public_key(issuer);
	if (key == NULL)
	{
		return FALSE;
	}
	valid = key->verify(key, scheme, this->tbsResponseData, this->signature);
	key->destroy(key);
	return valid;
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_x509_ocsp_response_t *this)
{
	return NULL;
}

/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_x509_ocsp_response_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	time_t t;

	if (when == NULL)
	{
		t = time(NULL);
	}
	else
	{
		t = *when;
	}
	if (not_before)
	{
		*not_before = this->producedAt;
	}
	if (not_after)
	{
		*not_after = this->usableUntil;
	}
	return (t < this->usableUntil);
}

/**
 * Implementation of certificate_t.is_newer.
 */
static bool is_newer(certificate_t *this, certificate_t *that)
{
	time_t this_update, that_update, now = time(NULL);
	bool new;

	this->get_validity(this, &now, &this_update, NULL);
	that->get_validity(that, &now, &that_update, NULL);
	new = this_update > that_update;
	DBG1("  ocsp response from %T is %s - existing ocsp response from %T %s",
				&this_update, FALSE, new ? "newer":"not newer",
				&that_update, FALSE, new ? "replaced":"retained");
	return new;
}
	
/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_x509_ocsp_response_t *this)
{
	return chunk_clone(this->encoding);
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_x509_ocsp_response_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;
	
	if (this == (private_x509_ocsp_response_t*)other)
	{
		return TRUE;
	}
	if (other->get_type(other) != CERT_X509_OCSP_RESPONSE)
	{
		return FALSE;
	}
	if (other->equals == (void*)equals)
	{	/* skip allocation if we have the same implementation */
		return chunk_equals(this->encoding, ((private_x509_ocsp_response_t*)other)->encoding); 
	}
	encoding = other->get_encoding(other);
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

/**
 * Implementation of certificate_t.get_ref
 */
static private_x509_ocsp_response_t* get_ref(private_x509_ocsp_response_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implements ocsp_t.destroy.
 */
static void destroy(private_x509_ocsp_response_t *this)
{
	if (ref_put(&this->ref))
	{
		this->certs->destroy_offset(this->certs, offsetof(certificate_t, destroy));
		this->responses->destroy_function(this->responses, free);
		DESTROY_IF(this->responderId);
		free(this->encoding.ptr);
		free(this);
	}
}

/**
 * load an OCSP response
 */
static x509_ocsp_response_t *load(chunk_t data)
{
	private_x509_ocsp_response_t *this;
	
	this = malloc_thing(private_x509_ocsp_response_t);
	
	this->public.interface.certificate.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.certificate.get_subject = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.certificate.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.certificate.has_subject = (id_match_t(*)(certificate_t*, identification_t *subject))has_issuer;
	this->public.interface.certificate.has_issuer = (id_match_t(*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.certificate.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.interface.certificate.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.certificate.get_validity = (bool(*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.certificate.is_newer = (bool (*)(certificate_t*,certificate_t*))is_newer;
	this->public.interface.certificate.get_encoding = (chunk_t(*)(certificate_t*))get_encoding;
	this->public.interface.certificate.equals = (bool(*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.certificate.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.certificate.destroy = (void (*)(certificate_t *this))destroy;
	this->public.interface.get_status = (cert_validation_t(*)(ocsp_response_t*, x509_t *subject, x509_t *issuer, time_t *revocation_time,crl_reason_t *revocation_reason,time_t *this_update, time_t *next_update))get_status;
	this->public.interface.create_cert_enumerator = (enumerator_t*(*)(ocsp_response_t*))create_cert_enumerator;
	
	this->ref = 1;
	this->encoding = data;
	this->tbsResponseData = chunk_empty;
	this->responderId = NULL;
	this->producedAt = UNDEFINED_TIME;
	this->usableUntil = UNDEFINED_TIME;
	this->responses = linked_list_create();
	this->nonce = chunk_empty;
	this->signatureAlgorithm = OID_UNKNOWN;
	this->signature = chunk_empty;
	this->certs = linked_list_create();

	if (!parse_OCSPResponse(this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}


typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for certificate loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded response */
	x509_ocsp_response_t *res;
};

/**
 * Implementation of builder_t.build
 */
static x509_ocsp_response_t *build(private_builder_t *this)
{
	x509_ocsp_response_t *res = this->res;
	
	free(this);
	return res;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	if (!this->res)
	{
		va_list args;
		chunk_t chunk;
		
		switch (part)
		{
			case BUILD_BLOB_ASN1_DER:
			{
				va_start(args, part);
				chunk = va_arg(args, chunk_t);
				this->res = load(chunk_clone(chunk));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->res)
	{
		destroy((private_x509_ocsp_response_t*)this->res);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *x509_ocsp_response_builder(certificate_type_t type)
{
	private_builder_t *this;
	
	if (type != CERT_X509_OCSP_RESPONSE)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->res = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

