/* Support of the Online Certificate Status Protocol (OCSP)
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <freeswan.h>

#include <library.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/rngs/rng.h>
#include <crypto/hashers/hasher.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "smartcard.h"
#include "whack.h"
#include "keys.h"
#include "fetch.h"
#include "ocsp.h"

#define NONCE_LENGTH            16

static const char *const cert_status_names[] = {
	"good",
	"revoked",
	"unknown",
	"undefined"
};


static const char *const response_status_names[] = {
	"successful",
	"malformed request",
	"internal error",
	"try later",
	"status #4",
	"signature required",
	"unauthorized"
};

/* response container */
typedef struct response response_t;

struct response {
	chunk_t          tbs;
	identification_t *responder_id_name;
	chunk_t           responder_id_key;
	time_t            produced_at;
	chunk_t           responses;
	chunk_t           nonce;
	int               algorithm;
	chunk_t           signature;
};

const response_t empty_response = {
	{ NULL, 0 }   ,     /* tbs */
	  NULL        ,     /* responder_id_name */
	{ NULL, 0 }   ,     /* responder_id_key */
	UNDEFINED_TIME,     /* produced_at */
	{ NULL, 0 }   ,     /* single_response */
	{ NULL, 0 }   ,     /* nonce */
	OID_UNKNOWN   ,     /* signature_algorithm */
	{ NULL, 0 }         /* signature */
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
	  NULL                , /* *next */
	OID_UNKNOWN           , /* hash_algorithm */
	{ NULL, 0 }           , /* issuer_name_hash */
	{ NULL, 0 }           , /* issuer_key_hash */
	{ NULL, 0 }           , /* serial_number */
	CERT_UNDEFINED        , /* status */
	UNDEFINED_TIME        , /* revocationTime */
	CRL_REASON_UNSPECIFIED, /* revocationReason */
	UNDEFINED_TIME        , /* this_update */
	UNDEFINED_TIME          /* next_update */
};


/* list of single requests */
typedef struct request_list request_list_t;
struct request_list {
	chunk_t request;
	request_list_t *next;
};

/* some OCSP specific prefabricated ASN.1 constants */
static const chunk_t ASN1_nonce_oid = chunk_from_chars(
	0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
);
static const chunk_t ASN1_response_oid = chunk_from_chars(
	0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04
);
static const chunk_t ASN1_response_content = chunk_from_chars(
	0x04, 0x0D,
		  0x30, 0x0B,
				0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
);

/* default OCSP uri */
static chunk_t ocsp_default_uri;

/* ocsp cache: pointer to first element */
static ocsp_location_t *ocsp_cache = NULL;

/* static temporary storage for ocsp requestor information */
static cert_t *ocsp_requestor_cert = NULL;

static smartcard_t *ocsp_requestor_sc = NULL;

static private_key_t *ocsp_requestor_key = NULL;

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
	{ 3,       "end loop",					ASN1_EOC,				ASN1_END  }, /* 18 */
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

/*
 * Build an ocsp location from certificate information
 * without unsharing its contents
 */
static bool build_ocsp_location(const cert_t *cert, ocsp_location_t *location)
{
	certificate_t *certificate = cert->cert;
	identification_t *issuer = certificate->get_issuer(certificate);
	x509_t *x509 = (x509_t*)certificate;
	chunk_t issuer_dn = issuer->get_encoding(issuer);
	chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
	hasher_t *hasher;
	static u_char digest[HASH_SIZE_SHA1];  /* temporary storage */

	enumerator_t *enumerator = x509->create_ocsp_uri_enumerator(x509);

	location->uri = NULL;
	while (enumerator->enumerate(enumerator, &location->uri))
	{
		break;
	}
	enumerator->destroy(enumerator);

	if (location->uri == NULL)
	{
		ca_info_t *ca = get_ca_info(issuer, authKeyID);
		if (ca && ca->ocspuri)
		{
			location->uri = ca->ocspuri;
		}
		else
		{   /* abort if no ocsp location uri is defined */
			return FALSE;
		}
	}

	/* compute authNameID from as SHA-1 hash of issuer DN */
	location->authNameID = chunk_create(digest, HASH_SIZE_SHA1);
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		return FALSE;
	}
	hasher->get_hash(hasher, issuer_dn, digest);
	hasher->destroy(hasher);

	location->next = NULL;
	location->issuer = issuer;
	location->authKeyID = authKeyID;

	if (authKeyID.ptr == NULL)
	{
		cert_t *authcert = get_authcert(issuer, authKeyID, X509_CA);

		if (authcert)
		{
			x509_t *x509 = (x509_t*)authcert->cert;

			location->authKeyID = x509->get_subjectKeyIdentifier(x509);
		}
	}

	location->nonce = chunk_empty;
	location->certinfo = NULL;

	return TRUE;
}

/**
 * Compare two ocsp locations for equality
 */
static bool same_ocsp_location(const ocsp_location_t *a, const ocsp_location_t *b)
{
	return ((a->authKeyID.ptr)
				? same_keyid(a->authKeyID, b->authKeyID)
				: a->issuer->equals(a->issuer, b->issuer))
			&& streq(a->uri, b->uri);
}

/**
 * Find an existing ocsp location in a chained list
 */
ocsp_location_t* get_ocsp_location(const ocsp_location_t * loc, ocsp_location_t *chain)
{

	while (chain)
	{
		if (same_ocsp_location(loc, chain))
			return chain;
		chain = chain->next;
	}
	return NULL;
}

/**
 * Retrieves the status of a cert from the ocsp cache
 * returns CERT_UNDEFINED if no status is found
 */
static cert_status_t get_ocsp_status(const ocsp_location_t *loc,
									 chunk_t serialNumber,
									 time_t *nextUpdate, time_t *revocationTime,
									 crl_reason_t *revocationReason)
{
	ocsp_certinfo_t *certinfo, **certinfop;
	int cmp = -1;

	/* find location */
	ocsp_location_t *location = get_ocsp_location(loc, ocsp_cache);

	if (location == NULL)
		return CERT_UNDEFINED;

	/* traverse list of certinfos in increasing order */
	certinfop = &location->certinfo;
	certinfo = *certinfop;

	while (certinfo)
	{
		cmp = chunk_compare(serialNumber, certinfo->serialNumber);
		if (cmp <= 0)
			break;
		certinfop = &certinfo->next;
		certinfo = *certinfop;
	}

	if (cmp == 0)
	{
		*nextUpdate = certinfo->nextUpdate;
		*revocationTime = certinfo->revocationTime;
		*revocationReason = certinfo->revocationReason;
		return certinfo->status;
	}

	return CERT_UNDEFINED;
}

/**
 * Verify the ocsp status of a certificate
 */
cert_status_t verify_by_ocsp(const cert_t *cert, time_t *until,
							 time_t *revocationDate,
							 crl_reason_t *revocationReason)
{
	x509_t *x509 = (x509_t*)cert->cert;
	chunk_t serialNumber = x509->get_serial(x509);
	cert_status_t status;
	ocsp_location_t location;
	time_t nextUpdate = UNDEFINED_TIME;

	*revocationDate = UNDEFINED_TIME;
	*revocationReason = CRL_REASON_UNSPECIFIED;

	/* is an ocsp location defined? */
	if (!build_ocsp_location(cert, &location))
	{
		return CERT_UNDEFINED;
	}

	lock_ocsp_cache("verify_by_ocsp");
	status = get_ocsp_status(&location, serialNumber, &nextUpdate
		, revocationDate, revocationReason);
	unlock_ocsp_cache("verify_by_ocsp");

	if (status == CERT_UNDEFINED || nextUpdate < time(NULL))
	{
		plog("ocsp status is stale or not in cache");
		add_ocsp_fetch_request(&location, serialNumber);

		/* inititate fetching of ocsp status */
		wake_fetch_thread("verify_by_ocsp");
	}
	*until = nextUpdate;
	return status;
}

/**
 * Check if an ocsp status is about to expire
 */
void check_ocsp(void)
{
	ocsp_location_t *location;

	lock_ocsp_cache("check_ocsp");
	location = ocsp_cache;

	while (location)
	{
		char buf[BUF_LEN];
		bool first = TRUE;
		ocsp_certinfo_t *certinfo = location->certinfo;

		while (certinfo)
		{
			if (!certinfo->once)
			{
				time_t time_left = certinfo->nextUpdate - time(NULL);

				DBG(DBG_CONTROL,
					if (first)
					{
						DBG_log("issuer: \"%Y\"", location->issuer);
						if (location->authKeyID.ptr)
						{
							datatot(location->authKeyID.ptr, location->authKeyID.len
								, ':', buf, BUF_LEN);
							DBG_log("authkey: %s", buf);
						}
						first = FALSE;
					}
					datatot(certinfo->serialNumber.ptr, certinfo->serialNumber.len
						, ':', buf, BUF_LEN);
					DBG_log("serial: %s, %ld seconds left", buf, time_left)
				)

				if (time_left < 2*crl_check_interval)
					add_ocsp_fetch_request(location, certinfo->serialNumber);
			}
			certinfo = certinfo->next;
		}
		location = location->next;
	}
	unlock_ocsp_cache("check_ocsp");
}

/**
 *  frees the allocated memory of a certinfo struct
 */
static void free_certinfo(ocsp_certinfo_t *certinfo)
{
	free(certinfo->serialNumber.ptr);
	free(certinfo);
}

/**
 * frees all certinfos in a chained list
 */
static void free_certinfos(ocsp_certinfo_t *chain)
{
	ocsp_certinfo_t *certinfo;

	while (chain)
	{
		certinfo = chain;
		chain = chain->next;
		free_certinfo(certinfo);
	}
}

/**
 * Frees the memory allocated to an ocsp location including all certinfos
 */
static void free_ocsp_location(ocsp_location_t* location)
{
	DESTROY_IF(location->issuer);
	free(location->authNameID.ptr);
	free(location->authKeyID.ptr);
	free(location->uri);
	free_certinfos(location->certinfo);
	free(location);
}

/*
 * Free a chained list of ocsp locations
 */
void free_ocsp_locations(ocsp_location_t **chain)
{
	while (*chain)
	{
		ocsp_location_t *location = *chain;
		*chain = location->next;
		free_ocsp_location(location);
	}
}

/**
 * Free the ocsp cache
 */
void free_ocsp_cache(void)
{
	lock_ocsp_cache("free_ocsp_cache");
	free_ocsp_locations(&ocsp_cache);
	unlock_ocsp_cache("free_ocsp_cache");
}

/**
 * Frees the ocsp cache and global variables
 */
void free_ocsp(void)
{
	free(ocsp_default_uri.ptr);
	free_ocsp_cache();
}

/**
 * List a chained list of ocsp_locations
 */
void list_ocsp_locations(ocsp_location_t *location, bool requests,
						 bool utc, bool strict)
{
	bool first = TRUE;

	while (location)
	{
		ocsp_certinfo_t *certinfo = location->certinfo;

		if (certinfo)
		{
			if (first)
			{
				whack_log(RC_COMMENT, " ");
				whack_log(RC_COMMENT, "List of OCSP %s:", requests ?
					"Fetch Requests" : "Responses");
				first = FALSE;
			}
			whack_log(RC_COMMENT, " ");
			if (location->issuer)
			{
				whack_log(RC_COMMENT, "  issuer:   \"%Y\"", location->issuer);
			}
			whack_log(RC_COMMENT, "  uri:      '%s'", location->uri);
			if (location->authNameID.ptr)
			{
				whack_log(RC_COMMENT, "  authname:  %#B", &location->authNameID);
			}
			if (location->authKeyID.ptr)
			{
				whack_log(RC_COMMENT, "  authkey:   %#B", &location->authKeyID);
			}
			while (certinfo)
			{
				chunk_t serial = chunk_skip_zero(certinfo->serialNumber);

				if (requests)
				{
					whack_log(RC_COMMENT, "  serial:    %#B, %d trials",
						 &serial, certinfo->trials);
				}
				else if (certinfo->once)
				{
					whack_log(RC_COMMENT, "  serial:    %#B, %s, once%s",
						&serial, cert_status_names[certinfo->status],
						(certinfo->nextUpdate < time(NULL))? " (expired)": "");
				}
				else
				{
					whack_log(RC_COMMENT, "  serial:    %#B, %s, until %T %s",
						&serial, cert_status_names[certinfo->status],
						&certinfo->nextUpdate, utc,
						check_expiry(certinfo->nextUpdate, OCSP_WARNING_INTERVAL, strict));
				}
				certinfo = certinfo->next;
			}
		}
		location = location->next;
	}
}

/**
 * List the ocsp cache
 */
void list_ocsp_cache(bool utc, bool strict)
{
	lock_ocsp_cache("list_ocsp_cache");
	list_ocsp_locations(ocsp_cache, FALSE, utc, strict);
	unlock_ocsp_cache("list_ocsp_cache");
}

static bool get_ocsp_requestor_cert(ocsp_location_t *location)
{
	cert_t *cert = NULL;

	/* initialize temporary static storage */
	ocsp_requestor_cert = NULL;
	ocsp_requestor_sc   = NULL;
	ocsp_requestor_key  = NULL;

	for (;;)
	{
		certificate_t *certificate;

		/* looking for a certificate from the same issuer */
		cert = get_x509cert(location->issuer, location->authKeyID, cert);
		if (cert == NULL)
		{
			break;
		}
		certificate = cert->cert;
		DBG(DBG_CONTROL,
			DBG_log("candidate: '%Y'", certificate->get_subject(certificate));
		)

		if (cert->smartcard)
		{
			/* look for a matching private key on a smartcard */
			smartcard_t *sc = scx_get(cert);

			if (sc)
			{
				DBG(DBG_CONTROL,
					DBG_log("matching smartcard found")
				)
				if (sc->valid)
				{
					ocsp_requestor_cert = cert;
					ocsp_requestor_sc = sc;
					return TRUE;
				}
				plog("unable to sign ocsp request without PIN");
			}
		}
		else
		{
			/* look for a matching private key in the chained list */
			private_key_t *private = get_x509_private_key(cert);

			if (private)
			{
				DBG(DBG_CONTROL,
					DBG_log("matching private key found")
				)
				ocsp_requestor_cert = cert;
				ocsp_requestor_key = private;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static chunk_t sc_build_sha1_signature(chunk_t tbs, smartcard_t *sc)
{
	hasher_t *hasher;
	u_char *pos;
	chunk_t digest;
	chunk_t digest_info, sigdata;
	size_t siglen = 0;

	if (!scx_establish_context(sc) || !scx_login(sc))
	{
		scx_release_context(sc);
		return chunk_empty;
	}

	siglen = scx_get_keylength(sc);

	if (siglen == 0)
	{
		plog("failed to get keylength from smartcard");
		scx_release_context(sc);
		return chunk_empty;
	}

	DBG(DBG_CONTROL | DBG_CRYPT,
		DBG_log("signing hash with RSA key from smartcard (slot: %d, id: %s)"
			, (int)sc->slot, sc->id)
	)

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		return chunk_empty;
	}
	hasher->allocate_hash(hasher, tbs, &digest);
	hasher->destroy(hasher);

	/* according to PKCS#1 v2.1 digest must be packaged into
	 * an ASN.1 structure for encryption
	 */
	digest_info = asn1_wrap(ASN1_SEQUENCE, "mm"
		, asn1_algorithmIdentifier(OID_SHA1)
		, asn1_wrap(ASN1_OCTET_STRING, "m", digest));

	pos = asn1_build_object(&sigdata, ASN1_BIT_STRING, 1 + siglen);
	*pos++ = 0x00;
	scx_sign_hash(sc, digest_info.ptr, digest_info.len, pos, siglen);
	free(digest_info.ptr);

	if (!pkcs11_keep_state)
	{
		scx_release_context(sc);
	}
	return sigdata;
}

/**
 * build signature into ocsp request gets built only if a request cert
 * with a corresponding private key is found
 */
static chunk_t build_signature(chunk_t tbsRequest)
{
	chunk_t sigdata, cert, certs = chunk_empty;

	if (ocsp_requestor_sc)
	{
		/* RSA signature is done on smartcard */
		sigdata = sc_build_sha1_signature(tbsRequest, ocsp_requestor_sc);
	}
	else
	{
		/* RSA signature is done in software */
		sigdata = x509_build_signature(tbsRequest, OID_SHA1, ocsp_requestor_key,
									   TRUE);
	}
	if (sigdata.ptr == NULL)
	{
		return chunk_empty;
	}

	/* include our certificate */
	if (ocsp_requestor_cert->cert->get_encoding(ocsp_requestor_cert->cert,
												CERT_ASN1_DER, &cert))
	{
		certs = asn1_wrap(ASN1_CONTEXT_C_0, "m",
					asn1_wrap(ASN1_SEQUENCE, "m", cert));
	}
	/* build signature comprising algorithm, signature and cert */
	return asn1_wrap(ASN1_CONTEXT_C_0, "m"
				, asn1_wrap(ASN1_SEQUENCE, "mmm"
					, asn1_algorithmIdentifier(OID_SHA1_WITH_RSA)
					, sigdata
					, certs
				  )
		   );
}

/**
 * Build request (into requestList)
 * no singleRequestExtensions used
 */
static chunk_t build_request(ocsp_location_t *location, ocsp_certinfo_t *certinfo)
{
	chunk_t reqCert = asn1_wrap(ASN1_SEQUENCE, "mmmm"
				, asn1_algorithmIdentifier(OID_SHA1)
				, asn1_simple_object(ASN1_OCTET_STRING, location->authNameID)
				, asn1_simple_object(ASN1_OCTET_STRING, location->authKeyID)
				, asn1_simple_object(ASN1_INTEGER, certinfo->serialNumber));

	return asn1_wrap(ASN1_SEQUENCE, "m", reqCert);
}

/**
 * build requestList (into TBSRequest)
 */
static chunk_t build_request_list(ocsp_location_t *location)
{
	chunk_t requestList;
	request_list_t *reqs = NULL;
	ocsp_certinfo_t *certinfo = location->certinfo;
	u_char *pos;

	size_t datalen = 0;

	/* build content */
	while (certinfo)
	{
		/* build request for every certificate in list
		 * and store them in a chained list
		 */
		request_list_t *req = malloc_thing(request_list_t);

		req->request = build_request(location, certinfo);
		req->next = reqs;
		reqs = req;

		datalen += req->request.len;
		certinfo = certinfo->next;
	}

	pos = asn1_build_object(&requestList, ASN1_SEQUENCE, datalen);

	/* copy all in chained list, free list afterwards */
	while (reqs)
	{
		request_list_t *req = reqs;

		mv_chunk(&pos, req->request);
		reqs = reqs->next;
		free(req);
	}

	return requestList;
}

/**
 * Build requestorName (into TBSRequest)
 */
static chunk_t build_requestor_name(void)
{
	certificate_t *certificate = ocsp_requestor_cert->cert;
	identification_t *subject = certificate->get_subject(certificate);

	return asn1_wrap(ASN1_CONTEXT_C_1, "m"
				, asn1_simple_object(ASN1_CONTEXT_C_4
					, subject->get_encoding(subject)));
}

/**
 * build nonce extension (into requestExtensions)
 */
static chunk_t build_nonce_extension(ocsp_location_t *location)
{
	rng_t *rng;

	/* generate a random nonce */
	location->nonce.ptr = malloc(NONCE_LENGTH),
	location->nonce.len = NONCE_LENGTH;
	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	rng->get_bytes(rng, location->nonce.len, location->nonce.ptr);
	rng->destroy(rng);

	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_nonce_oid
				, asn1_simple_object(ASN1_OCTET_STRING, location->nonce));
}

/**
 * Build requestExtensions (into TBSRequest)
 */
static chunk_t build_request_ext(ocsp_location_t *location)
{
	return asn1_wrap(ASN1_CONTEXT_C_2, "m"
				, asn1_wrap(ASN1_SEQUENCE, "mm"
					, build_nonce_extension(location)
					, asn1_wrap(ASN1_SEQUENCE, "cc"
						, ASN1_response_oid
						, ASN1_response_content
					  )
				  )
			);
}

/**
 * Build TBSRequest (into OCSPRequest)
 */
static chunk_t build_tbs_request(ocsp_location_t *location, bool has_requestor_cert)
{
	/* version is skipped since the default is ok */
	return asn1_wrap(ASN1_SEQUENCE, "mmm"
				, (has_requestor_cert)
						? build_requestor_name()
						: chunk_empty
				, build_request_list(location)
				, build_request_ext(location));
}

/**
 * Assembles an ocsp request to given location
 * and sets nonce field in location to the sent nonce
 */
chunk_t build_ocsp_request(ocsp_location_t *location)
{
	bool has_requestor_cert;
	chunk_t tbsRequest, signature;

	DBG(DBG_CONTROL,
		DBG_log("assembling ocsp request");
		DBG_log("issuer: \"%Y\"", location->issuer);
		if (location->authKeyID.ptr)
		{
			DBG_log("authkey: %#B", &location->authKeyID);
		}
	)
	lock_certs_and_keys("build_ocsp_request");

	/* looks for requestor cert and matching private key */
	has_requestor_cert = get_ocsp_requestor_cert(location);

	/* build content */
	tbsRequest = build_tbs_request(location, has_requestor_cert);

	/* sign tbsReuqest */
	signature = (has_requestor_cert)? build_signature(tbsRequest)
									: chunk_empty;

	unlock_certs_and_keys("build_ocsp_request");

	return asn1_wrap(ASN1_SEQUENCE, "mm"
				, tbsRequest
				, signature);
}

/**
 * Check if the OCSP response has a valid signature
 */
static bool valid_ocsp_response(response_t *res)
{
	int pathlen, pathlen_constraint;
	cert_t *authcert;

	lock_authcert_list("valid_ocsp_response");

	authcert = get_authcert(res->responder_id_name, res->responder_id_key,
							X509_OCSP_SIGNER | X509_CA);
	if (authcert == NULL)
	{
		plog("no matching ocsp signer cert found");
		unlock_authcert_list("valid_ocsp_response");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("ocsp signer cert found")
	)

	if (!x509_check_signature(res->tbs, res->signature, res->algorithm,
							  authcert->cert))
	{
		plog("signature of ocsp response is invalid");
		unlock_authcert_list("valid_ocsp_response");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("signature of ocsp response is valid")
	)


	for (pathlen = -1; pathlen <= X509_MAX_PATH_LEN; pathlen++)
	{
		cert_t *cert = authcert;
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer  = certificate->get_issuer(certificate);
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		time_t not_before, not_after;

		DBG(DBG_CONTROL,
			DBG_log("subject: '%Y'", subject);
			DBG_log("issuer:  '%Y'", issuer);
			if (authKeyID.ptr)
			{
				DBG_log("authkey:  %#B", &authKeyID);
			}
		)

		if (!certificate->get_validity(certificate, NULL, &not_before, &not_after))
		{
			plog("certificate is invalid (valid from %T to %T)",
				 &not_before, FALSE, &not_after, FALSE);

			unlock_authcert_list("valid_ocsp_response");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate is valid")
		)

		authcert = get_authcert(issuer, authKeyID, X509_CA);
		if (authcert == NULL)
		{
			plog("issuer cacert not found");
			unlock_authcert_list("valid_ocsp_response");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("issuer cacert found")
		)

		if (!certificate->issued_by(certificate, authcert->cert))
		{
			plog("certificate signature is invalid");
			unlock_authcert_list("valid_ocsp_response");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate signature is valid")
		)

		/* check path length constraint */
		pathlen_constraint = x509->get_constraint(x509, X509_PATH_LEN);
		if (pathlen_constraint != X509_NO_CONSTRAINT &&
			pathlen > pathlen_constraint)
		{
			plog("path length of %d violates constraint of %d",
				 pathlen, pathlen_constraint);
			return FALSE;
		}

		/* check if cert is self-signed */
		if (x509->get_flags(x509) & X509_SELF_SIGNED)
		{
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca with a path length of %d",
						pathlen)
			)
			unlock_authcert_list("valid_ocsp_response");
			return TRUE;
		}
	}
	plog("maximum path length of %d exceeded", X509_MAX_PATH_LEN);
	unlock_authcert_list("valid_ocsp_response");
	return FALSE;
}

/**
 * Parse a basic OCSP response
 */
static bool parse_basic_ocsp_response(chunk_t blob, int level0, response_t *res)
{
	asn1_parser_t *parser;
	chunk_t object;
	u_int version;
	int objectID;
	int extn_oid = OID_UNKNOWN;
	bool success = FALSE;
	bool critical;

	parser = asn1_parser_create(basicResponseObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
		case BASIC_RESPONSE_TBS_DATA:
			res->tbs = object;
			break;
		case BASIC_RESPONSE_VERSION:
			version = (object.len)? (1 + (u_int)*object.ptr) : 1;
			if (version != OCSP_BASIC_RESPONSE_VERSION)
			{
				plog("wrong ocsp basic response version (version= %i)",  version);
				goto end;
			}
			break;
		case BASIC_RESPONSE_ID_BY_NAME:
			res->responder_id_name = identification_create_from_encoding(
										ID_DER_ASN1_DN, object);
			DBG(DBG_PARSING,
				DBG_log("  '%Y'", res->responder_id_name)
			)
			break;
		case BASIC_RESPONSE_ID_BY_KEY:
			res->responder_id_key = object;
			break;
		case BASIC_RESPONSE_PRODUCED_AT:
			res->produced_at = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
			break;
		case BASIC_RESPONSE_RESPONSES:
			res->responses = object;
			break;
		case BASIC_RESPONSE_EXT_ID:
			extn_oid = asn1_known_oid(object);
			break;
		case BASIC_RESPONSE_CRITICAL:
			critical = object.len && *object.ptr;
			DBG(DBG_PARSING,
				DBG_log("  %s",(critical)?"TRUE":"FALSE");
			)
			break;
		case BASIC_RESPONSE_EXT_VALUE:
			if (extn_oid == OID_NONCE)
				res->nonce = object;
			break;
		case BASIC_RESPONSE_ALGORITHM:
			res->algorithm = asn1_parse_algorithmIdentifier(object,
								parser->get_level(parser)+1, NULL);
			break;
		case BASIC_RESPONSE_SIGNATURE:
			res->signature = object;
			break;
		case BASIC_RESPONSE_CERTIFICATE:
			{
				cert_t *cert = malloc_thing(cert_t);
				x509_t *x509;

				*cert = cert_empty;
				cert->cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509,
										  BUILD_BLOB_ASN1_DER, object,
										  BUILD_END);
				if (cert->cert == NULL)
				{
					DBG(DBG_CONTROL | DBG_PARSING,
						DBG_log("parsing of embedded ocsp certificate failed")
					)
					cert_free(cert);
					break;
				}
				x509 = (x509_t*)cert->cert;

				if ((x509->get_flags(x509) & X509_OCSP_SIGNER) &&
					trust_authcert_candidate(cert, NULL))
				{
					add_authcert(cert, X509_OCSP_SIGNER);
				}
				else
				{
					DBG(DBG_CONTROL | DBG_PARSING,
						DBG_log("embedded ocsp certificate rejected")
					)
					cert_free(cert);
				}
			}
			break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;

}


/**
 * Parse an ocsp response and return the result as a response_t struct
 */
static response_status parse_ocsp_response(chunk_t blob, response_t * res)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int ocspResponseType = OID_UNKNOWN;
	bool success = FALSE;
	response_status rStatus = STATUS_INTERNALERROR;

	parser = asn1_parser_create(ocspResponseObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID) {
		case OCSP_RESPONSE_STATUS:
			rStatus = (response_status) *object.ptr;

			switch (rStatus)
			{
			case STATUS_SUCCESSFUL:
				break;
			case STATUS_MALFORMEDREQUEST:
			case STATUS_INTERNALERROR:
			case STATUS_TRYLATER:
			case STATUS_SIGREQUIRED:
			case STATUS_UNAUTHORIZED:
				plog("ocsp response: server said '%s'"
					, response_status_names[rStatus]);
				goto end;
			default:
				goto end;
			}
			break;
		case OCSP_RESPONSE_TYPE:
			ocspResponseType = asn1_known_oid(object);
			break;
		case OCSP_RESPONSE:
			{
				switch (ocspResponseType) {
				case OID_BASIC:
					success = parse_basic_ocsp_response(object,
									parser->get_level(parser)+1, res);
					break;
				default:
					DBG(DBG_CONTROL,
						DBG_log("ocsp response is not of type BASIC");
						DBG_dump_chunk("ocsp response OID: ", object);
					)
					goto end;
				}
			}
			break;
		}
	}
	success &= parser->success(parser);

end:
	parser->destroy(parser);
	return rStatus;
}

/**
 * Parse a basic OCSP response
 */
static bool parse_ocsp_single_response(chunk_t blob, int level0,
									   single_response_t *sres)
{
	asn1_parser_t *parser;
	chunk_t object;
	u_int extn_oid;
	int objectID;
	bool critical;
	bool success = FALSE;

	parser = asn1_parser_create(singleResponseObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
		case SINGLE_RESPONSE_ALGORITHM:
			sres->hash_algorithm = asn1_parse_algorithmIdentifier(object,
										parser->get_level(parser)+1, NULL);
			break;
		case SINGLE_RESPONSE_ISSUER_NAME_HASH:
			sres->issuer_name_hash = object;
			break;
		case SINGLE_RESPONSE_ISSUER_KEY_HASH:
			sres->issuer_key_hash = object;
			break;
		case SINGLE_RESPONSE_SERIAL_NUMBER:
			sres->serialNumber = object;
			break;
		case SINGLE_RESPONSE_CERT_STATUS_GOOD:
			sres->status = CERT_GOOD;
			break;
		case SINGLE_RESPONSE_CERT_STATUS_REVOKED:
			sres->status = CERT_REVOKED;
			break;
		case SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME:
			sres->revocationTime = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
			break;
		case SINGLE_RESPONSE_CERT_STATUS_CRL_REASON:
			sres->revocationReason = (object.len == 1)
				? *object.ptr : CRL_REASON_UNSPECIFIED;
			break;
		case SINGLE_RESPONSE_CERT_STATUS_UNKNOWN:
			sres->status = CERT_UNKNOWN;
			break;
		case SINGLE_RESPONSE_THIS_UPDATE:
			sres->thisUpdate = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
			break;
		case SINGLE_RESPONSE_NEXT_UPDATE:
			sres->nextUpdate = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
			break;
		case SINGLE_RESPONSE_EXT_ID:
			extn_oid = asn1_known_oid(object);
			break;
		case SINGLE_RESPONSE_CRITICAL:
			critical = object.len && *object.ptr;
			DBG(DBG_PARSING,
				DBG_log("  %s",(critical)?"TRUE":"FALSE");
			)
		case SINGLE_RESPONSE_EXT_VALUE:
			break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	return success;
}

/**
 * Add an ocsp location to a chained list
 */
ocsp_location_t* add_ocsp_location(const ocsp_location_t *loc,
								   ocsp_location_t **chain)
{
	ocsp_location_t *location = malloc_thing(ocsp_location_t);

	/* unshare location fields */
	location->issuer = loc->issuer->clone(loc->issuer);
	location->authNameID = chunk_clone(loc->authNameID);
	location->authKeyID = chunk_clone(loc->authKeyID);
	location->uri = strdup(loc->uri);
	location->certinfo = NULL;

	/* insert new ocsp location in front of chain */
	location->next = *chain;
	*chain = location;

	DBG(DBG_CONTROL,
		DBG_log("new ocsp location added")
	)

	return location;
}

/**
 * add a certinfo struct to a chained list
 */
void add_certinfo(ocsp_location_t *loc, ocsp_certinfo_t *info,
				  ocsp_location_t **chain, bool request)
{
	ocsp_location_t *location;
	ocsp_certinfo_t *certinfo, **certinfop;
	char buf[BUF_LEN];
	time_t now;
	int cmp = -1;

	location = get_ocsp_location(loc, *chain);
	if (location == NULL)
	{
		location = add_ocsp_location(loc, chain);
	}

	/* traverse list of certinfos in increasing order */
	certinfop = &location->certinfo;
	certinfo = *certinfop;

	while (certinfo)
	{
		cmp = chunk_compare(info->serialNumber, certinfo->serialNumber);
		if (cmp <= 0)
			break;
		certinfop = &certinfo->next;
		certinfo = *certinfop;
	}

	if (cmp != 0)
	{
		/* add a new certinfo entry */
		ocsp_certinfo_t *cnew = malloc_thing(ocsp_certinfo_t);

		cnew->serialNumber = chunk_clone(info->serialNumber);
		cnew->next = certinfo;
		cnew->trials = 0;
		*certinfop = cnew;
		certinfo = cnew;
	}

	DBG(DBG_CONTROL,
		datatot(info->serialNumber.ptr, info->serialNumber.len, ':'
			, buf, BUF_LEN);
		DBG_log("ocsp %s for serial %s %s"
			, request?"fetch request":"certinfo"
			, buf
			, (cmp == 0)? (request?"already exists":"updated"):"added")
	)

	time(&now);

	if (request)
	{
		certinfo->status = CERT_UNDEFINED;

		if (cmp != 0)
		{
			certinfo->thisUpdate = now;
		}
		certinfo->nextUpdate = UNDEFINED_TIME;
	}
	else
	{
		certinfo->status = info->status;
		certinfo->revocationTime = info->revocationTime;
		certinfo->revocationReason = info->revocationReason;

		certinfo->thisUpdate = (info->thisUpdate != UNDEFINED_TIME)?
			info->thisUpdate : now;

		certinfo->once = (info->nextUpdate == UNDEFINED_TIME);

		certinfo->nextUpdate = (certinfo->once)?
			(now + OCSP_DEFAULT_VALID_TIME) : info->nextUpdate;
	}
}

/**
 * Process received ocsp single response and add it to ocsp cache
 */
static void process_single_response(ocsp_location_t *location,
									single_response_t *sres)
{
	ocsp_certinfo_t *certinfo, **certinfop;
	int cmp = -1;

	if (sres->hash_algorithm != OID_SHA1)
	{
		plog("only SHA-1 hash supported in OCSP single response");
		return;
	}
	if (!(chunk_equals(sres->issuer_name_hash, location->authNameID)
	&&   chunk_equals(sres->issuer_key_hash, location->authKeyID)))
	{
		plog("ocsp single response has wrong issuer");
		return;
	}

	/* traverse list of certinfos in increasing order */
	certinfop = &location->certinfo;
	certinfo = *certinfop;

	while (certinfo)
	{
		cmp = chunk_compare(sres->serialNumber, certinfo->serialNumber);
		if (cmp <= 0)
			break;
		certinfop = &certinfo->next;
		certinfo = *certinfop;
	}

	if (cmp != 0)
	{
		plog("received unrequested cert status from ocsp server");
		return;
	}

	/* unlink cert from ocsp fetch request list */
	*certinfop = certinfo->next;

	/* update certinfo using the single response information */
	certinfo->thisUpdate = sres->thisUpdate;
	certinfo->nextUpdate = sres->nextUpdate;
	certinfo->status = sres->status;
	certinfo->revocationTime = sres->revocationTime;
	certinfo->revocationReason = sres->revocationReason;

	/* add or update certinfo in ocsp cache */
	lock_ocsp_cache("process_single_response");
	add_certinfo(location, certinfo, &ocsp_cache, FALSE);
	unlock_ocsp_cache("process_single_response");

	/* free certinfo unlinked from ocsp fetch request list */
	free_certinfo(certinfo);
}

/**
 *  Destroy a response_t object
 */
static void free_response(response_t *res)
{
	DESTROY_IF(res->responder_id_name);
}

/**
 *  Parse and verify ocsp response and update the ocsp cache
 */
void parse_ocsp(ocsp_location_t *location, chunk_t blob)
{
	response_t res = empty_response;

	/* parse the ocsp response without looking at the single responses yet */
	response_status status = parse_ocsp_response(blob, &res);

	if (status != STATUS_SUCCESSFUL)
	{
		plog("error in ocsp response");
		goto free;
	}
	/* check if there was a nonce in the request */
	if (location->nonce.ptr && res.nonce.ptr == NULL)
	{
		plog("ocsp response contains no nonce, replay attack possible");
	}
	/* check if the nonce is identical */
	if (res.nonce.ptr && !chunk_equals(res.nonce, location->nonce))
	{
		plog("invalid nonce in ocsp response");
		goto free;
	}
	/* check if the response is signed by a trusted key */
	if (!valid_ocsp_response(&res))
	{
		plog("invalid ocsp response");
		goto free;
	}
	DBG(DBG_CONTROL,
		DBG_log("valid ocsp response")
	)

	/* now parse the single responses one at a time */
	{
		asn1_parser_t *parser;
		chunk_t object;
		int objectID;

		parser = asn1_parser_create(responsesObjects, res.responses);

		while (parser->iterate(parser, &objectID, &object))
		{
			if (objectID == RESPONSES_SINGLE_RESPONSE)
			{
				single_response_t sres = empty_single_response;

				if (!parse_ocsp_single_response(object,
										parser->get_level(parser)+1, &sres))
				{
					goto end;
				}
				process_single_response(location, &sres);
			}
		}
end:
		parser->destroy(parser);
	}

free:
	free_response(&res);
}
