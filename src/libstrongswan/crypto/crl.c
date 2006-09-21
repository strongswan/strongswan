/**
 * @file crl.c
 * 
 * @brief Implementation of crl_t.
 * 
 */

/*
 * Copyright (C) 2006 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
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

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <types.h>
#include <definitions.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/pem.h>
#include <utils/logger_manager.h>
#include <utils/linked_list.h>
#include <utils/identification.h>

#include "certinfo.h"
#include "x509.h"
#include "crl.h"

#define CRL_WARNING_INTERVAL	7	/* days */

static logger_t *logger;
extern char* check_expiry(time_t expiration_date, int warning_interval, bool strict);
extern time_t parse_time(chunk_t blob, int level0);
extern void parse_authorityKeyIdentifier(chunk_t blob, int level0 , chunk_t *authKeyID, chunk_t *authKeySerialNumber);

/* access structure for a revoked certificate */

typedef struct revokedCert_t revokedCert_t;

struct revokedCert_t {
	chunk_t       userCertificate;
	time_t	      revocationDate;
	crl_reason_t  revocationReason;
};

typedef struct private_crl_t private_crl_t;

/**
 * Private data of a crl_t object.
 */
struct private_crl_t {
	/**
	 * Public interface for this crl.
	 */
	crl_t public;
	
	/**
	 * Time when crl was installed
	 */
	time_t installed;

	/**
	 * List of crlDistributionPoints
	 */
	linked_list_t *crlDistributionPoints;

	/**
	 * X.509 crl in DER format
	 */
	chunk_t certificateList;

	/**
	 * X.509 crl body over which signature is computed
	 */
	chunk_t tbsCertList;

	/**
	 * Version of the X.509 crl
	 */
	u_int version;
	
	/**
	 * Signature algorithm
	 */
	int sigAlg;
	
	/**
	 * ID representing the crl issuer
	 */
	identification_t *issuer;
	
	/**
	 * Time when the crl was generated
	 */
	time_t thisUpdate;

	/**
	 * Time when an update crl will be available
	 */
	time_t nextUpdate;

	/**
	 * List of identification_t's representing subjectAltNames
	 */
	linked_list_t *revokedCertificates;
	
	/**
	 * Authority Key Identifier
	 */
	chunk_t authKeyID;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;
	
	/**
	 * Signature algorithm (must be identical to sigAlg)
	 */
	int algorithm;
	
	/**
	 * Signature
	 */
	chunk_t signature;
};

/**
  * ASN.1 definition of an X.509 certificate revocation list
 */
static const asn1Object_t crlObjects[] = {
	{ 0, "certificateList",				ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
	{ 1,   "tbsCertList",				ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
	{ 2,     "version",					ASN1_INTEGER,      ASN1_OPT |
														   ASN1_BODY }, /*  2 */
	{ 2,     "end opt",					ASN1_EOC,          ASN1_END  }, /*  3 */
	{ 2,     "signature",				ASN1_EOC,          ASN1_RAW  }, /*  4 */	
	{ 2,     "issuer",					ASN1_SEQUENCE,     ASN1_OBJ  }, /*  5 */
	{ 2,     "thisUpdate",				ASN1_EOC,          ASN1_RAW  }, /*  6 */
	{ 2,     "nextUpdate",				ASN1_EOC,          ASN1_RAW  }, /*  7 */
	{ 2,     "revokedCertificates",		ASN1_SEQUENCE,     ASN1_OPT |
														   ASN1_LOOP }, /*  8 */
	{ 3,       "certList",				ASN1_SEQUENCE,     ASN1_NONE }, /*  9 */
	{ 4,         "userCertificate",		ASN1_INTEGER,      ASN1_BODY }, /* 10 */
	{ 4,         "revocationDate",		ASN1_EOC,          ASN1_RAW  }, /* 11 */
	{ 4,         "crlEntryExtensions",  ASN1_SEQUENCE,     ASN1_OPT |
							   							   ASN1_LOOP }, /* 12 */
	{ 5,           "extension",			ASN1_SEQUENCE,	   ASN1_NONE }, /* 13 */
	{ 6,             "extnID",			ASN1_OID,          ASN1_BODY }, /* 14 */
	{ 6,             "critical",		ASN1_BOOLEAN,      ASN1_DEF |
														   ASN1_BODY }, /* 15 */
	{ 6,             "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 16 */
	{ 4,         "end opt or loop",		ASN1_EOC,          ASN1_END  }, /* 17 */
	{ 2,     "end opt or loop",			ASN1_EOC,          ASN1_END  }, /* 18 */
	{ 2,     "optional extensions",		ASN1_CONTEXT_C_0,  ASN1_OPT  }, /* 19 */
	{ 3,       "crlExtensions",			ASN1_SEQUENCE,     ASN1_LOOP }, /* 20 */
	{ 4,         "extension",			ASN1_SEQUENCE,     ASN1_NONE }, /* 21 */
	{ 5,           "extnID",			ASN1_OID,          ASN1_BODY }, /* 22 */
	{ 5,           "critical",			ASN1_BOOLEAN,      ASN1_DEF |
														   ASN1_BODY }, /* 23 */
	{ 5,           "extnValue",			ASN1_OCTET_STRING, ASN1_BODY }, /* 24 */
	{ 3,       "end loop",				ASN1_EOC,          ASN1_END  }, /* 25 */
	{ 2,     "end opt",					ASN1_EOC,          ASN1_END  }, /* 26 */
	{ 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 27 */
	{ 1,   "signatureValue",			ASN1_BIT_STRING,   ASN1_BODY }  /* 28 */
 };

#define CRL_OBJ_CERTIFICATE_LIST		 0
#define CRL_OBJ_TBS_CERT_LIST			 1
#define CRL_OBJ_VERSION					 2
#define CRL_OBJ_SIG_ALG					 4
#define CRL_OBJ_ISSUER					 5
#define CRL_OBJ_THIS_UPDATE				 6
#define CRL_OBJ_NEXT_UPDATE				 7
#define CRL_OBJ_USER_CERTIFICATE		10
#define CRL_OBJ_REVOCATION_DATE			11
#define CRL_OBJ_CRL_ENTRY_EXTN_ID		14
#define CRL_OBJ_CRL_ENTRY_CRITICAL		15
#define CRL_OBJ_CRL_ENTRY_EXTN_VALUE	16
#define CRL_OBJ_EXTN_ID					22
#define CRL_OBJ_CRITICAL				23
#define CRL_OBJ_EXTN_VALUE				24
#define CRL_OBJ_ALGORITHM				27
#define CRL_OBJ_SIGNATURE				28
#define CRL_OBJ_ROOF					29

/**
 * Parses a CRL revocation reason code
 */
static crl_reason_t parse_crl_reasonCode(chunk_t object)
{
	crl_reason_t reason = REASON_UNSPECIFIED;

	if (*object.ptr == ASN1_ENUMERATED && asn1_length(&object) == 1)
	{
		reason = *object.ptr;
	}
	logger->log(logger, CONTROL|LEVEL2, "  '%s'", enum_name(&crl_reason_names, reason));

    return reason;
}

/**
 *  Parses an X.509 Certificate Revocation List (CRL)
 */
bool parse_x509crl(chunk_t blob, u_int level0, private_crl_t *crl)
{
	asn1_ctx_t ctx;
	bool critical;
	chunk_t extnID;
	chunk_t userCertificate;
	revokedCert_t *revokedCert = NULL;
	chunk_t object;
	u_int level;
	int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE);

	while (objectID < CRL_OBJ_ROOF)
	{
		if (!extract_object(crlObjects, &objectID, &object, &level, &ctx))
			return FALSE;

		/* those objects which will parsed further need the next higher level */
		level++;

		switch (objectID)
		{
			case CRL_OBJ_CERTIFICATE_LIST:
			crl->certificateList = object;
				break;
			case CRL_OBJ_TBS_CERT_LIST:
				crl->tbsCertList = object;
				break;
			case CRL_OBJ_VERSION:
				crl->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
				logger->log(logger, CONTROL|LEVEL2, "  v%d", crl->version);
				break;
			case CRL_OBJ_SIG_ALG:
				crl->sigAlg = parse_algorithmIdentifier(object, level, NULL);
				break;
			case CRL_OBJ_ISSUER:
				crl->issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				logger->log(logger, CONTROL|LEVEL1, "  '%s'", crl->issuer->get_string(crl->issuer));
				break;
			case CRL_OBJ_THIS_UPDATE:
				crl->thisUpdate = parse_time(object, level);
				break;
			case CRL_OBJ_NEXT_UPDATE:
				crl->nextUpdate = parse_time(object, level);
				break;
			case CRL_OBJ_USER_CERTIFICATE:
				userCertificate = object;
				break;
			case CRL_OBJ_REVOCATION_DATE:
				revokedCert = malloc_thing(revokedCert_t);
				revokedCert->userCertificate = userCertificate;
				revokedCert->revocationDate = parse_time(object, level);
				revokedCert->revocationReason = REASON_UNSPECIFIED;
				crl->revokedCertificates->insert_last(crl->revokedCertificates, (void *)revokedCert);
				break;
			case CRL_OBJ_CRL_ENTRY_EXTN_ID:
			case CRL_OBJ_EXTN_ID:
				extnID = object;
				break;
			case CRL_OBJ_CRL_ENTRY_CRITICAL:
			case CRL_OBJ_CRITICAL:
				critical = object.len && *object.ptr;
				logger->log(logger, CONTROL|LEVEL2, "  %s",(critical)?"TRUE":"FALSE");
				break;
			case CRL_OBJ_CRL_ENTRY_EXTN_VALUE:
			case CRL_OBJ_EXTN_VALUE:
				{
					int extn_oid = known_oid(extnID);

					if (revokedCert && extn_oid == OID_CRL_REASON_CODE)
					{
						revokedCert->revocationReason = parse_crl_reasonCode(object);
					}
					else if (extn_oid == OID_AUTHORITY_KEY_ID)
					{
						parse_authorityKeyIdentifier(object, level, &crl->authKeyID, &crl->authKeySerialNumber);
					}
				}
				break;
			case CRL_OBJ_ALGORITHM:
				crl->algorithm = parse_algorithmIdentifier(object, level, NULL);
				break;
			case CRL_OBJ_SIGNATURE:
				crl->signature = object;
				break;
			default:
				break;
		}
		objectID++;
	}
	time(&crl->installed);
	return TRUE;
}

/**
 * Implements crl_t.is_valid
 */
static err_t is_valid(const private_crl_t *this, time_t *until, bool strict)
{
	char buf[TIMETOA_BUF];

	time_t current_time = time(NULL);
	
	timetoa(buf, BUF_LEN, &this->thisUpdate, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  this update : %s", buf);
	timetoa(buf, BUF_LEN, &current_time, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  current time: %s", buf);
	timetoa(buf, BUF_LEN, &this->nextUpdate, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  next update:  %s", buf);

	if (strict && until != NULL
	&& (*until == UNDEFINED_TIME || this->nextUpdate < *until)) 
	{
		*until = this->nextUpdate;
	}
	if (current_time > this->nextUpdate)
		return "has expired";
	logger->log(logger, CONTROL|LEVEL1, "  crl is valid", buf);
	return NULL;
}

/**
 * Implements crl_t.get_issuer
 */
static identification_t *get_issuer(const private_crl_t *this)
{
	return this->issuer;
}

/**
 * Implements crl_t.equals_issuer
 */
static bool equals_issuer(const private_crl_t *this, const private_crl_t *other)
{
	return (this->authKeyID.ptr)
			? chunk_equals(this->authKeyID, other->authKeyID)
			: (this->issuer->equals(this->issuer, other->issuer)
			   && chunk_equals_or_null(this->authKeySerialNumber, other->authKeySerialNumber));
}

/**
 * Implements crl_t.is_issuer
 */
static bool is_issuer(const private_crl_t *this, const x509_t *issuer)
{
	return (this->authKeyID.ptr)
			? chunk_equals(this->authKeyID, issuer->get_subjectKeyID(issuer))
			: (this->issuer->equals(this->issuer, issuer->get_subject(issuer))
			   && chunk_equals_or_null(this->authKeySerialNumber, issuer->get_serialNumber(issuer)));
}

/**
 * Implements crl_t.is_newer
 */
static bool is_newer(const private_crl_t *this, const private_crl_t *other)
{
	return (this->nextUpdate > other->nextUpdate);
}

/**
 * Implements crl_t.verify
 */
static bool verify(const private_crl_t *this, const rsa_public_key_t *signer)
{
	return signer->verify_emsa_pkcs1_signature(signer, this->tbsCertList, this->signature) == SUCCESS;
}

/**
 * Implements crl_t.get_status
 */
static void get_status(const private_crl_t *this, certinfo_t *certinfo)
{
	chunk_t serialNumber = certinfo->get_serialNumber(certinfo);
	iterator_t *iterator = this->revokedCertificates->create_iterator(this->revokedCertificates, TRUE);

	certinfo->set_nextUpdate(certinfo, this->nextUpdate);
	certinfo->set_status(certinfo, CERT_GOOD);

	while (iterator->has_next(iterator))
	{
		revokedCert_t *revokedCert;

		iterator->current(iterator, (void**)&revokedCert);
		if (chunk_equals(serialNumber, revokedCert->userCertificate))
		{
			certinfo->set_status(certinfo, CERT_REVOKED);
			certinfo->set_revocationTime(certinfo, revokedCert->revocationDate);
			certinfo->set_revocationReason(certinfo, revokedCert->revocationReason);
			break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implements crl_t.destroy
 */
static void destroy(private_crl_t *this)
{
	revokedCert_t *revokedCert;
	identification_t *id;

   while (this->revokedCertificates->remove_last(this->revokedCertificates, (void**)&revokedCert) == SUCCESS)
	{
		free(revokedCert);
	}
	this->revokedCertificates->destroy(this->revokedCertificates);

	while (this->crlDistributionPoints->remove_last(this->crlDistributionPoints, (void**)&id) == SUCCESS)
	{
		id->destroy(id);
	}
	this->crlDistributionPoints->destroy(this->crlDistributionPoints);

	if (this->issuer)
		this->issuer->destroy(this->issuer);

	free(this->certificateList.ptr);
	free(this);
}

/**
 * log crl
 */
static void log_crl(const private_crl_t *this, logger_t *logger, bool utc, bool strict)
{
	identification_t *issuer = this->issuer;
	linked_list_t *revokedCertificates   = this->revokedCertificates;

	char buf[BUF_LEN];

	timetoa(buf, BUF_LEN, &this->installed, utc);
	logger->log(logger, CONTROL, "%s, revoked certs: %d",
			buf, revokedCertificates->get_count(revokedCertificates));

	logger->log(logger, CONTROL, "       issuer:  '%s'", issuer->get_string(issuer));
	
	timetoa(buf, BUF_LEN, &this->thisUpdate, utc);
	logger->log(logger, CONTROL, "       updates:  this %s", buf);
	
	timetoa(buf, BUF_LEN, &this->nextUpdate, utc);
	logger->log(logger, CONTROL, "                 next %s %s", buf,
			check_expiry(this->nextUpdate, CRL_WARNING_INTERVAL, strict));

	if (this->authKeyID.ptr != NULL)
	{
		chunk_to_hex(buf, BUF_LEN, this->authKeyID);
		logger->log(logger, CONTROL, "       authkey:  %s", buf);
	}
	if (this->authKeySerialNumber.ptr != NULL)
	{
		chunk_to_hex(buf, BUF_LEN, this->authKeySerialNumber);
		logger->log(logger, CONTROL, "       aserial:  %s", buf);
	}
}

/*
 * Described in header.
 */
crl_t *crl_create_from_chunk(chunk_t chunk)
{
	private_crl_t *this = malloc_thing(private_crl_t);
	
	/* initialize */
	this->crlDistributionPoints = linked_list_create();
	this->tbsCertList = CHUNK_INITIALIZER;
	this->issuer = NULL;
	this->revokedCertificates = linked_list_create();
	this->authKeyID = CHUNK_INITIALIZER;
	this->authKeySerialNumber = CHUNK_INITIALIZER;
	
	/* public functions */
	this->public.get_issuer = (identification_t* (*) (const crl_t*))get_issuer;
	this->public.equals_issuer = (bool (*) (const crl_t*,const crl_t*))equals_issuer;
	this->public.is_issuer = (bool (*) (const crl_t*,const x509_t*))is_issuer;
	this->public.is_valid = (err_t (*) (const crl_t*,time_t*,bool))is_valid;
	this->public.is_newer = (bool (*) (const crl_t*,const crl_t*))is_newer;
	this->public.verify = (bool (*) (const crl_t*,const rsa_public_key_t*))verify;
	this->public.get_status = (void (*) (const crl_t*,certinfo_t*))get_status;
	this->public.log_crl = (void (*) (const crl_t*,logger_t*,bool,bool))log_crl;
	this->public.destroy = (void (*) (crl_t*))destroy;

	/* we do not use a per-instance logger right now, since its not always accessible */
	logger = logger_manager->get_logger(logger_manager, ASN1);
	
	if (!parse_x509crl(chunk, 0, this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/*
 * Described in header.
 */
crl_t *crl_create_from_file(const char *filename)
{
	bool pgp = FALSE;
	chunk_t chunk = CHUNK_INITIALIZER;
	crl_t *crl = NULL;

	if (!pem_asn1_load_file(filename, NULL, "crl", &chunk, &pgp))
		return NULL;

	crl = crl_create_from_chunk(chunk);

	if (crl == NULL)
		free(chunk.ptr);
	return crl;
}
