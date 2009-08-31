/* Support of X.509 certificate revocation lists (CRLs)
 * Copyright (C) 2000-2009 Andreas Steffen
 *
 * HSR Hochschule fuer Technik Rapperswil
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/hashers/hasher.h>
#include <credentials/certificates/certificate.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "keys.h"
#include "whack.h"
#include "fetch.h"
#include "builder.h"


/* chained lists of X.509 crls */

static x509crl_t  *x509crls      = NULL;

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
	{ 1,   "signatureValue",			ASN1_BIT_STRING,   ASN1_BODY }, /* 28 */
	{ 0, "exit",						ASN1_EOC,		   ASN1_EXIT }
};

#define CRL_OBJ_CERTIFICATE_LIST         0
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

const x509crl_t empty_x509crl = {
	  NULL        , /* *next */
	UNDEFINED_TIME, /* installed */
	  NULL        , /* distributionPoints */
	{ NULL, 0 }   , /* certificateList */
	{ NULL, 0 }   , /*   tbsCertList */
			1     , /*     version */
	OID_UNKNOWN   , /*     sigAlg */
	{ NULL, 0 }   , /*     issuer */
	UNDEFINED_TIME, /*     thisUpdate */
	UNDEFINED_TIME, /*     nextUpdate */
	  NULL        , /*     revokedCertificates */
					/*     crlExtensions */
					/*       extension */
					/*         extnID */
					/*         critical */
					/*         extnValue */
	{ NULL, 0 }   , /*           authKeyID */
	{ NULL, 0 }   , /*           authKeySerialNumber */
	{ NULL, 0 }   , /*           crlNumber */
	OID_UNKNOWN   , /*   algorithm */
	{ NULL, 0 }     /*   signature */
};

/**
 *  Get the X.509 CRL with a given issuer
 */
static x509crl_t* get_x509crl(chunk_t issuer, chunk_t serial, chunk_t keyid)
{
	x509crl_t *crl = x509crls;
	x509crl_t *prev_crl = NULL;

	while (crl != NULL)
	{
		if ((keyid.ptr != NULL && crl->authKeyID.ptr != NULL)
		? same_keyid(keyid, crl->authKeyID)
		: (same_dn(crl->issuer, issuer) && same_serial(serial, crl->authKeySerialNumber)))
		{
			if (crl != x509crls)
			{
				/* bring the CRL up front */
				prev_crl->next = crl->next;
				crl->next = x509crls;
				x509crls = crl;
			}
			return crl;
		}
		prev_crl = crl;
		crl = crl->next;
	}
	return NULL;
}

/**
 *  Free the dynamic memory used to store revoked certificates
 */
static void free_revoked_certs(revokedCert_t* revokedCerts)
{
	while (revokedCerts != NULL)
	{
		revokedCert_t * revokedCert = revokedCerts;
		revokedCerts = revokedCert->next;
		free(revokedCert);
	}
}

/**
 *  Free the dynamic memory used to store CRLs
 */
void free_crl(x509crl_t *crl)
{
	free_revoked_certs(crl->revokedCertificates);
	free_generalNames(crl->distributionPoints, TRUE);
	free(crl->certificateList.ptr);
	free(crl);
}

static void free_first_crl(void)
{
	x509crl_t *crl = x509crls;

	x509crls = crl->next;
	free_crl(crl);
}

void free_crls(void)
{
	lock_crl_list("free_crls");

	while (x509crls != NULL)
		free_first_crl();

	unlock_crl_list("free_crls");
}

/**
 * Insert X.509 CRL into chained list
 */
bool insert_crl(x509crl_t *crl, chunk_t crl_uri, bool cache_crl)
{
	x509cert_t *issuer_cert;
	x509crl_t *oldcrl;
	bool valid_sig;
	generalName_t *gn;

	/* add distribution point */
	gn = malloc_thing(generalName_t);
	gn->kind = GN_URI;
	gn->name = crl_uri;
	gn->next = crl->distributionPoints;
	crl->distributionPoints = gn;

	lock_authcert_list("insert_crl");
	/* get the issuer cacert */
	issuer_cert = get_authcert(crl->issuer, crl->authKeySerialNumber,
		crl->authKeyID, AUTH_CA);
	if (issuer_cert == NULL)
	{
		plog("crl issuer cacert not found");
		free_crl(crl);
		unlock_authcert_list("insert_crl");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("crl issuer cacert found")
	)

	/* check the issuer's signature of the crl */
	valid_sig = x509_check_signature(crl->tbsCertList, crl->signature,
									 crl->algorithm, issuer_cert);
	unlock_authcert_list("insert_crl");

	if (!valid_sig)
	{
		free_crl(crl);
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("crl signature is valid")
	)

	lock_crl_list("insert_crl");
	oldcrl = get_x509crl(crl->issuer, crl->authKeySerialNumber
		, crl->authKeyID);

	if (oldcrl != NULL)
	{
		if (crl->thisUpdate > oldcrl->thisUpdate)
		{
			/* keep any known CRL distribution points */
			add_distribution_points(oldcrl->distributionPoints
				, &crl->distributionPoints);

			/* now delete the old CRL */
			free_first_crl();
			DBG(DBG_CONTROL,
				DBG_log("thisUpdate is newer - existing crl deleted")
			)
		}
		else
		{
			unlock_crl_list("insert_crls");
			DBG(DBG_CONTROL,
				DBG_log("thisUpdate is not newer - existing crl not replaced");
			)
			free_crl(crl);
			return oldcrl->nextUpdate - time(NULL) > 2*crl_check_interval;
		}
	}

	/* insert new CRL */
	crl->next = x509crls;
	x509crls = crl;

	unlock_crl_list("insert_crl");

	/* If crl caching is enabled then the crl is saved locally.
	 * Only http or ldap URIs are cached but not local file URIs.
	 * The issuer's subjectKeyID is used as a unique filename
	 */
	if (cache_crl && strncasecmp(crl_uri.ptr, "file", 4) != 0)
	{
		char path[BUF_LEN], buf[BUF_LEN];
		char digest_buf[HASH_SIZE_SHA1];
		chunk_t subjectKeyID = chunk_from_buf(digest_buf);
		bool has_keyID;
		
		if (issuer_cert->subjectKeyID.ptr == NULL)
		{
			has_keyID = compute_subjectKeyID(issuer_cert, subjectKeyID);
		}
		else
		{
			subjectKeyID = issuer_cert->subjectKeyID;
			has_keyID = TRUE;
		}
		if (has_keyID)
		{
			datatot(subjectKeyID.ptr, subjectKeyID.len, 16, buf, BUF_LEN);
			snprintf(path, BUF_LEN, "%s/%s.crl", CRL_PATH, buf);
			chunk_write(crl->certificateList, path, "crl",  0022, TRUE);
		}
	}

	/* is the fetched crl valid? */
	return crl->nextUpdate - time(NULL) > 2*crl_check_interval;
}

/**
 *  Loads CRLs
 */
void load_crls(void)
{
	struct dirent **filelist;
	u_char buf[BUF_LEN];
	u_char *save_dir;
	int n;

	/* change directory to specified path */
	save_dir = getcwd(buf, BUF_LEN);
	if (chdir(CRL_PATH))
	{
		plog("Could not change to directory '%s'", CRL_PATH);
	}
	else
	{
		plog("Changing to directory '%s'", CRL_PATH);
		n = scandir(CRL_PATH, &filelist, file_select, alphasort);

		if (n < 0)
			plog("  scandir() error");
		else
		{
			while (n--)
			{
				char *filename = filelist[n]->d_name;
				x509crl_t *crl;
				
				crl = lib->creds->create(lib->creds, CRED_CERTIFICATE,
						CERT_PLUTO_CRL, BUILD_FROM_FILE, filename, BUILD_END);
				if (crl)
				{
					chunk_t crl_uri;

					plog("  loaded crl from '%s'", filename);
					crl_uri.len = 7 + sizeof(CRL_PATH) + strlen(filename);
					crl_uri.ptr = malloc(crl_uri.len + 1);

					/* build CRL file URI */
					snprintf(crl_uri.ptr, crl_uri.len + 1, "file://%s/%s"
						, CRL_PATH, filename);

					insert_crl(crl, crl_uri, FALSE);
				}
				free(filelist[n]);
			}
			free(filelist);
		}
	}
	/* restore directory path */
	ignore_result(chdir(save_dir));
}

/**
 * Parses a CRL revocation reason code
 */
static crl_reason_t parse_crl_reasonCode(chunk_t object)
{
	crl_reason_t reason = CRL_UNSPECIFIED;

	if (*object.ptr == ASN1_ENUMERATED
	&&  asn1_length(&object) == 1)
	{
		reason = *object.ptr;
	}

	DBG(DBG_PARSING,
		DBG_log("  '%N'", crl_reason_names, reason)
	)
	return reason;
}

/*
 *  Parses an X.509 CRL
 */
bool parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl)
{
	u_char buf[BUF_LEN];
	asn1_parser_t *parser;
	chunk_t extnID;
	chunk_t userCertificate = chunk_empty;
	chunk_t object;
	int objectID;
	bool success = FALSE;
	bool critical;

	parser = asn1_parser_create(crlObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser)+1;

		switch (objectID) {
		case CRL_OBJ_CERTIFICATE_LIST:
			crl->certificateList = object;
			break;
		case CRL_OBJ_TBS_CERT_LIST:
			crl->tbsCertList = object;
			break;
		case CRL_OBJ_VERSION:
			crl->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
			DBG(DBG_PARSING,
				DBG_log("  v%d", crl->version);
			)
			break;
		case CRL_OBJ_SIG_ALG:
			crl->sigAlg = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case CRL_OBJ_ISSUER:
			crl->issuer = object;
			DBG(DBG_PARSING,
				dntoa(buf, BUF_LEN, object);
				DBG_log("  '%s'",buf)
			)
			break;
		case CRL_OBJ_THIS_UPDATE:
			crl->thisUpdate = asn1_parse_time(object, level);
			break;
		case CRL_OBJ_NEXT_UPDATE:
			crl->nextUpdate = asn1_parse_time(object, level);
			break;
		case CRL_OBJ_USER_CERTIFICATE:
			userCertificate = object;
			break;
		case CRL_OBJ_REVOCATION_DATE:
			{
				/* put all the serial numbers and the revocation date in a chained list
				   with revocedCertificates pointing to the first revoked certificate */

				revokedCert_t *revokedCert = malloc_thing(revokedCert_t);
				revokedCert->userCertificate = userCertificate;
				revokedCert->revocationDate = asn1_parse_time(object, level);
				revokedCert->revocationReason = CRL_UNSPECIFIED;
				revokedCert->next = crl->revokedCertificates;
				crl->revokedCertificates = revokedCert;
			}
			break;
		case CRL_OBJ_CRL_ENTRY_EXTN_ID:
		case CRL_OBJ_EXTN_ID:
			extnID = object;
			break;
		case CRL_OBJ_CRL_ENTRY_CRITICAL:
		case CRL_OBJ_CRITICAL:
			critical = object.len && *object.ptr;
			DBG(DBG_PARSING,
				DBG_log("  %s",(critical)?"TRUE":"FALSE");
			)
			break;
		case CRL_OBJ_CRL_ENTRY_EXTN_VALUE:
		case CRL_OBJ_EXTN_VALUE:
			{
				u_int extn_oid = asn1_known_oid(extnID);

				if (extn_oid == OID_CRL_REASON_CODE)
				{
					crl->revokedCertificates->revocationReason =
						parse_crl_reasonCode(object);
				}
				else if (extn_oid == OID_AUTHORITY_KEY_ID)
				{
					parse_authorityKeyIdentifier(object, level
						, &crl->authKeyID, &crl->authKeySerialNumber);
				}
				else if (extn_oid == OID_CRL_NUMBER)
				{
					if (!asn1_parse_simple_object(&object, ASN1_INTEGER,
												  level, "crlNumber"))
					{
						goto end;
					}
					crl->crlNumber = object;
				}
			}
			break;
		case CRL_OBJ_ALGORITHM:
			crl->algorithm = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case CRL_OBJ_SIGNATURE:
			crl->signature = object;
			break;
		default:
			break;
		}
	}
	success = parser->success(parser);
	time(&crl->installed);

end:
	parser->destroy(parser);
	return success;
}

/*  Checks if the current certificate is revoked. It goes through the
 *  list of revoked certificates of the corresponding crl. Either the
 *  status CERT_GOOD or CERT_REVOKED is returned
 */
static cert_status_t
check_revocation(const x509crl_t *crl, chunk_t serial
, time_t *revocationDate, crl_reason_t * revocationReason)
{
	revokedCert_t *revokedCert = crl->revokedCertificates;

	*revocationDate = UNDEFINED_TIME;
	*revocationReason = CRL_UNSPECIFIED;
	
	DBG(DBG_CONTROL,
		DBG_dump_chunk("serial number:", serial)
	)

	while(revokedCert != NULL)
	{
		/* compare serial numbers */
		if (revokedCert->userCertificate.len == serial.len &&
			memeq(revokedCert->userCertificate.ptr, serial.ptr, serial.len))
		{
			*revocationDate = revokedCert->revocationDate;
			*revocationReason = revokedCert->revocationReason;
			return CERT_REVOKED;
		}
		revokedCert = revokedCert->next;
	}
	return CERT_GOOD;
}

/*
 * check if any crls are about to expire
 */
void
check_crls(void)
{
	x509crl_t *crl;

	lock_crl_list("check_crls");
	crl = x509crls;

	while (crl != NULL)
	{
		time_t time_left = crl->nextUpdate - time(NULL);
		u_char buf[BUF_LEN];

		DBG(DBG_CONTROL,
			dntoa(buf, BUF_LEN, crl->issuer);
			DBG_log("issuer: '%s'",buf);
			if (crl->authKeyID.ptr != NULL)
			{
				datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
					, buf, BUF_LEN);
				DBG_log("authkey: %s", buf);
			}
			DBG_log("%ld seconds left", time_left)
		)
		if (time_left < 2*crl_check_interval)
		{
			fetch_req_t *req = build_crl_fetch_request(crl->issuer
				, crl->authKeySerialNumber
				, crl->authKeyID, crl->distributionPoints);
			add_crl_fetch_request(req);
		}
		crl = crl->next;
	}
	unlock_crl_list("check_crls");
}

/*
 * verify if a cert hasn't been revoked by a crl
 */
cert_status_t
verify_by_crl(const x509cert_t *cert, time_t *until, time_t *revocationDate
, crl_reason_t *revocationReason)
{
	x509crl_t *crl;

	ca_info_t *ca = get_ca_info(cert->issuer, cert->authKeySerialNumber
							  , cert->authKeyID);

	generalName_t *crluri = (ca == NULL)? NULL : ca->crluri;

	*revocationDate = UNDEFINED_TIME;
	*revocationReason = CRL_UNSPECIFIED;

	lock_crl_list("verify_by_crl");
	crl = get_x509crl(cert->issuer, cert->authKeySerialNumber, cert->authKeyID);

	if (crl == NULL)
	{
		unlock_crl_list("verify_by_crl");
		plog("crl not found");

		if (cert->crlDistributionPoints != NULL)
		{
			fetch_req_t *req = build_crl_fetch_request(cert->issuer
				, cert->authKeySerialNumber
				, cert->authKeyID, cert->crlDistributionPoints);
			add_crl_fetch_request(req);
		}

		if (crluri != NULL)
		{
			fetch_req_t *req = build_crl_fetch_request(cert->issuer
				, cert->authKeySerialNumber
				, cert->authKeyID, crluri);
			add_crl_fetch_request(req);
		}

		if (cert->crlDistributionPoints != 0 || crluri != NULL)
		{
			wake_fetch_thread("verify_by_crl");
			return CERT_UNKNOWN;
		}
		else
			return CERT_UNDEFINED;
	}
	else
	{
		x509cert_t *issuer_cert;
		bool valid;

		DBG(DBG_CONTROL,
			DBG_log("crl found")
		)

		add_distribution_points(cert->crlDistributionPoints
				, &crl->distributionPoints);

		add_distribution_points(crluri
				, &crl->distributionPoints);

		lock_authcert_list("verify_by_crl");

		issuer_cert = get_authcert(crl->issuer, crl->authKeySerialNumber
				, crl->authKeyID, AUTH_CA);
		valid = x509_check_signature(crl->tbsCertList, crl->signature,
									 crl->algorithm, issuer_cert);
		
		unlock_authcert_list("verify_by_crl");

		if (valid)
		{
			cert_status_t status;

			DBG(DBG_CONTROL,
				DBG_log("crl signature is valid")
			)
		   /* return the expiration date */
			*until = crl->nextUpdate;

			/* has the certificate been revoked? */
			status = check_revocation(crl, cert->serialNumber, revocationDate
								, revocationReason);

			if (*until < time(NULL))
			{
				fetch_req_t *req;

				plog("crl update is overdue since %T", until, TRUE);

				/* try to fetch a crl update */
				req = build_crl_fetch_request(crl->issuer
								, crl->authKeySerialNumber
								, crl->authKeyID, crl->distributionPoints);
				unlock_crl_list("verify_by_crl");

				add_crl_fetch_request(req);
				wake_fetch_thread("verify_by_crl");
			}
			else
			{
				unlock_crl_list("verify_by_crl");
				DBG(DBG_CONTROL,
					DBG_log("crl is valid")
				)
			}
			return status;
		}
		else
		{
			unlock_crl_list("verify_by_crl");
			plog("crl signature is invalid");
			return CERT_UNKNOWN;
		}
	}
}

/*
 *  list all X.509 crls in the chained list
 */
void
list_crls(bool utc, bool strict)
{
	x509crl_t *crl;

	lock_crl_list("list_crls");
	crl = x509crls;

	if (crl != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 CRLs:");
		whack_log(RC_COMMENT, " ");
	}

	while (crl != NULL)
	{
		u_char buf[BUF_LEN];
		u_int revoked = 0;
		revokedCert_t *revokedCert = crl->revokedCertificates;

		/* count number of revoked certificates in CRL */
		while (revokedCert != NULL)
		{
			revoked++;
			revokedCert = revokedCert->next;
		}

		whack_log(RC_COMMENT, "%T, revoked certs: %d",
				&crl->installed, utc, revoked);
		dntoa(buf, BUF_LEN, crl->issuer);
		whack_log(RC_COMMENT, "       issuer:   '%s'", buf);
		if (crl->crlNumber.ptr != NULL)
		{
			datatot(crl->crlNumber.ptr, crl->crlNumber.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "       crlnumber: %s", buf);
		}
		list_distribution_points(crl->distributionPoints);

		whack_log(RC_COMMENT, "       updates:   this %T",
				&crl->thisUpdate, utc);
		whack_log(RC_COMMENT, "                  next %T %s",
				&crl->nextUpdate, utc,
				check_expiry(crl->nextUpdate, CRL_WARNING_INTERVAL, strict));
		if (crl->authKeyID.ptr != NULL)
		{
			datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "       authkey:   %s", buf);
		}
		if (crl->authKeySerialNumber.ptr != NULL)
		{
			datatot(crl->authKeySerialNumber.ptr, crl->authKeySerialNumber.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "       aserial:   %s", buf);
		}

		crl = crl->next;
	}
	unlock_crl_list("list_crls");
}

