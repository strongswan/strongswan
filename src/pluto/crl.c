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

static x509crl_t  *x509crls = NULL;

/**
 *  Get the X.509 CRL with a given issuer
 */
static x509crl_t* get_x509crl(identification_t *issuer, chunk_t keyid)
{
	x509crl_t *x509crl = x509crls;
	x509crl_t *prev_crl = NULL;

	while (x509crl != NULL)
	{
		certificate_t *cert_crl = x509crl->crl;
		crl_t *crl = (crl_t*)cert_crl;
		identification_t *crl_issuer = cert_crl->get_issuer(cert_crl);
		chunk_t authKeyID = crl->get_authKeyIdentifier(crl);

		if ((keyid.ptr && authKeyID.ptr)? same_keyid(keyid, authKeyID) :
			issuer->equals(issuer, crl_issuer))
		{
			if (x509crl != x509crls)
			{
				/* bring the CRL up front */
				prev_crl->next = x509crl->next;
				x509crl->next = x509crls;
				x509crls = x509crl;
			}
			return x509crl;
		}
		prev_crl = x509crl;
		x509crl = x509crl->next;
	}
	return NULL;
}

/**
 *  Free the dynamic memory used to store CRLs
 */
void free_crl(x509crl_t *crl)
{
	DESTROY_IF(crl->crl);
	crl->distributionPoints->destroy_function(crl->distributionPoints, free);
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
	{
		free_first_crl();
	}

	unlock_crl_list("free_crls");
}

/**
 * Insert X.509 CRL into chained list
 */
bool insert_crl(x509crl_t *x509crl, char *crl_uri, bool cache_crl)
{
	certificate_t *cert_crl = x509crl->crl;
	crl_t *crl = (crl_t*)cert_crl;
	identification_t *issuer = cert_crl->get_issuer(cert_crl);
	chunk_t authKeyID = crl->get_authKeyIdentifier(crl);
	cert_t *issuer_cert;
	x509crl_t *oldcrl;
	time_t now, nextUpdate;
	bool valid_sig;

	/* add distribution point */
	add_distribution_point(x509crl->distributionPoints, crl_uri);

	lock_authcert_list("insert_crl");

	/* get the issuer cacert */
	issuer_cert = get_authcert(issuer, authKeyID, X509_CA);
	if (issuer_cert == NULL)
	{
		plog("crl issuer cacert not found");
		free_crl(x509crl);
		unlock_authcert_list("insert_crl");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("crl issuer cacert found")
	)

	/* check the issuer's signature of the crl */
	valid_sig = cert_crl->issued_by(cert_crl, issuer_cert->cert);
	unlock_authcert_list("insert_crl");

	if (!valid_sig)
	{
		free_crl(x509crl);
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("crl signature is valid")
	)

	/* note the current time */
	time(&now);

	lock_crl_list("insert_crl");
	oldcrl = get_x509crl(issuer, authKeyID);

	if (oldcrl != NULL)
	{
		certificate_t *old_cert_crl = oldcrl->crl;

		if (crl_is_newer((crl_t*)cert_crl, (crl_t*)old_cert_crl))
		{
			/* keep any known CRL distribution points */
			add_distribution_points(x509crl->distributionPoints,
									oldcrl->distributionPoints);

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
			free_crl(x509crl);
			old_cert_crl->get_validity(old_cert_crl, &now, NULL, &nextUpdate);
			return nextUpdate - now > 2*crl_check_interval;
		}
	}

	/* insert new CRL */
	x509crl->next = x509crls;
	x509crls = x509crl;

	unlock_crl_list("insert_crl");

	/* If crl caching is enabled then the crl is saved locally.
	 * Only http or ldap URIs are cached but not local file URIs.
	 * The CRL's authorityKeyIdentifier is used as a unique filename
	 */
	if (cache_crl && strncasecmp(crl_uri, "file", 4) != 0)
	{
		char buf[BUF_LEN];
		chunk_t hex, encoding;

		hex = chunk_to_hex(crl->get_authKeyIdentifier(crl), NULL, FALSE);
		snprintf(buf, sizeof(buf), "%s/%s.crl", CRL_PATH, hex.ptr);
		free(hex.ptr);

		if (cert_crl->get_encoding(cert_crl, CERT_ASN1_DER, &encoding))
		{
			chunk_write(encoding, buf, "crl", 022, TRUE);
			free(encoding.ptr);
		}
	}

	/* is the fetched crl valid? */
	cert_crl->get_validity(cert_crl, &now, NULL, &nextUpdate);
	return nextUpdate - now > 2*crl_check_interval;
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
				x509crl_t *x509crl;

				x509crl = lib->creds->create(lib->creds, CRED_CERTIFICATE,
										 CERT_PLUTO_CRL,
										 BUILD_FROM_FILE, filename, BUILD_END);
				if (x509crl)
				{
					char crl_uri[BUF_LEN];

					plog("  loaded crl from '%s'", filename);
					snprintf(crl_uri, BUF_LEN, "file://%s/%s", CRL_PATH, filename);
					insert_crl(x509crl, crl_uri, FALSE);
				}
				free(filelist[n]);
			}
			free(filelist);
		}
	}
	/* restore directory path */
	ignore_result(chdir(save_dir));
}


/*  Checks if the current certificate is revoked. It goes through the
 *  list of revoked certificates of the corresponding crl. Either the
 *  status CERT_GOOD or CERT_REVOKED is returned
 */
static cert_status_t check_revocation(crl_t *crl, chunk_t cert_serial,
									  time_t *revocationDate,
									  crl_reason_t *revocationReason)
{
	enumerator_t *enumerator;
	cert_status_t status;
	chunk_t serial;

	DBG(DBG_CONTROL,
		DBG_log("serial number: %#B", &cert_serial)
	)
	*revocationDate = UNDEFINED_TIME;
	*revocationReason = CRL_REASON_UNSPECIFIED;
	status = CERT_GOOD;

	enumerator = crl->create_enumerator(crl);
	while (enumerator->enumerate(enumerator, &serial,
								 revocationDate, revocationReason))
	{
		if (chunk_equals(serial, cert_serial))
		{
			status = CERT_REVOKED;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return status;
}

/*
 * check if any crls are about to expire
 */
void check_crls(void)
{
	x509crl_t *x509crl;
	time_t now, nextUpdate, time_left;

	lock_crl_list("check_crls");
	time(&now);
	x509crl = x509crls;

	while (x509crl != NULL)
	{
		certificate_t *cert_crl = x509crl->crl;
		crl_t *crl = (crl_t*)cert_crl;
		identification_t *issuer = cert_crl->get_issuer(cert_crl);
		chunk_t authKeyID = crl->get_authKeyIdentifier(crl);

		cert_crl->get_validity(cert_crl, &now, NULL, &nextUpdate);
		time_left = nextUpdate - now;

		DBG(DBG_CONTROL,
			DBG_log("issuer: '%Y'", issuer);
			if (authKeyID.ptr)
			{
				DBG_log("authkey: %#B", &authKeyID);
			}
			DBG_log("%ld seconds left", time_left)
		)
		if (time_left < 2*crl_check_interval)
		{
			fetch_req_t *req = build_crl_fetch_request(issuer, authKeyID,
											x509crl->distributionPoints);
			add_crl_fetch_request(req);
		}
		x509crl = x509crl->next;
	}
	unlock_crl_list("check_crls");
}

/*
 * verify if a cert hasn't been revoked by a crl
 */
cert_status_t verify_by_crl(cert_t *cert, time_t *until, time_t *revocationDate,
							crl_reason_t *revocationReason)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	identification_t *issuer = certificate->get_issuer(certificate);
	chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
	x509crl_t *x509crl;
	ca_info_t *ca;
	enumerator_t *enumerator;
	x509_cdp_t *cdp;

	ca = get_ca_info(issuer, authKeyID);

	*revocationDate = UNDEFINED_TIME;
	*revocationReason = CRL_REASON_UNSPECIFIED;

	lock_crl_list("verify_by_crl");
	x509crl = get_x509crl(issuer, authKeyID);

	if (x509crl == NULL)
	{
		linked_list_t *crluris;

		unlock_crl_list("verify_by_crl");
		plog("crl not found");

		crluris = linked_list_create();
		if (ca)
		{
			add_distribution_points(crluris, ca->crluris);
		}

		enumerator = x509->create_crl_uri_enumerator(x509);
		while (enumerator->enumerate(enumerator, &cdp))
		{
			add_distribution_point(crluris, cdp->uri);
		}
		enumerator->destroy(enumerator);

		if (crluris->get_count(crluris) > 0)
		{
			fetch_req_t *req;

			req = build_crl_fetch_request(issuer, authKeyID, crluris);
			crluris->destroy_function(crluris, free);
			add_crl_fetch_request(req);
			wake_fetch_thread("verify_by_crl");
			return CERT_UNKNOWN;
		}
		else
		{
			crluris->destroy(crluris);
			return CERT_UNDEFINED;
		}
	}
	else
	{
		certificate_t *cert_crl = x509crl->crl;
		crl_t *crl = (crl_t*)cert_crl;
		chunk_t authKeyID = crl->get_authKeyIdentifier(crl);
		cert_t *issuer_cert;
		bool trusted, valid;

		DBG(DBG_CONTROL,
			DBG_log("crl found")
		)

		if (ca)
		{
			add_distribution_points(x509crl->distributionPoints, ca->crluris);
		}

		enumerator = x509->create_crl_uri_enumerator(x509);
		while (enumerator->enumerate(enumerator, &cdp))
		{
			add_distribution_point(x509crl->distributionPoints, cdp->uri);
		}
		enumerator->destroy(enumerator);

		lock_authcert_list("verify_by_crl");

		issuer_cert = get_authcert(issuer, authKeyID, X509_CA);
		trusted = issuer_cert ? cert_crl->issued_by(cert_crl, issuer_cert->cert)
							  : FALSE;

		unlock_authcert_list("verify_by_crl");

		if (trusted)
		{
			cert_status_t status;

			DBG(DBG_CONTROL,
				DBG_log("crl signature is valid")
			)

			/* return the expiration date */
			valid = cert_crl->get_validity(cert_crl, NULL, NULL, until);

			/* has the certificate been revoked? */
			status = check_revocation(crl, x509->get_serial(x509), revocationDate
								, revocationReason);

			if (valid)
			{
				unlock_crl_list("verify_by_crl");
				DBG(DBG_CONTROL,
					DBG_log("crl is valid: until %T", until, FALSE)
				)
			}
			else
			{
				fetch_req_t *req;

				DBG(DBG_CONTROL,
					DBG_log("crl is stale: since %T", until, FALSE)
				)

				/* try to fetch a crl update */
				req = build_crl_fetch_request(issuer, authKeyID,
											  x509crl->distributionPoints);
				unlock_crl_list("verify_by_crl");

				add_crl_fetch_request(req);
				wake_fetch_thread("verify_by_crl");
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
void list_crls(bool utc, bool strict)
{
	x509crl_t *x509crl;

	lock_crl_list("list_crls");
	x509crl = x509crls;

	if (x509crl)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 CRLs:");
	}

	while (x509crl)
	{
		certificate_t *cert_crl = x509crl->crl;
		crl_t *crl = (crl_t*)cert_crl;
		chunk_t serial, authKeyID;
		time_t thisUpdate, nextUpdate;
		u_int revoked = 0;
		enumerator_t *enumerator;

		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "  issuer:   \"%Y\"",
				cert_crl->get_issuer(cert_crl));
		serial = chunk_skip_zero(crl->get_serial(crl));
		if (serial.ptr)
		{
			whack_log(RC_COMMENT, "  serial:    %#B", &serial);
		}

		/* count number of revoked certificates in CRL */
		enumerator = crl->create_enumerator(crl);
		while (enumerator->enumerate(enumerator, NULL, NULL, NULL))
		{
			revoked++;
		}
		enumerator->destroy(enumerator);
		whack_log(RC_COMMENT, "  revoked:   %d certificates", revoked);

		list_distribution_points(x509crl->distributionPoints);

		cert_crl->get_validity(cert_crl, NULL, &thisUpdate, &nextUpdate);
		whack_log(RC_COMMENT, "  updates:   this %T", &thisUpdate, utc);
		whack_log(RC_COMMENT, "             next %T %s", &nextUpdate, utc,
				check_expiry(nextUpdate, CRL_WARNING_INTERVAL, strict));
		authKeyID = crl->get_authKeyIdentifier(crl);
		if (authKeyID.ptr)
		{
			whack_log(RC_COMMENT, "  authkey:   %#B", &authKeyID);
		}

		x509crl = x509crl->next;
	}
	unlock_crl_list("list_crls");
}

