/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2009 Andreas Steffen
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
#include <sys/types.h>

#include <freeswan.h>

#include <utils.h>
#include <credentials/certificates/ac.h>

#include "ac.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "log.h"
#include "whack.h"
#include "fetch.h"
#include "builder.h"

/**
 * Chained list of X.509 attribute certificates
 */
static x509acert_t *x509acerts   = NULL;

/**
 *  Free a X.509 attribute certificate
 */
void free_acert(x509acert_t *ac)
{
	if (ac)
	{
		DESTROY_IF(ac->ac);
		free(ac);
	}
}

/**
 *  Free first X.509 attribute certificate in the chained list
 */
static void free_first_acert(void)
{
	x509acert_t *first = x509acerts;
	x509acerts = first->next;
	free_acert(first);
}

/**
 * Free all attribute certificates in the chained list
 */
void free_acerts(void)
{
	while (x509acerts != NULL)
	{
		free_first_acert();
	}
}

/**
 *  Get a X.509 attribute certificate for a given holder
 */
x509acert_t* get_x509acert(chunk_t issuer, chunk_t serial)
{
	x509acert_t *x509ac = x509acerts;
	x509acert_t *prev_ac = NULL;

	while (x509ac != NULL)
	{
		ac_t *ac = (ac_t*)x509ac->ac;
		identification_t *holderIssuer = ac->get_holderIssuer(ac);
		chunk_t holderIssuer_dn = holderIssuer->get_encoding(holderIssuer);
		chunk_t holderSerial = ac->get_holderSerial(ac);

		if (same_dn(issuer, holderIssuer_dn) &&
			chunk_equals(serial, holderSerial))
		{
			if (x509ac!= x509acerts)
			{
				/* bring the certificate up front */
				prev_ac->next = x509ac->next;
				x509ac->next = x509acerts;
				x509acerts = x509ac;
			}
			return x509ac;
		}
		prev_ac = x509ac;
		x509ac = x509ac->next;
	}
	return NULL;
}

/**
 *  Add a X.509 attribute certificate to the chained list
 */
static void add_acert(x509acert_t *x509ac)
{
	certificate_t *cert_ac = x509ac->ac;
	ac_t *ac = (ac_t*)cert_ac;
	identification_t *holderIssuer = ac->get_holderIssuer(ac);
	chunk_t holderIssuer_dn = holderIssuer->get_encoding(holderIssuer);
	chunk_t holderSerial = ac->get_serial(ac);
	x509acert_t *old_ac;

	old_ac = get_x509acert(holderIssuer_dn, holderSerial);
	if (old_ac != NULL)
	{
		if (cert_ac->is_newer(cert_ac, old_ac->ac))
		{
			/* delete the old attribute cert */
			free_first_acert();
			DBG(DBG_CONTROL,
				DBG_log("attribute cert is newer - existing cert deleted")
			)
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("attribute cert is not newer - existing cert kept");
			)
			free_acert(x509ac);
			return;
		}
	}
	plog("attribute cert added");

	/* insert new attribute cert at the root of the chain */
	x509ac->next = x509acerts;
	x509acerts = x509ac;
}

/**
 * verifies a X.509 attribute certificate
 */
bool verify_x509acert(x509acert_t *x509ac, bool strict)
{
	certificate_t *cert_ac = x509ac->ac;
	ac_t *ac = (ac_t*)cert_ac;
	identification_t *subject = cert_ac->get_subject(cert_ac);
	identification_t *issuer = cert_ac->get_issuer(cert_ac);
	chunk_t issuer_dn = issuer->get_encoding(issuer);
	chunk_t authKeyID = ac->get_authKeyIdentifier(ac);
	x509cert_t *aacert;
	time_t notBefore, valid_until;

	DBG(DBG_CONTROL,
		DBG_log("holder: '%Y'", subject);
		DBG_log("issuer: '%Y'", issuer);
	)

	if (!cert_ac->get_validity(cert_ac, NULL, NULL, &valid_until))
	{
		plog("attribute certificate is invalid (valid from %T to %T)",
			 &notBefore, FALSE, &valid_until, FALSE);
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("attribute certificate is valid until %T", &valid_until, FALSE)
	)

	lock_authcert_list("verify_x509acert");
	aacert = get_authcert(issuer_dn, authKeyID, X509_AA);
	unlock_authcert_list("verify_x509acert");

	if (aacert == NULL)
	{
		plog("issuer aacert not found");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("issuer aacert found")
	)

	if (!cert_ac->issued_by(cert_ac, aacert->cert))
	{
		plog("attribute certificate signature is invalid");
		return FALSE;
	}
	DBG(DBG_CONTROL,
		DBG_log("attribute certificate signature is valid");
	)

	return verify_x509cert(aacert, strict, &valid_until);
}

/**
 * Check if at least one peer attribute matches a connection attribute
 */
bool match_group_membership(ietf_attributes_t *peer_attributes, char *conn,
							ietf_attributes_t *conn_attributes)
{
	bool match;

	if (conn_attributes == NULL)
	{
		return TRUE;
	}

	match = conn_attributes->matches(conn_attributes, peer_attributes);
	DBG(DBG_CONTROL,
		DBG_log("%s: peer with attributes '%s' is %sa member of the groups '%s'",
				conn,
				peer_attributes->get_string(peer_attributes),
				match ? "" : "not ",
				conn_attributes->get_string(conn_attributes))
	)
	return match;

}

/**
 * Loads X.509 attribute certificates
 */
void load_acerts(void)
{
	u_char buf[BUF_LEN];

	/* change directory to specified path */
	u_char *save_dir = getcwd(buf, BUF_LEN);

	if (!chdir(A_CERT_PATH))
	{
		struct dirent **filelist;
		int n;

		plog("Changing to directory '%s'",A_CERT_PATH);
		n = scandir(A_CERT_PATH, &filelist, file_select, alphasort);

		if (n > 0)
		{
			while (n--)
			{
				char *filename = filelist[n]->d_name;
				x509acert_t *ac;

				ac = lib->creds->create(lib->creds, CRED_CERTIFICATE,
							CERT_PLUTO_AC, BUILD_FROM_FILE, filename,
							BUILD_END);
				if (ac)
				{
					plog("  loaded attribute certificate from '%s'", filename);
					add_acert(ac);
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
 *  list all X.509 attribute certificates in the chained list
 */
void list_acerts(bool utc)
{
	x509acert_t *x509ac = x509acerts;
	time_t now;

	/* determine the current time */
	time(&now);

	if (x509ac)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 Attribute Certificates:");
		whack_log(RC_COMMENT, " ");
	}

	while (x509ac)
	{
		certificate_t *cert_ac = x509ac->ac;
		ac_t *ac = (ac_t*)cert_ac;
		identification_t *entityName, *holderIssuer, *issuer;
		chunk_t holderSerial, serial, authKeyID;
		time_t notBefore, notAfter;
		ietf_attributes_t *groups;


		whack_log(RC_COMMENT, "%T", &x509ac->installed, utc);

		entityName = cert_ac->get_subject(cert_ac);
		if (entityName)
		{
			whack_log(RC_COMMENT, "       holder:   '%Y'", entityName);
		}

		holderIssuer = ac->get_holderIssuer(ac);
		if (holderIssuer)
		{
			whack_log(RC_COMMENT, "       hissuer:  '%Y'", holderIssuer);
		}

		holderSerial = ac->get_holderSerial(ac);
		if (holderSerial.ptr)
		{
			whack_log(RC_COMMENT, "       hserial:   %#B", &holderSerial);
		}

		groups = ac->get_groups(ac);		
		if (groups)
		{
			whack_log(RC_COMMENT, "       groups:    %s",
					groups->get_string(groups));
			groups->destroy(groups);
		}

		issuer = cert_ac->get_issuer(cert_ac);
		whack_log(RC_COMMENT, "       issuer:   '%Y'", issuer);

		serial = ac->get_serial(ac);
		whack_log(RC_COMMENT, "       serial:    %#B", &serial);

		cert_ac->get_validity(cert_ac, &now, &notBefore, &notAfter);
		whack_log(RC_COMMENT, "       validity:  not before %T %s",
				&notBefore, utc,
				(notBefore < now)?"ok":"fatal (not valid yet)");
		whack_log(RC_COMMENT, "                  not after  %T %s",
				&notAfter, utc,
				check_expiry(notAfter, ACERT_WARNING_INTERVAL, TRUE));

		authKeyID = ac->get_authKeyIdentifier(ac);
		if (authKeyID.ptr)
		{
			whack_log(RC_COMMENT, "       authkey:   %#B", &authKeyID);
		}

		x509ac = x509ac->next;
	}
}

