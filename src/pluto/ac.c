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

#include <sys/stat.h>
#include <time.h>

#include <debug.h>
#include <utils/enumerator.h>
#include <utils/linked_list.h>
#include <credentials/certificates/ac.h>

#include "ac.h"
#include "ca.h"
#include "certs.h"
#include "fetch.h"
#include "log.h"

/**
 * Chained list of X.509 attribute certificates
 */
static linked_list_t *acerts   = NULL;

/**
 * Initialize the linked list of attribute certificates
 */
void ac_initialize(void)
{
	acerts = linked_list_create();
}

/**
 * Free the linked list of attribute certificates
 */
void ac_finalize(void)
{
	if (acerts)
	{
		acerts->destroy_offset(acerts, offsetof(certificate_t, destroy));
	}
}

/**
 *  Get a X.509 attribute certificate for a given holder
 */
certificate_t* ac_get_cert(identification_t *issuer, chunk_t serial)
{
	enumerator_t *enumerator;
	certificate_t *cert, *found = NULL;

	enumerator = acerts->create_enumerator(acerts);
	while (enumerator->enumerate(enumerator, &cert))
	{
		ac_t *ac = (ac_t*)cert;

		if (issuer->equals(issuer, ac->get_holderIssuer(ac)) &&
			  chunk_equals(serial, ac->get_holderSerial(ac)))
		{
			found = cert;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Verifies a X.509 attribute certificate
 */
bool ac_verify_cert(certificate_t *cert, bool strict)
{
	ac_t *ac = (ac_t*)cert;
	identification_t *subject = cert->get_subject(cert);
	identification_t *issuer  = cert->get_issuer(cert);
	chunk_t authKeyID = ac->get_authKeyIdentifier(ac);
	cert_t *aacert;
	time_t notBefore, valid_until;

	DBG1(DBG_LIB, "holder: '%Y'", subject);
	DBG1(DBG_LIB, "issuer: '%Y'", issuer);

	if (!cert->get_validity(cert, NULL, NULL, &valid_until))
	{
		DBG1(DBG_LIB, "attribute certificate is invalid (valid from %T to %T)",
			 &notBefore, FALSE, &valid_until, FALSE);
		return FALSE;
	}
	DBG1(DBG_LIB, "attribute certificate is valid until %T", &valid_until,
		 FALSE);

	lock_authcert_list("verify_x509acert");
	aacert = get_authcert(issuer, authKeyID, X509_AA);
	unlock_authcert_list("verify_x509acert");

	if (aacert == NULL)
	{
		DBG1(DBG_LIB, "issuer aacert not found");
		return FALSE;
	}
	DBG2(DBG_LIB, "issuer aacert found");

	if (!cert->issued_by(cert, aacert->cert))
	{
		DBG1(DBG_LIB, "attribute certificate signature is invalid");
		return FALSE;
	}
	DBG1(DBG_LIB, "attribute certificate signature is valid");

	return verify_x509cert(aacert, strict, &valid_until);
}

/**
 *  Add a X.509 attribute certificate to the chained list
 */
static void ac_add_cert(certificate_t *cert)
{
	ac_t *ac = (ac_t*)cert;
	identification_t *hIssuer = ac->get_holderIssuer(ac);
	chunk_t hSerial = ac->get_holderSerial(ac);

	enumerator_t *enumerator;
	certificate_t *cert_old;

	enumerator = acerts->create_enumerator(acerts);
	while (enumerator->enumerate(enumerator, &cert_old))
	{
		ac_t *ac_old = (ac_t*)cert_old;

		if (hIssuer->equals(hIssuer, ac_old->get_holderIssuer(ac_old)) &&
			   chunk_equals(hSerial, ac_old->get_holderSerial(ac_old)))
		{
			if (certificate_is_newer(cert, cert_old))
			{
				acerts->remove_at(acerts, enumerator);
				cert_old->destroy(cert_old);
			}
			else
			{
				cert->destroy(cert);
				cert = NULL;
			}
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (cert)
	{
		acerts->insert_last(acerts, cert);
	}
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
	DBG1(DBG_LIB, "%s: peer with attributes '%s' is %sa member of the "
		 "groups '%s'", conn, peer_attributes->get_string(peer_attributes),
		 match ? "" : "not ", conn_attributes->get_string(conn_attributes));

	return match;
}

/**
 * Loads X.509 attribute certificates
 */
void ac_load_certs(void)
{
	enumerator_t *enumerator;
	struct stat st;
	char *file;

	DBG1(DBG_LIB, "loading attribute certificates from '%s'", A_CERT_PATH);

	enumerator = enumerator_create_directory(A_CERT_PATH);
	if (!enumerator)
	{
		return;
	}

	while (enumerator->enumerate(enumerator, NULL, &file, &st))
	{
		certificate_t *cert;

		if (!S_ISREG(st.st_mode))
		{
			/* skip special file */
			continue;
		}
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_AC,
								  BUILD_FROM_FILE, file, BUILD_END);
		if (cert)
		{
			DBG1(DBG_LIB, "  loaded attribute certificate from '%s'", file);
			ac_add_cert(cert);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 *  List all X.509 attribute certificates in the chained list
 */
void ac_list_certs(bool utc)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	time_t now;

	/* determine the current time */
	time(&now);

	if (acerts->get_count(acerts) > 0)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 Attribute Certificates:");
	}

	enumerator = acerts->create_enumerator(acerts);
	while (enumerator->enumerate(enumerator, &cert))
	{
		ac_t *ac = (ac_t*)cert;
		identification_t *entityName, *holderIssuer, *issuer;
		chunk_t holderSerial, serial, authKeyID;
		time_t notBefore, notAfter;
		ietf_attributes_t *groups;

		whack_log(RC_COMMENT, " ");

		entityName = cert->get_subject(cert);
		if (entityName)
		{
			whack_log(RC_COMMENT, "  holder:   \"%Y\"", entityName);
		}

		holderIssuer = ac->get_holderIssuer(ac);
		if (holderIssuer)
		{
			whack_log(RC_COMMENT, "  hissuer:  \"%Y\"", holderIssuer);
		}

		holderSerial = chunk_skip_zero(ac->get_holderSerial(ac));
		if (holderSerial.ptr)
		{
			whack_log(RC_COMMENT, "  hserial:   %#B", &holderSerial);
		}

		groups = ac->get_groups(ac);
		if (groups)
		{
			whack_log(RC_COMMENT, "  groups:    %s", groups->get_string(groups));
			groups->destroy(groups);
		}

		issuer = cert->get_issuer(cert);
		whack_log(RC_COMMENT, "  issuer:   \"%Y\"", issuer);

		serial = chunk_skip_zero(ac->get_serial(ac));
		whack_log(RC_COMMENT, "  serial:    %#B", &serial);

		cert->get_validity(cert, &now, &notBefore, &notAfter);
		whack_log(RC_COMMENT, "  validity:  not before %T %s",
				&notBefore, utc,
				(notBefore < now)?"ok":"fatal (not valid yet)");
		whack_log(RC_COMMENT, "             not after  %T %s", &notAfter, utc,
				check_expiry(notAfter, ACERT_WARNING_INTERVAL, TRUE));

		authKeyID = ac->get_authKeyIdentifier(ac);
		if (authKeyID.ptr)
		{
			whack_log(RC_COMMENT, "  authkey:   %#B", &authKeyID);
		}
	}
	enumerator->destroy(enumerator);
}

