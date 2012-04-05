/* Support of X.509 certificates
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
#include <crypto/hashers/hasher.h>
#include <utils/enumerator.h>
#include <utils/identification.h>

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
#include "ocsp.h"

/**
 * Check for equality between two key identifiers
 */
bool same_keyid(chunk_t a, chunk_t b)
{
	if (a.ptr == NULL || b.ptr == NULL)
	{
		return FALSE;
	}
	return chunk_equals(a, b);
}

/**
 * Stores a chained list of end certs and CA certs
 */
void store_x509certs(linked_list_t *certs, bool strict)
{
	cert_t *x509cert, *cacerts = NULL;
	certificate_t *cert;
	enumerator_t *enumerator;

	/* first extract CA certs, ignoring self-signed root CA certs */

	enumerator = certs->create_enumerator(certs);
	while (enumerator->enumerate(enumerator, &cert))
	{
		x509_t *x509 = (x509_t*)cert;
		x509_flag_t flags;

		flags = x509->get_flags(x509);
		if (flags & X509_CA)
		{
			/* we don't accept self-signed CA certs */
			if (flags & X509_SELF_SIGNED)
			{
				plog("self-signed cacert rejected");
			}
			else
			{
				/* insertion into temporary chain of candidate CA certs */
				x509cert = malloc_thing(cert_t);
				*x509cert = cert_empty;
				x509cert->cert = cert->get_ref(cert);
				x509cert->next = cacerts;
				cacerts = x509cert;
			}
		}
	}
	enumerator->destroy(enumerator);

	/* now verify the candidate CA certs */

	while (cacerts)
	{
		cert_t *cert = cacerts;

		cacerts = cacerts->next;

		if (trust_authcert_candidate(cert, cacerts))
		{
			add_authcert(cert, X509_CA);
		}
		else
		{
			plog("intermediate cacert rejected");
			cert_free(cert);
		}
	}

	/* now verify the end certificates */

	enumerator = certs->create_enumerator(certs);
	while (enumerator->enumerate(enumerator, &cert))
	{
		time_t valid_until;
		x509_t *x509 = (x509_t*)cert;

		if (!(x509->get_flags(x509) & X509_CA))
		{
			x509cert = malloc_thing(cert_t);
			*x509cert = cert_empty;
			x509cert->cert = cert->get_ref(cert);

			if (verify_x509cert(x509cert, strict, &valid_until))
			{
				DBG(DBG_CONTROL | DBG_PARSING,
					DBG_log("public key validated")
				)
				add_public_key_from_cert(x509cert, valid_until, DAL_SIGNED);
			}
			else
			{
				plog("X.509 certificate rejected");
				cert_free(x509cert);
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Check if a signature over binary blob is genuine
 */
bool x509_check_signature(chunk_t tbs, chunk_t sig, int algorithm,
						  certificate_t *issuer_cert)
{
	bool success;
	public_key_t *key;
	signature_scheme_t scheme;

	scheme = signature_scheme_from_oid(algorithm);
	if (scheme == SIGN_UNKNOWN)
	{
		return FALSE;
	}

	key = issuer_cert->get_public_key(issuer_cert);
	if (key == NULL)
	{
		return FALSE;
	}
	success = key->verify(key, scheme, tbs, sig);
	key->destroy(key);

	return success;
}

/**
 * Build an ASN.1 encoded PKCS#1 signature over a binary blob
 */
chunk_t x509_build_signature(chunk_t tbs, int algorithm, private_key_t *key,
							 bool bit_string)
{
	chunk_t signature;
	signature_scheme_t scheme = signature_scheme_from_oid(algorithm);

	if (scheme == SIGN_UNKNOWN || !key->sign(key, scheme, tbs, &signature))
	{
		return chunk_empty;
	}
	return (bit_string) ? asn1_bitstring("m", signature)
						: asn1_wrap(ASN1_OCTET_STRING, "m", signature);
}

/**
 * Verifies a X.509 certificate
 */
bool verify_x509cert(cert_t *cert, bool strict, time_t *until)
{
	int pathlen, pathlen_constraint;

	*until = 0;

	for (pathlen = -1; pathlen <= X509_MAX_PATH_LEN; pathlen++)
	{
		certificate_t *certificate = cert->cert;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer  = certificate->get_issuer(certificate);
		x509_t *x509 = (x509_t*)certificate;
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		cert_t *issuer_cert;
		time_t notBefore, notAfter;
		bool valid;

		DBG(DBG_CONTROL,
			DBG_log("subject: '%Y'", subject);
			DBG_log("issuer:  '%Y'", issuer);
			if (authKeyID.ptr)
			{
				DBG_log("authkey:  %#B", &authKeyID);
			}
		)

		valid = certificate->get_validity(certificate, NULL,
										  &notBefore, &notAfter);
		if (*until == UNDEFINED_TIME || notAfter < *until)
		{
			*until = notAfter;
		}
		if (!valid)
		{
			plog("certificate is invalid (valid from %T to %T)",
				 &notBefore, FALSE, &notAfter, FALSE);
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate is valid")
		)

		lock_authcert_list("verify_x509cert");
		issuer_cert = get_authcert(issuer, authKeyID, X509_CA);
		if (issuer_cert == NULL)
		{
			plog("issuer cacert not found");
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("issuer cacert found")
		)

		if (!certificate->issued_by(certificate, issuer_cert->cert))
		{
			plog("certificate signature is invalid");
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate signature is valid")
		)
		unlock_authcert_list("verify_x509cert");

		/* check path length constraint */
		pathlen_constraint = x509->get_constraint(x509, X509_PATH_LEN);
		if (pathlen_constraint != X509_NO_CONSTRAINT &&
			pathlen > pathlen_constraint)
		{
			plog("path length of %d violates constraint of %d",
				 pathlen, pathlen_constraint);
			return FALSE;
		}

		/* check if cert is a self-signed root ca */
		if (pathlen >= 0 && (x509->get_flags(x509) & X509_SELF_SIGNED))
		{
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca with a path length of %d",
						 pathlen)
			)
			return TRUE;
		}
		else
		{
			time_t nextUpdate = *until;
			time_t revocationDate = UNDEFINED_TIME;
			crl_reason_t revocationReason = CRL_REASON_UNSPECIFIED;

			/* first check certificate revocation using ocsp */
			cert_status_t status = verify_by_ocsp(cert, &nextUpdate
				, &revocationDate, &revocationReason);

			/* if ocsp service is not available then fall back to crl */
			if ((status == CERT_UNDEFINED)
			||  (status == CERT_UNKNOWN && strict))
			{
				status = verify_by_crl(cert, &nextUpdate, &revocationDate
					, &revocationReason);
			}

			switch (status)
			{
			case CERT_GOOD:
				/* if status information is stale */
				if (strict && nextUpdate < time(NULL))
				{
					DBG(DBG_CONTROL,
						DBG_log("certificate is good but status is stale")
					)
					remove_x509_public_key(cert);
					return FALSE;
				}
				DBG(DBG_CONTROL,
					DBG_log("certificate is good")
				)

				/* with strict crl policy the public key must have the same
				 * lifetime as the validity of the ocsp status or crl lifetime
				 */
				if (strict && nextUpdate < *until)
				{
					*until = nextUpdate;
				}
				break;
			case CERT_REVOKED:
				plog("certificate was revoked on %T, reason: %N"
					, &revocationDate, TRUE
					, crl_reason_names, revocationReason);
				remove_x509_public_key(cert);
				return FALSE;
			case CERT_UNKNOWN:
			case CERT_UNDEFINED:
			default:
				plog("certificate status unknown");
				if (strict)
				{
					remove_x509_public_key(cert);
					return FALSE;
				}
				break;
			}
		}

		/* go up one step in the trust chain */
		cert = issuer_cert;
	}
	plog("maximum path length of %d exceeded", X509_MAX_PATH_LEN);
	return FALSE;
}

/**
 * List all X.509 certs in a chained list
 */
void list_x509cert_chain(const char *caption, cert_t* cert,
						 x509_flag_t flags, bool utc)
{
	bool first = TRUE;
	time_t now;

	/* determine the current time */
	time(&now);

	while (cert)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;

		if (certificate->get_type(certificate) == CERT_X509 &&
		   (flags == X509_NONE || (flags & x509->get_flags(x509))))
		{
			enumerator_t *enumerator;
			char buf[BUF_LEN];
			char *pos = buf;
			int len = BUF_LEN, pathlen;
			bool first_altName = TRUE;
			identification_t *id;
			time_t notBefore, notAfter;
			public_key_t *key;
			chunk_t serial, keyid, subjkey, authkey;

			if (first)
			{
				whack_log(RC_COMMENT, " ");
				whack_log(RC_COMMENT, "List of X.509 %s Certificates:", caption);
				first = FALSE;
			}
			whack_log(RC_COMMENT, " ");

			enumerator = x509->create_subjectAltName_enumerator(x509);
			while (enumerator->enumerate(enumerator, &id))
			{
				int written;

				if (first_altName)
				{
					written = snprintf(pos, len, "%Y", id);
					first_altName = FALSE;
				}
				else
				{
					written = snprintf(pos, len, ", %Y", id);
				}
				if (written < 0 || written >= len)
				{
					break;
				}
				pos += written;
				len -= written;
			}
			enumerator->destroy(enumerator);
			if (!first_altName)
			{
				whack_log(RC_COMMENT, "  altNames:  %s", buf);
			}

			whack_log(RC_COMMENT, "  subject:  \"%Y\"",
				certificate->get_subject(certificate));
			whack_log(RC_COMMENT, "  issuer:   \"%Y\"",
				certificate->get_issuer(certificate));
				serial = chunk_skip_zero(x509->get_serial(x509));
			whack_log(RC_COMMENT, "  serial:    %#B", &serial);

			/* list validity */
			certificate->get_validity(certificate, &now, &notBefore, &notAfter);
			whack_log(RC_COMMENT, "  validity:  not before %T %s",
				&notBefore, utc,
				(notBefore < now)?"ok":"fatal (not valid yet)");
			whack_log(RC_COMMENT, "             not after  %T %s",
				&notAfter, utc,
				check_expiry(notAfter, CA_CERT_WARNING_INTERVAL, TRUE));

			key = certificate->get_public_key(certificate);
			if (key)
			{
				whack_log(RC_COMMENT, "  pubkey:    %N %4d bits%s",
					key_type_names, key->get_type(key),
					key->get_keysize(key),
					cert->smartcard ? ", on smartcard" :
					(has_private_key(cert)? ", has private key" : ""));

				if (key->get_fingerprint(key, KEYID_PUBKEY_INFO_SHA1, &keyid))
				{
					whack_log(RC_COMMENT, "  keyid:     %#B", &keyid);
				}
				if (key->get_fingerprint(key, KEYID_PUBKEY_SHA1, &subjkey))
				{
					whack_log(RC_COMMENT, "  subjkey:   %#B", &subjkey);
				}
				key->destroy(key);
			}

			/* list optional authorityKeyIdentifier */
			authkey = x509->get_authKeyIdentifier(x509);
			if (authkey.ptr)
			{
				whack_log(RC_COMMENT, "  authkey:   %#B", &authkey);
			}

			/* list optional pathLenConstraint */
			pathlen = x509->get_constraint(x509, X509_PATH_LEN);
			if (pathlen != X509_NO_CONSTRAINT)
			{
				whack_log(RC_COMMENT, "  pathlen:   %d", pathlen);
			}

		}
		cert = cert->next;
	}
}

