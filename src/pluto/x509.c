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
 * Chained lists of X.509 end certificates
 */
static x509cert_t *x509certs     = NULL;

const x509cert_t empty_x509cert = {
	  NULL        , /* cert */
	  NULL        , /* *next */
			0     , /* count */
	  FALSE         /* smartcard */
};

/* coding of X.501 distinguished name */

/**
 * For each link pointing to the certificate increase the count by one
 */
void share_x509cert(x509cert_t *cert)
{
	if (cert != NULL)
	{
		cert->count++;
	}
}

/**
 *  Add a X.509 user/host certificate to the chained list
 */
x509cert_t* add_x509cert(x509cert_t *cert)
{
	certificate_t *certificate = cert->cert;
	x509cert_t *c = x509certs;

	while (c != NULL)
	{
		if (certificate->equals(certificate, c->cert)) /* already in chain, free cert */
		{
			free_x509cert(cert);
			return c;
		}
		c = c->next;
	}

	/* insert new cert at the root of the chain */
	lock_certs_and_keys("add_x509cert");
	cert->next = x509certs;
	x509certs = cert;
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  x509 cert inserted")
	)
	unlock_certs_and_keys("add_x509cert");
	return cert;
}

/**
 * Choose either subject DN or a subjectAltName as connection end ID
 */
identification_t* select_x509cert_id(x509cert_t *cert, identification_t *id)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	identification_t *subject, *subjectAltName;

	bool copy_subject_dn = TRUE;    /* ID is subject DN */

	if (id->get_type(id) != ID_ANY) /* check for a matching subjectAltName */
	{
		enumerator_t *enumerator;

		enumerator = x509->create_subjectAltName_enumerator(x509);
		while (enumerator->enumerate(enumerator, &subjectAltName))
		{
			if (id->equals(id, subjectAltName))
			{
				copy_subject_dn = FALSE; /* take subjectAltName instead */
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	if (copy_subject_dn)
	{
		id->destroy(id);
		subject = certificate->get_subject(certificate);
		plog("  no subjectAltName matches ID '%Y', replaced by subject DN", id);

		return subject->clone(subject);
	}
	else
	{
		return id;
	}
}

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
 * Get a X.509 certificate with a given issuer found at a certain position
 */
x509cert_t* get_x509cert(identification_t *issuer, chunk_t keyid, x509cert_t *chain)
{
	x509cert_t *cert = chain ? chain->next : x509certs;

	while (cert)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);

		if (keyid.ptr ? same_keyid(keyid, authKeyID) :
			certificate->has_issuer(certificate, issuer))
		{
			return cert;
		}
		cert = cert->next;
	}
	return NULL;
}

/**
 *  Free a X.509 certificate
 */
void free_x509cert(x509cert_t *cert)
{
	if (cert)
	{
		certificate_t *certificate = cert->cert;

		if (certificate)
		{
			certificate->destroy(certificate);
		}
		free(cert);
		cert = NULL;
	}
}

/**
 * Release of a certificate decreases the count by one
 * the certificate is freed when the counter reaches zero
 */
void release_x509cert(x509cert_t *cert)
{
	if (cert && --cert->count == 0)
	{
		x509cert_t **pp = &x509certs;
		while (*pp != cert)
		{
			pp = &(*pp)->next;
		}
		*pp = cert->next;
		free_x509cert(cert);
	}
}

/**
 * Stores a chained list of end certs and CA certs
 */
void store_x509certs(linked_list_t *certs, bool strict)
{
	x509cert_t *x509cert, *cacerts = NULL;
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
				x509cert = malloc_thing(x509cert_t);
				*x509cert = empty_x509cert;
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
		x509cert_t *cert = cacerts;

		cacerts = cacerts->next;

		if (trust_authcert_candidate(cert, cacerts))
		{
			add_authcert(cert, X509_CA);
		}
		else
		{
			plog("intermediate cacert rejected");
			free_x509cert(cert);
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
			x509cert = malloc_thing(x509cert_t);
			*x509cert = empty_x509cert;
			x509cert->cert = cert->get_ref(cert);

			if (verify_x509cert(x509cert, strict, &valid_until))
			{
				DBG(DBG_CONTROL | DBG_PARSING,
					DBG_log("public key validated")
				)
				add_x509_public_key(x509cert, valid_until, DAL_SIGNED);
			}
			else
			{
				plog("X.509 certificate rejected");
				free_x509cert(x509cert);
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
bool verify_x509cert(const x509cert_t *cert, bool strict, time_t *until)
{
	int pathlen;

	*until = 0;

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		certificate_t *certificate = cert->cert;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer  = certificate->get_issuer(certificate);
		x509_t *x509 = (x509_t*)certificate;
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		x509cert_t *issuer_cert;
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

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && (x509->get_flags(x509) & X509_SELF_SIGNED))
		{
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca")
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
	plog("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	return FALSE;
}

/**
 * List all X.509 certs in a chained list
 */
void list_x509cert_chain(const char *caption, x509cert_t* cert,
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

		if (flags == X509_NONE || (flags & x509->get_flags(x509)))
		{
			enumerator_t *enumerator;
			char buf[BUF_LEN];
			char *pos = buf;
			int len = BUF_LEN;
			bool first_altName = TRUE;
			identification_t *id;
			time_t notBefore, notAfter;
			public_key_t *key;
			chunk_t serial, keyid, subjkey, authkey;
			cert_t c;

			c.type = CERT_X509_SIGNATURE;
			c.u.x509 = cert;

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
				serial = x509->get_serial(x509);
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
			if (key);
			{
				whack_log(RC_COMMENT, "  pubkey:    %N %4d bits%s",
					key_type_names, key->get_type(key),
					key->get_keysize(key) * BITS_PER_BYTE,				
					cert->smartcard ? ", on smartcard" :
					(has_private_key(c)? ", has private key" : ""));

				if (key->get_fingerprint(key, KEY_ID_PUBKEY_INFO_SHA1, &keyid))
				{
					whack_log(RC_COMMENT, "  keyid:     %#B", &keyid);
				}
				if (key->get_fingerprint(key, KEY_ID_PUBKEY_SHA1, &subjkey))
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
		}
		cert = cert->next;
	}
}

/**
 * List all X.509 end certificates in a chained list
 */
void list_x509_end_certs(bool utc)
{
	list_x509cert_chain("End Entity", x509certs, X509_NONE, utc);
}
