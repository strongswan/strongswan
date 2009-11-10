/* Certificate support for IKE authentication
 * Copyright (C) 2002-2009 Andreas Steffen
 *
 * HSR - Hochschule fuer Technik Rapperswil
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
#include <time.h>

#include <freeswan.h>

#include <library.h>
#include <asn1/asn1.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/pgp_certificate.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "certs.h"
#include "whack.h"
#include "fetch.h"
#include "keys.h"
#include "builder.h"

/**
 * Initialization
 */
const cert_t cert_empty = {
	NULL   , /* cert */
	NULL   , /* *next */
	  0    , /* count */
	FALSE    /* smartcard */
};

/**
 * Chained lists of X.509 and PGP end entity certificates
 */
static cert_t *certs = NULL;

/**
 *  Free a pluto certificate
 */
void cert_free(cert_t *cert)
{
	if (cert)
	{
		certificate_t *certificate = cert->cert;

		if (certificate)
		{
			certificate->destroy(certificate);
		}
		free(cert);
	}
}

/**
 *  Add a pluto end entity certificate to the chained list
 */
cert_t* cert_add(cert_t *cert)
{
	certificate_t *certificate = cert->cert;
	cert_t *c = certs;

	while (c != NULL)
	{
		if (certificate->equals(certificate, c->cert)) /* already in chain, free cert */
		{
			cert_free(cert);
			return c;
		}
		c = c->next;
	}

	/* insert new cert at the root of the chain */
	lock_certs_and_keys("cert_add");
	cert->next = certs;
	certs = cert;
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  cert inserted")
	)
	unlock_certs_and_keys("cert_add");
	return cert;
}

/**
 * Passphrase callback to read from whack fd
 */
chunk_t whack_pass_cb(prompt_pass_t *pass, int try)
{
	int n;

	if (try > MAX_PROMPT_PASS_TRIALS)
	{
		whack_log(RC_LOG_SERIOUS, "invalid passphrase, too many trials");
		return chunk_empty;
	}
	if (try == 1)
	{
		whack_log(RC_ENTERSECRET, "need passphrase for 'private key'");
	}
	else
	{
		whack_log(RC_ENTERSECRET, "invalid passphrase, please try again");
	}

	n = read(pass->fd, pass->secret, PROMPT_PASS_LEN);

	if (n == -1)
	{
		whack_log(RC_LOG_SERIOUS, "read(whackfd) failed");
		return chunk_empty;
	}

	pass->secret[n-1] = '\0';

	if (strlen(pass->secret) == 0)
	{
		whack_log(RC_LOG_SERIOUS, "no passphrase entered, aborted");
		return chunk_empty;
	}
	return chunk_create(pass->secret, strlen(pass->secret));
}

/**
 *  Loads a PKCS#1 or PGP private key file
 */
private_key_t* load_private_key(char* filename, prompt_pass_t *pass,
								key_type_t type)
{
	private_key_t *key = NULL;
	char *path;

	path = concatenate_paths(PRIVATE_KEY_PATH, filename);
	if (pass && pass->prompt && pass->fd != NULL_FD)
	{	/* use passphrase callback */
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path,
								 BUILD_PASSPHRASE_CALLBACK, whack_pass_cb, pass,
								 BUILD_END);
		if (key)
		{
			whack_log(RC_SUCCESS, "valid passphrase");
		}
	}
	else if (pass)
	{	/* use a given passphrase */
		chunk_t password = chunk_create(pass->secret, strlen(pass->secret));
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path,
								 BUILD_PASSPHRASE, password, BUILD_END);
	}
	else
	{	/* no passphrase */
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path, BUILD_END);

	}
	if (key)
	{
		plog("  loaded private key from '%s'", filename);
	}
	else
	{
		plog("  syntax error in private key file");
	}
	return key;
}

/**
 *  Loads a X.509 or OpenPGP certificate
 */
cert_t* load_cert(char *filename, const char *label, x509_flag_t flags)
{
	cert_t *cert;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT,
							  BUILD_FROM_FILE, filename,
							  BUILD_X509_FLAG, flags,
							  BUILD_END);
	if (cert)
	{
		plog("  loaded %s certificate from '%s'", label, filename);
	}
	return cert;
}

/**
 *  Loads a host certificate
 */
cert_t* load_host_cert(char *filename)
{
	char *path = concatenate_paths(HOST_CERT_PATH, filename);

	return load_cert(path, "host", X509_NONE);
}

/**
 *  Loads a CA certificate
 */
cert_t* load_ca_cert(char *filename)
{
	char *path = concatenate_paths(CA_CERT_PATH, filename);

	return load_cert(path, "CA", X509_NONE);
}

/**
 * for each link pointing to the certificate increase the count by one
 */
void cert_share(cert_t *cert)
{
	if (cert != NULL)
	{
		cert->count++;
	}
}

/*  release of a certificate decreases the count by one
 *  the certificate is freed when the counter reaches zero
 */
void cert_release(cert_t *cert)
{
	if (cert && --cert->count == 0)
	{
		cert_t **pp = &certs;
		while (*pp != cert)
		{
			pp = &(*pp)->next;
		}
		*pp = cert->next;
		cert_free(cert);
	}
}

/**
 *  List all PGP end certificates in a chained list
 */
void list_pgp_end_certs(bool utc)
{
	cert_t *cert = certs;
	time_t now = time(NULL);
	bool first = TRUE;


	while (cert != NULL)
	{
		certificate_t *certificate = cert->cert;

		if (certificate->get_type(certificate) == CERT_GPG)
		{
			time_t created, until;
			public_key_t *key;
			identification_t *userid = certificate->get_subject(certificate);
			pgp_certificate_t *pgp_cert = (pgp_certificate_t*)certificate;
			chunk_t fingerprint = pgp_cert->get_fingerprint(pgp_cert);

			if (first)
			{
				whack_log(RC_COMMENT, " ");
				whack_log(RC_COMMENT, "List of PGP End Entity Certificates:");
				first = false;
			}
			whack_log(RC_COMMENT, " ");
			whack_log(RC_COMMENT, "  userid:   '%Y'", userid);
			whack_log(RC_COMMENT, "  digest:    %#B", &fingerprint);

			/* list validity */
			certificate->get_validity(certificate, &now, &created, &until);
			whack_log(RC_COMMENT, "  created:   %T", &created, utc);
			whack_log(RC_COMMENT, "  until:     %T %s%s", &until, utc,
					check_expiry(until, CA_CERT_WARNING_INTERVAL, TRUE),
					(until == TIME_32_BIT_SIGNED_MAX) ? " (expires never)":"");

			key = certificate->get_public_key(certificate);
			if (key)
			{
				chunk_t keyid;

				whack_log(RC_COMMENT, "  pubkey:    %N %4d bits%s",
						key_type_names, key->get_type(key),
						key->get_keysize(key) * BITS_PER_BYTE,
						has_private_key(cert)? ", has private key" : "");
				if (key->get_fingerprint(key, KEY_ID_PUBKEY_INFO_SHA1, &keyid))
				{
					whack_log(RC_COMMENT, "  keyid:     %#B", &keyid);
				}
				if (key->get_fingerprint(key, KEY_ID_PUBKEY_SHA1, &keyid))
				{
					whack_log(RC_COMMENT, "  subjkey:   %#B", &keyid);
				}
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
	list_x509cert_chain("End Entity", certs, X509_NONE, utc);
}

/**
 *  list all X.509 and OpenPGP end certificates
 */
void cert_list(bool utc)
{
	list_x509_end_certs(utc);
	list_pgp_end_certs(utc);
}

