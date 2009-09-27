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

#include <freeswan.h>

#include "library.h"
#include "asn1/asn1.h"
#include "credentials/certificates/certificate.h"

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "certs.h"
#include "whack.h"
#include "builder.h"

/**
 * used for initializatin of certs
 */
const cert_t cert_empty = {CERT_NONE, {NULL}};

/**
 * extracts the certificate to be sent to the peer
 */
chunk_t cert_get_encoding(cert_t cert)
{
	switch (cert.type)
	{
	case CERT_PGP:
		return chunk_clone(cert.u.pgp->certificate);
	case CERT_X509_SIGNATURE:
		return cert.u.x509->cert->get_encoding(cert.u.x509->cert);
	default:
		return chunk_empty;
	}
}

public_key_t* cert_get_public_key(const cert_t cert)
{
	switch (cert.type)
	{
		case CERT_PGP:
		{
			public_key_t *public_key = cert.u.pgp->public_key;

			return public_key->get_ref(public_key);
		}
		case CERT_X509_SIGNATURE:
		{
			certificate_t *certificate = cert.u.x509->cert;

			return certificate->get_public_key(certificate);
		}
		default:
			return NULL;
	}
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
bool load_cert(char *filename, const char *label, cert_t *out)
{
	cert_t *cert;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT,
							  BUILD_FROM_FILE, filename, BUILD_END);
	if (cert)
	{
		/* the API passes an empty cert_t, we move over and free the built one */
		plog("  loaded %s certificate from '%s'", label, filename);
		*out = *cert;
		free(cert);
		return TRUE;
	}
	return FALSE;
}

/**
 *  Loads a host certificate
 */
bool load_host_cert(char *filename, cert_t *cert)
{
	char *path = concatenate_paths(HOST_CERT_PATH, filename);

	return load_cert(path, "host", cert);
}

/**
 *  Loads a CA certificate
 */
bool load_ca_cert(char *filename, cert_t *cert)
{
	char *path = concatenate_paths(CA_CERT_PATH, filename);

	return load_cert(path, "CA", cert);
}

/**
 * establish equality of two certificates
 */
bool same_cert(const cert_t *a, const cert_t *b)
{
	return a->type == b->type && a->u.x509 == b->u.x509;
}

/**
 * for each link pointing to the certificate increase the count by one
 */
void share_cert(cert_t cert)
{
	switch (cert.type)
	{
	case CERT_PGP:
		share_pgpcert(cert.u.pgp);
		break;
	case CERT_X509_SIGNATURE:
		share_x509cert(cert.u.x509);
		break;
	default:
		break;
	}
}

/*  release of a certificate decreases the count by one
 "  the certificate is freed when the counter reaches zero
 */
void
release_cert(cert_t cert)
{
   switch (cert.type)
	{
	case CERT_PGP:
		release_pgpcert(cert.u.pgp);
		break;
	case CERT_X509_SIGNATURE:
		release_x509cert(cert.u.x509);
		break;
	default:
		break;
	}
}

/*
 *  list all X.509 and OpenPGP end certificates
 */
void
list_certs(bool utc)
{
	list_x509_end_certs(utc);
	list_pgp_end_certs(utc);
}

