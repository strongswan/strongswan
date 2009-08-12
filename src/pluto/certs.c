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

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "pem.h"
#include "certs.h"
#include "whack.h"

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
		return cert.u.pgp->certificate;
	case CERT_X509_SIGNATURE:
		return cert.u.x509->certificate;
	default:
		return chunk_empty;
	}
}

public_key_t* cert_get_public_key(const cert_t cert)
{
	switch (cert.type)
	{
		case CERT_PGP:
			return cert.u.pgp->public_key;
			break;
		case CERT_X509_SIGNATURE:
			return cert.u.x509->public_key;
			break;
		default:
			return NULL;
	}
}

/* load a coded key or certificate file with autodetection
 * of binary DER or base64 PEM ASN.1 formats and armored PGP format
 */
bool load_coded_file(char *filename, prompt_pass_t *pass, const char *type,
					 chunk_t *blob, bool *pgp)
{
	err_t ugh = NULL;

	FILE *fd = fopen(filename, "r");

	if (fd)
	{
		int bytes;
		fseek(fd, 0, SEEK_END );
		blob->len = ftell(fd);
		rewind(fd);
		blob->ptr = malloc(blob->len);
		bytes = fread(blob->ptr, 1, blob->len, fd);
		fclose(fd);
		plog("  loaded %s file '%s' (%d bytes)", type, filename, bytes);

		*pgp = FALSE;

		/* try DER format */
		if (is_asn1(*blob))
		{
			DBG(DBG_PARSING,
				DBG_log("  file coded in DER format");
			)
			return TRUE;
		}

		/* try PEM format */
		ugh = pemtobin(blob, pass, filename, pgp);

		if (ugh == NULL)
		{
			if (*pgp)
			{
				DBG(DBG_PARSING,
					DBG_log("  file coded in armored PGP format");
				)
				return TRUE;
			}
			if (is_asn1(*blob))
			{
				DBG(DBG_PARSING,
					DBG_log("  file coded in PEM format");
				)
				return TRUE;
			}
			ugh = "file coded in unknown format, discarded";
		}

		/* a conversion error has occured */
		plog("  %s", ugh);
		free(blob->ptr);
		*blob = chunk_empty;
	}
	else
	{
		plog("  could not open %s file '%s'", type, filename);
	}
	return FALSE;
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
 *  Loads a PKCS#1 or PGP privatekey file
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
	if (key == NULL)
	{
		plog("  syntax error in private key file");
	}
	return key;
}

/**
 *  Loads a X.509 or OpenPGP certificate
 */
bool load_cert(char *filename, const char *label, cert_t *cert)
{
	bool pgp = FALSE;
	chunk_t blob = chunk_empty;

	/* initialize cert struct */
	cert->type = CERT_NONE;
	cert->u.x509 = NULL;

	if (load_coded_file(filename, NULL, label, &blob, &pgp))
	{
		if (pgp)
		{
			pgpcert_t *pgpcert = malloc_thing(pgpcert_t);
			*pgpcert = pgpcert_empty;
			if (parse_pgp(blob, pgpcert))
			{
				cert->type = CERT_PGP;
				cert->u.pgp = pgpcert;
				return TRUE;
			}
			else
			{
				plog("  error in OpenPGP certificate");
				free_pgpcert(pgpcert);
				return FALSE;
			}
		}
		else
		{
			x509cert_t *x509cert = malloc_thing(x509cert_t);
			*x509cert = empty_x509cert;
			if (parse_x509cert(blob, 0, x509cert))
			{
				cert->type = CERT_X509_SIGNATURE;
				cert->u.x509 = x509cert;
				return TRUE;
			}
			else
			{
				plog("  error in X.509 certificate");
				free_x509cert(x509cert);
				return FALSE;
			}
		}
	}
	return FALSE;
}

/**
 *  Loads a host certificate
 */
bool load_host_cert(char *filename, cert_t *cert)
{
	char *path = concatenate_paths(HOST_CERT_PATH, filename);

	return load_cert(path, "host cert", cert);
}

/**
 *  Loads a CA certificate
 */
bool load_ca_cert(char *filename, cert_t *cert)
{
	char *path = concatenate_paths(CA_CERT_PATH, filename);

	return load_cert(path, "CA cert", cert);
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

