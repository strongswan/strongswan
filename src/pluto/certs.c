/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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
 *
 * RCSID $Id$
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <freeswan.h>
#include <ipsec_policy.h>

#include "asn1/asn1.h"

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "pem.h"
#include "certs.h"
#include "pkcs1.h"

/**
 * used for initializatin of certs
 */
const cert_t empty_cert = {CERT_NONE, {NULL}};

/**
 * extracts the certificate to be sent to the peer
 */
chunk_t get_mycert(cert_t cert)
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
 *  Loads a PKCS#1 or PGP private RSA key file
 */
err_t load_rsa_private_key(char* filename, prompt_pass_t *pass,
						   RSA_private_key_t *key)
{
	err_t ugh = NULL;
	bool pgp = FALSE;
	chunk_t blob = chunk_empty;

	char *path = concatenate_paths(PRIVATE_KEY_PATH, filename);

	if (load_coded_file(path, pass, "private key", &blob, &pgp))
	{
		if (pgp)
		{
			if (!parse_pgp(blob, NULL, key))
				ugh = "syntax error in PGP private key file";
		}
		else
		{
			if (!pkcs1_parse_private_key(blob, key))
				ugh = "syntax error in PKCS#1 private key file";
		}
		free(blob.ptr);
	}
	else
		ugh = "error loading RSA private key file";

	return ugh;
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
			*pgpcert = empty_pgpcert;
			if (parse_pgp(blob, pgpcert, NULL))
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

