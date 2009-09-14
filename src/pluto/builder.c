/* Pluto certificate/CRL/AC builder hooks.
 * Copyright (C) 2002-2009 Andreas Steffen
 * Copyright (C) 2009 Martin Willi
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

#include "builder.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <freeswan.h>

#include <library.h>
#include <credentials/certificates/certificate.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "certs.h"
#include "ac.h"
#include "crl.h"

/**
 * Load a certificate
 */
static cert_t *builder_load_cert(certificate_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;
	bool pgp = FALSE;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_PGP:
				pgp = TRUE;
				/* FALL */
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.ptr)
	{
		if (pgp)
		{
			pgpcert_t *pgpcert = malloc_thing(pgpcert_t);
			*pgpcert = pgpcert_empty;
			if (parse_pgp(chunk_clone(blob), pgpcert))
			{
				cert_t *cert = malloc_thing(cert_t);
				*cert = cert_empty;
				cert->type = CERT_PGP;
				cert->u.pgp = pgpcert;
				return cert;
			}
			plog("  error in OpenPGP certificate");
			free_pgpcert(pgpcert);
		}
		else
		{
			x509cert_t *x509cert = malloc_thing(x509cert_t);
			*x509cert = empty_x509cert;
			if (parse_x509cert(chunk_clone(blob), 0, x509cert))
			{
				cert_t *cert = malloc_thing(cert_t);
				*cert = cert_empty;
				cert->type = CERT_X509_SIGNATURE;
				cert->u.x509 = x509cert;
				return cert;
			}
			plog("  error in X.509 certificate");
			free_x509cert(x509cert);
		}
	}
	return NULL;
}

/**
 * Load a attribute certificate
 */
static x509acert_t *builder_load_ac(certificate_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;
	x509acert_t *ac;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.ptr)
	{
		ac = malloc_thing(x509acert_t);
		*ac = empty_ac;
		if (parse_ac(chunk_clone(blob), ac) &&
			verify_x509acert(ac, FALSE))
		{
			return ac;
		}
		plog("  error in X.509 AC");
		free_acert(ac);
	}
	return NULL;
}

/**
 * Load a CRL
 */
static x509crl_t *builder_load_crl(certificate_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;
	x509crl_t *crl;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.ptr)
	{
		crl = malloc_thing(x509crl_t);
		*crl = empty_x509crl;
		if (parse_x509crl(chunk_clone(blob), 0, crl))
		{
			return crl;
		}
		plog("  error in X.509 crl");
		free_crl(crl);
	}
	return NULL;
}

void init_builder(void)
{
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT,
							(builder_function_t)builder_load_cert);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_AC,
							(builder_function_t)builder_load_ac);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL,
							(builder_function_t)builder_load_crl);
}

void free_builder(void)
{
	lib->creds->remove_builder(lib->creds, (builder_function_t)builder_load_cert);
	lib->creds->remove_builder(lib->creds, (builder_function_t)builder_load_ac);
	lib->creds->remove_builder(lib->creds, (builder_function_t)builder_load_crl);
}

