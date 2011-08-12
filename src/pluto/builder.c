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
#include <time.h>

#include <freeswan.h>

#include <library.h>
#include <credentials/certificates/certificate.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "certs.h"
#include "crl.h"

/**
 * Load a certificate
 */
static cert_t *builder_load_cert(certificate_type_t type, va_list args)
{
	x509_flag_t flags = 0;
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
			case BUILD_X509_FLAG:
				flags |= va_arg(args, x509_flag_t);
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
		cert_t *cert = malloc_thing(cert_t);

		*cert = cert_empty;

		if (pgp)
		{
			cert->cert = lib->creds->create(lib->creds,
										   CRED_CERTIFICATE, CERT_GPG,
										   BUILD_BLOB_PGP, blob,
										   BUILD_END);
		}
		else
		{
			cert->cert = lib->creds->create(lib->creds,
										   CRED_CERTIFICATE, CERT_X509,
										   BUILD_BLOB_ASN1_DER, blob,
										   BUILD_X509_FLAG, flags,
										   BUILD_END);
		}
		if (cert->cert)
		{
			return cert;
		}
		plog("  error in X.509 certificate");
		cert_free(cert);
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
		crl->next = NULL;
		crl->distributionPoints = linked_list_create();
		crl->crl = lib->creds->create(lib->creds,
									  CRED_CERTIFICATE, CERT_X509_CRL,
									  BUILD_BLOB_ASN1_DER, blob,
									  BUILD_END);
		if (crl->crl)
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
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT, FALSE,
							(builder_function_t)builder_load_cert);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL, FALSE,
							(builder_function_t)builder_load_crl);
}

void free_builder(void)
{
	lib->creds->remove_builder(lib->creds, (builder_function_t)builder_load_cert);
	lib->creds->remove_builder(lib->creds, (builder_function_t)builder_load_crl);
}

