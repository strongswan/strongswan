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

#include "library.h"

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "certs.h"
#include "ac.h"

/**
 * currently building cert_t
 */
static cert_t *cert;

/**
 * builder add function
 */
static void cert_add(builder_t *this, builder_part_t part, ...)
{
	chunk_t blob;
	va_list args;

	va_start(args, part);
	blob = va_arg(args, chunk_t);
	va_end(args);

	switch (part)
	{
		case BUILD_BLOB_PGP:
		{
			pgpcert_t *pgpcert = malloc_thing(pgpcert_t);
			*pgpcert = pgpcert_empty;
			if (parse_pgp(blob, pgpcert))
			{
				cert->type = CERT_PGP;
				cert->u.pgp = pgpcert;
			}
			else
			{
				plog("  error in OpenPGP certificate");
				free_pgpcert(pgpcert);
			}
			break;
		}
		case BUILD_BLOB_ASN1_DER:
		{
			x509cert_t *x509cert = malloc_thing(x509cert_t);
			*x509cert = empty_x509cert;
			if (parse_x509cert(blob, 0, x509cert))
			{
				cert->type = CERT_X509_SIGNATURE;
				cert->u.x509 = x509cert;
			}
			else
			{
				plog("  error in X.509 certificate");
				free_x509cert(x509cert);
			}
			break;
		}
		default:
			builder_cancel(this);
			break;
	}
}

/**
 * builder build function
 */
static void *cert_build(builder_t *this)
{
	free(this);
	if (cert->type == CERT_NONE)
	{
		return NULL;
	}
	return cert;
}

/**
 * certificate builder in cert_t format.
 */
static builder_t *cert_builder(credential_type_t type, int subtype)
{
	builder_t *this;
	
	if (subtype != CRED_TYPE_CERTIFICATE)
	{
		return NULL;
	}
	this = malloc_thing(builder_t);
	this->add = cert_add;
	this->build = cert_build;

	cert->type = CERT_NONE;
	cert->u.x509 = NULL;
	cert->u.pgp = NULL;

	return this;
}

/**
 * currently building x509ac_t
 */
static x509acert_t *ac;

/**
 * builder add function
 */
static void ac_add(builder_t *this, builder_part_t part, ...)
{
	chunk_t blob;
	va_list args;

	switch (part)
	{
		case BUILD_BLOB_ASN1_DER:
		{
			va_start(args, part);
			blob = va_arg(args, chunk_t);
			va_end(args);
	
			ac = malloc_thing(x509acert_t);

			*ac = empty_ac;

			if (!parse_ac(blob, ac) && !verify_x509acert(ac, FALSE))
			{
				free_acert(ac);
				ac = NULL;
			}
			break;
		}
		default:
			builder_cancel(this);
			break;
	}
}

/**
 * builder build function
 */
static void *ac_build(builder_t *this)
{
	free(this);
	return ac;
}

/**
 * certificate builder in x509ac_t format.
 */
static builder_t *ac_builder(credential_type_t type, int subtype)
{
	builder_t *this;
	
	if (subtype != CRED_TYPE_AC)
	{
		return NULL;
	}
	this = malloc_thing(builder_t);
	this->add = ac_add;
	this->build = ac_build;
	
	ac = NULL;
	
	return this;
}

void init_builder(void)
{
	lib->creds->add_builder(lib->creds, CRED_PLUTO_CERT, CRED_TYPE_CERTIFICATE,
							(builder_constructor_t)cert_builder);
	lib->creds->add_builder(lib->creds, CRED_PLUTO_CERT, CRED_TYPE_AC,
							(builder_constructor_t)ac_builder);
}

void free_builder(void)
{
	lib->creds->remove_builder(lib->creds, (builder_constructor_t)cert_builder);
	lib->creds->remove_builder(lib->creds, (builder_constructor_t)ac_builder);
}

