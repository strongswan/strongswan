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

typedef struct private_builder_t private_builder_t;

struct private_builder_t {
	/** implements builder interface */
	builder_t public;
	/** built credential */
	union {
		void *cred;
		cert_t *cert;
		x509crl_t *crl;
		x509acert_t *ac;
	};
};

/**
 * builder add function for certificates
 */
static void cert_add(private_builder_t *this, builder_part_t part, ...)
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
			if (parse_pgp(chunk_clone(blob), pgpcert))
			{
				this->cert = malloc_thing(cert_t);
				*this->cert = cert_empty;
				this->cert->type = CERT_PGP;
				this->cert->u.pgp = pgpcert;
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
			if (parse_x509cert(chunk_clone(blob), 0, x509cert))
			{
				this->cert = malloc_thing(cert_t);
				*this->cert = cert_empty;
				this->cert->type = CERT_X509_SIGNATURE;
				this->cert->u.x509 = x509cert;
			}
			else
			{
				plog("  error in X.509 certificate");
				free_x509cert(x509cert);
			}
			break;
		}
		default:
			if (this->cert)
			{
				switch (this->cert->type)
				{
					case CERT_X509_SIGNATURE:
						free_x509cert(this->cert->u.x509);
						break;
					case CERT_PGP:
						free_pgpcert(this->cert->u.pgp);
						break;
					default:
						break;
				}
				free(this->cert);
			}
			builder_cancel(&this->public);
			break;
	}
}

/**
 * builder add function for attribute certificates
 */
static void ac_add(private_builder_t *this, builder_part_t part, ...)
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
	
			this->ac = malloc_thing(x509acert_t);

			*this->ac = empty_ac;

			if (!parse_ac(chunk_clone(blob), this->ac) &&
				!verify_x509acert(this->ac, FALSE))
			{
				free_acert(this->ac);
				this->ac = NULL;
			}
			break;
		}
		default:
			if (this->ac)
			{
				free_acert(this->ac);
			}
			builder_cancel(&this->public);
			break;
	}
}

/**
 * builder add function for crls
 */
static void crl_add(private_builder_t *this, builder_part_t part, ...)
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

			this->crl = malloc_thing(x509crl_t);
			*this->crl = empty_x509crl;

			if (!parse_x509crl(chunk_clone(blob), 0, this->crl))
			{
				plog("  error in X.509 crl");
				free_crl(this->crl);
				this->crl = NULL;
			}
			break;
		}
		default:
			if (this->crl)
			{
				free_crl(this->crl);
			}
			builder_cancel(&this->public);
			break;
	}
}

/**
 * builder build function
 */
static void *build(private_builder_t *this)
{
	void *cred;
	
	cred = this->cred;
	free(this);
	
	return cred;
}

/**
 * builder for pluto credentials
 */
static builder_t *builder(int subtype)
{
	private_builder_t *this = malloc_thing(private_builder_t);
	
	switch (subtype)
	{
		case CERT_PLUTO_CERT:
			this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))cert_add;
			break;
		case CERT_PLUTO_AC:
			this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))ac_add;
			break;
		case CERT_PLUTO_CRL:
			this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))crl_add;
			break;
		default:
			free(this);
			return NULL;
	}
	this->public.build = (void*(*)(builder_t*))build;
	this->cred = NULL;
	
	return &this->public;
}

void init_builder(void)
{
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT,
							(builder_constructor_t)builder);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_AC,
							(builder_constructor_t)builder);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL,
							(builder_constructor_t)builder);
}

void free_builder(void)
{
	lib->creds->remove_builder(lib->creds, (builder_constructor_t)builder);
}

