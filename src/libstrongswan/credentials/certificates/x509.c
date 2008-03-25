/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * $Id$
 */

#include <library.h>
#include <debug.h>
#include <asn1/pem.h>

#include "x509.h"

ENUM(x509_flag_names, X509_CA, X509_SELF_SIGNED,
	"X509_CA",
	"X509_AA",
	"X509_OCSP_SIGNER",
	"X509_SELF_SIGNED",
);

/*
 * Defined in header.
 */
x509_t* x509_create_from_file(char *path, char *label, x509_flag_t flag)
{
	bool pgp = FALSE;
	chunk_t chunk;
	x509_t *x509;
	certificate_t *cert;
	time_t notBefore, notAfter, now;
	
	if (!pem_asn1_load_file(path, NULL, &chunk, &pgp))
	{
		DBG1("  could not load %s file '%s'", label, path);
		return NULL;
	}
	x509 = (x509_t*)lib->creds->create(lib->creds,
									   CRED_CERTIFICATE, CERT_X509,
									   BUILD_BLOB_ASN1_DER, chunk,
									   BUILD_X509_FLAG, flag,
									   BUILD_END);
	if (x509 == NULL)
	{
		DBG1("  could not parse loaded %s file '%s'",label, path);
		return NULL;
	}
	DBG1("  loaded %s file '%s'", label, path);
	
	/* check validity */
	cert = &x509->interface;
	now = time(NULL);
	cert->get_validity(cert, &now, &notBefore, &notAfter);
	if (now > notAfter)
	{
		DBG1("  certificate expired at %T, discarded", &notAfter);
		cert->destroy(cert);
		return NULL;
	}
	if (now < notBefore)
	{
		DBG1("  certificate not valid before %T", &notBefore);
	}
	return x509;
}


