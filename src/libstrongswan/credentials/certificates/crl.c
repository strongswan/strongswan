/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2006 Andreas Steffen
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
#include "crl.h"

ENUM(crl_reason_names, CRL_UNSPECIFIED, CRL_REMOVE_FROM_CRL,
	"unspecified",
	"key compromise",
	"ca compromise",
	"affiliation changed",
	"superseded",
	"cessation of operation",
	"certificate hold",
	"reason #7",
	"remove from crl",
);

/*
 * Defined in header.
 */
crl_t* crl_create_from_file(char *path)
{
	crl_t *crl;
	bool pgp = FALSE;
	chunk_t chunk;
	
	if (!pem_asn1_load_file(path, NULL, &chunk, &pgp))
	{
		DBG1("  could not load crl file '%s'", path);
		return NULL;
	}
	crl = (crl_t*)lib->creds->create(lib->creds,
									 CRED_CERTIFICATE, CERT_X509_CRL,
									 BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
	if (crl == NULL)
	{
		DBG1("  could not parse loaded crl file '%s'", path);
		return NULL;
	}
	DBG1("  loaded crl file '%s'", path);
	return crl;
}
