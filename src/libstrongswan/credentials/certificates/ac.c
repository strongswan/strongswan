/*
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2002-2008 Andreas Steffen
 *
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
 * $Id: ac.h 3300 2007-10-12 21:53:18Z andreas $
 */

#include <library.h>
#include <debug.h>
#include <asn1/pem.h>

#include "ac.h"

/*
 * Defined in header.
 */
ac_t* ac_create_from_file(char *path)
{
	ac_t *ac;
	bool pgp = FALSE;
	chunk_t chunk;
	
	if (!pem_asn1_load_file(path, NULL, &chunk, &pgp))
	{
		DBG1("  could not load attr cert file '%s'", path);
		return NULL;
	}
/*	ac = (ac_t*)lib->creds->create(lib->creds,
								   CRED_CERTIFICATE, CERT_X509_AC,
								   BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
*/
	ac = NULL;
	if (ac == NULL)
	{
		DBG1("  could not parse loaded attr cert file '%s'", path);
		return NULL;
	}
	DBG1("  loaded attr cert file '%s'", path);
	return ac;
}


