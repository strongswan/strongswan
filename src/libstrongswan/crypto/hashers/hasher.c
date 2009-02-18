/*
 * Copyright (C) 2005 Jan Hutter
 * Copyright (C) 2005-2006 Martin Willi
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
 * $Id$
 */

#include "hasher.h"

#include <asn1/oid.h>

ENUM(hash_algorithm_names, HASH_UNKNOWN, HASH_MD4,
	"HASH_UNKNOWN",
	"HASH_PREFERRED",
	"HASH_MD2",
	"HASH_MD5",
	"HASH_SHA1",
	"HASH_SHA256",
	"HASH_SHA384",
	"HASH_SHA512",
	"HASH_MD4"
);

/*
 * Described in header.
 */
hash_algorithm_t hasher_algorithm_from_oid(int oid)
{
	switch (oid)
	{
		case OID_MD2:
		case OID_MD2_WITH_RSA:
			return HASH_MD2;
		case OID_MD5:
		case OID_MD5_WITH_RSA:
			return HASH_MD5;
		case OID_SHA1:
		case OID_SHA1_WITH_RSA:
			return HASH_SHA1;
		case OID_SHA256:
		case OID_SHA256_WITH_RSA:
			return HASH_SHA256;
		case OID_SHA384:
		case OID_SHA384_WITH_RSA:
			return HASH_SHA384;
		case OID_SHA512:
		case OID_SHA512_WITH_RSA:
			return HASH_SHA512;
		default:
			return HASH_UNKNOWN;
	}
}

/*
 * Described in header.
 */
int hasher_algorithm_to_oid(hash_algorithm_t alg)
{
	int oid;

	switch (alg)
	{
		case HASH_MD2:
			oid = OID_MD2;
			break;
		case HASH_MD5:
			oid = OID_MD5;
			break;
		case HASH_SHA1:
			oid = OID_SHA1;
			break;
		case HASH_SHA256:
			oid = OID_SHA256;
			break;
		case HASH_SHA384:
			oid = OID_SHA384;
			break;
		case HASH_SHA512:
			oid = OID_SHA512;
			break;
		default:
			oid = OID_UNKNOWN;
	}
	return oid;
}

/*
 * Described in header.
 */
int hasher_signature_algorithm_to_oid(hash_algorithm_t alg)
{
	int oid;

	switch (alg)
	{
		case HASH_MD2:
			oid = OID_MD2_WITH_RSA;
			break;
		case HASH_MD5:
			oid = OID_MD5_WITH_RSA;
			break;
		case HASH_SHA1:
			oid = OID_SHA1_WITH_RSA;
			break;
		case HASH_SHA256:
			oid = OID_SHA256_WITH_RSA;
			break;
		case HASH_SHA384:
			oid = OID_SHA384_WITH_RSA;
			break;
		case HASH_SHA512:
			oid = OID_SHA512_WITH_RSA;
			break;
		default:
			oid = OID_UNKNOWN;
	}
	return oid;
}

