/*
 * Copyright (C) 2002-2009 Andreas Steffen
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
 */
 
#include "pgp.h"

ENUM(pgp_sym_alg_names, PGP_SYM_ALG_PLAIN, PGP_SYM_ALG_TWOFISH,
	"PLAINTEXT",
	"IDEA",
	"3DES",
	"CAST5",
	"BLOWFISH",
	"SAFER",
	"DES",
	"AES_128",
	"AES_192",
	"AES_256",
	"TWOFISH"
);

/*
 * Defined in header.
 */
size_t pgp_length(chunk_t *blob, size_t len)
{
	size_t size = 0;

	if (len > blob->len)
	{
		return PGP_INVALID_LENGTH;
	}
	blob->len -= len;

	while (len-- > 0)
	{
		size = 256*size + *blob->ptr++;
	}
	return size;
}

