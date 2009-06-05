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
 
/**
 * @defgroup pgpi pgp
 * @{ @ingroup pgp
 */

#ifndef PGP_H_
#define PGP_H_

typedef enum pgp_sym_alg_t pgp_sym_alg_t;

#include <chunk.h>
#include <enum.h>

/**
 * OpenPGP symmetric key algorithms defined in section 9.2 of RFC 4880
 */
enum pgp_sym_alg_t {
	PGP_SYM_ALG_PLAIN    =  0,
	PGP_SYM_ALG_IDEA     =  1,
	PGP_SYM_ALG_3DES     =  2,
	PGP_SYM_ALG_CAST5    =  3,
	PGP_SYM_ALG_BLOWFISH =  4,
	PGP_SYM_ALG_SAFER    =  5,
	PGP_SYM_ALG_DES      =  6,
	PGP_SYM_ALG_AES_128  =  7,
	PGP_SYM_ALG_AES_192  =  8,
	PGP_SYM_ALG_AES_256  =  9,
	PGP_SYM_ALG_TWOFISH  = 10
};

/**
 * Enum names for pgp_sym_alg_t
 */
extern enum_name_t *pgp_sym_alg_names;

#define PGP_INVALID_LENGTH	0xffffffff

/**
 * Returns the length of an OpenPGP (RFC 4880) packet
 * The blob pointer is advanced past the length field
 *
 * @param blob		pointer to an OpenPGP blob
 * @param len		size of the length field
 * @return			length of the next OpenPGP packet
 */
size_t pgp_length(chunk_t *blob, size_t len);

#endif /** PGP_H_ @}*/
