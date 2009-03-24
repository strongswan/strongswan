/*
 * Copyright (C) 2008 Tobias Brunner
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

/**
 * @defgroup openssl_util openssl_util
 * @{ @ingroup openssl_p
 */

#ifndef OPENSSL_UTIL_H_
#define OPENSSL_UTIL_H_

#include <library.h>
#include <openssl/bn.h>

/**
 * Returns the length in bytes of a field element
 */
#define EC_FIELD_ELEMENT_LEN(group) ((EC_GROUP_get_degree(group) + 7) / 8)

/**
 * Creates a hash of a given type of a chunk of data.
 * 
 * Note: this function allocates memory for the hash
 * 
 * @param hash_type	NID of the hash
 * @param data		the chunk of data to hash
 * @param hash		chunk that contains the hash
 * @return 			TRUE on success, FALSE otherwise
 */
bool openssl_hash_chunk(int hash_type, chunk_t data, chunk_t *hash);

/**
 * Concatenates two bignums into a chunk, thereby enfocing the length of
 * a single BIGNUM, if necessary, by pre-pending it with zeros.
 * 
 * Note: this function allocates memory for the chunk
 * 
 * @param len		the length of a single BIGNUM
 * @param a			first BIGNUM
 * @param b			second BIGNUM
 * @param chunk		resulting chunk
 * @return			TRUE on success, FALSE otherwise
 */
bool openssl_bn_cat(int len, BIGNUM *a, BIGNUM *b, chunk_t *chunk);

/**
 * Splits a chunk into two bignums of equal binary length.
 * 
 * @param chunk		a chunk that contains the two BIGNUMs
 * @param a			first BIGNUM
 * @param b			second BIGNUM
 * @return			TRUE on success, FALSE otherwise
 */
bool openssl_bn_split(chunk_t chunk, BIGNUM *a, BIGNUM *b);

#endif /** OPENSSL_UTIL_H_ @}*/
