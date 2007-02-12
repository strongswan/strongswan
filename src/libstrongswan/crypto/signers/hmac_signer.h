/**
 * @file hmac_signer.h
 * 
 * @brief Interface of hmac_signer_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef HMAC_SIGNER_H_
#define HMAC_SIGNER_H_

typedef struct hmac_signer_t hmac_signer_t;

#include <crypto/signers/signer.h>
#include <crypto/hashers/hasher.h>

/**
 * @brief Implementation of signer_t interface using HMAC.
 *
 * HMAC uses a standard hash function implemented in a hasher_t to build
 * a MAC.
 *
 * @ingroup signers
 */
struct hmac_signer_t {
	
	/**
	 * generic signer_t interface for this signer
	 */
	signer_t signer_interface;
};

/**
 * @brief Creates a new hmac_signer_t.
 *
 * HMAC signatures are often truncated to shorten them to a more usable, but
 * still secure enough length.
 * Block size must be equal or smaller then the hash algorithms
 * hash.
 *
 * @param hash_algoritm		Hash algorithm to use with signer
 * @param block_size		Size of resulting signature (truncated to block_size)
 * @return					
 * 							- hmac_signer_t
 * 							- NULL if hash algorithm not supported
 * 
 * @ingroup signers
 */
hmac_signer_t *hmac_signer_create(hash_algorithm_t hash_algoritm,
								  size_t block_size);


#endif /*HMAC_SIGNER_H_*/
