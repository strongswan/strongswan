/**
 * @file hmac_signer.h
 * 
 * @brief Interface of hmac_signer_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef _HMAC_SIGNER_H_
#define _HMAC_SIGNER_H_

#include <transforms/signers/signer.h>
#include <transforms/hashers/hasher.h>

typedef struct hmac_signer_t hmac_signer_t;

/**
 * @brief Implementation of hmac_signer_t interface using the
 * HMAC algorithm in combination with eather MD5 or SHA1.
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
 * @param hash_algorithm		Hash algorithm to use with signer
 * 
 * @return
 * 							- hmac_signer_t if successfully
 * 							- NULL if out of ressources
 * 
 * @ingroup signers
 */
hmac_signer_t *hmac_signer_create(hash_algorithm_t hash_algoritm);


#endif //_HMAC_SIGNER_H_
