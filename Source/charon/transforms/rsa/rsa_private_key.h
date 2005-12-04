/**
 * @file rsa_private_key.h
 * 
 * @brief Interface rsa_private_key_t.
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

#ifndef RSA_PRIVATE_KEY_H_
#define RSA_PRIVATE_KEY_H_

#include <types.h>
#include <definitions.h>

#include <transforms/rsa/rsa_public_key.h>
#include <transforms/hashers/hasher.h>


typedef struct rsa_private_key_t rsa_private_key_t;

/**
 * @brief RSA private key with associated functions.
 * 
 * Currently only supports signing using EMSA encoding.
 * 
 * @ingroup asymmetrics
 */
struct rsa_private_key_t {

	status_t (*build_emsa_pkcs1_signature) (rsa_private_key_t *this, hash_algorithm_t hash_algorithm, chunk_t data, chunk_t *signature);
	
	status_t (*set_key) (rsa_private_key_t *this, chunk_t key);
	
	status_t (*get_key) (rsa_private_key_t *this, chunk_t *key);
	
	status_t (*load_key) (rsa_private_key_t *this, char *file);
	
	status_t (*save_key) (rsa_private_key_t *this, char *file);
	
	status_t (*generate_key) (rsa_private_key_t *this, size_t key_size);
	
	rsa_public_key_t *(*get_public_key) (rsa_private_key_t *this);

	void (*destroy) (rsa_private_key_t *this);
};

/**
 * Types are defined in public_key.h
 * 
 * @ingroup asymmetrics
 */
rsa_private_key_t *rsa_private_key_create();

#endif /*RSA_PRIVATE_KEY_H_*/
