/**
 * @file rsa_public_key.h
 * 
 * @brief Interface rsa_public_key_t.
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

#ifndef RSA_PUBLIC_KEY_H_
#define RSA_PUBLIC_KEY_H_

#include <gmp.h>

#include <types.h>
#include <definitions.h>


typedef struct rsa_public_key_t rsa_public_key_t;

/**
 * @brief RSA public key with associated functions.
 * 
 * Currently only supports signature verification using
 * the EMSA encoding (see PKCS1)
 * 
 * @ingroup asymmetrics
 */
struct rsa_public_key_t {

	status_t (*verify_emsa_pkcs1_signature) (rsa_public_key_t *this, chunk_t data, chunk_t signature);
	
	status_t (*set_key) (rsa_public_key_t *this, chunk_t key);
	
	status_t (*get_key) (rsa_public_key_t *this, chunk_t *key);
	
	status_t (*load_key) (rsa_public_key_t *this, char *file);
	
	status_t (*save_key) (rsa_public_key_t *this, char *file);

	void (*destroy) (rsa_public_key_t *this);
};

/**
 * 
 * @ingroup asymmetrics
 */
rsa_public_key_t *rsa_public_key_create();

#endif /*RSA_PUBLIC_KEY_H_*/
