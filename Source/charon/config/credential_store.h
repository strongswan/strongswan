/**
 * @file credential_store.h
 * 
 * @brief Interface credential_store_t.
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

#ifndef CREDENTIAL_STORE_H_
#define CREDENTIAL_STORE_H_

#include <types.h>
#include <transforms/rsa/rsa_private_key.h>
#include <transforms/rsa/rsa_public_key.h>


typedef struct credential_store_t credential_store_t;

/**
 * @brief The interface for a credential_store backend.
 * 
 * @b Constructors:
 * 	- stroke_create()
 * 
 * @ingroup config
 */
struct credential_store_t { 

	/**
	 * @brief Returns the preshared secret of a specific ID.
	 * 
	 * The returned chunk must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param identification		identification_t object identifiying the secret.
	 * @param[out] preshared_secret	the preshared secret will be written there.
	 * 
	 * @return		
	 * 								- NOT_FOUND	if no preshared secrets for specific ID could be found
	 * 								- SUCCESS
	 */	
	status_t (*get_shared_secret) (credential_store_t *this, identification_t *identification, chunk_t *preshared_secret);
	
	/**
	 * @brief Returns the RSA public key of a specific ID.
	 * 
	 * The returned rsa_public_key_t must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param identification		identification_t object identifiying the key.
	 * @param[out] public_key		the public key will be written there
	 * 
	 * @return		
	 * 								- NOT_FOUND	if no key is configured for specific id
	 * 								- SUCCESS
	 */	
	status_t (*get_rsa_public_key) (credential_store_t *this, identification_t *identification, rsa_public_key_t **public_key);
	
	/**
	 * @brief Returns the RSA private key of a specific ID.
	 * 
	 * The returned rsa_private_key_t must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param identification		identification_t object identifiying the key
	 * @param[out] private_key		the private key will be written there
	 * 
	 * @return		
	 * 								- NOT_FOUND	if no key is configured for specific id
	 * 								- SUCCESS
	 */	
	status_t (*get_rsa_private_key) (credential_store_t *this, identification_t *identification, rsa_private_key_t **private_key);

	/**
	 * @brief Destroys a credential_store_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (credential_store_t *this);
};

#endif /*CREDENTIAL_STORE_H_*/
