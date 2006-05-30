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
#include <crypto/x509.h>
#include <crypto/rsa/rsa_private_key.h>
#include <crypto/rsa/rsa_public_key.h>
#include <utils/identification.h>
#include <utils/logger.h>


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
	 * @param id					identification_t object identifiying the secret.
	 * @param[out] preshared_secret	the preshared secret will be written there.
	 * @return
	 * 								- NOT_FOUND	if no preshared secrets for specific ID could be found
	 * 								- SUCCESS
	 *
	 * @todo We should use two IDs to query shared secrets, since we want to use different
	 * keys for different peers...
	 */	
	status_t (*get_shared_secret) (credential_store_t *this, identification_t *id, chunk_t *secret);
	
	/**
	 * @brief Returns the RSA public key of a specific ID.
	 * 
	 * The returned rsa_public_key_t must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param id					identification_t object identifiying the key.
	 * @return						public key, or NULL if not found
	 */
	rsa_public_key_t* (*get_rsa_public_key) (credential_store_t *this, identification_t *id);
	
	/**
	 * @brief Returns the RSA private key belonging to an RSA public key
	 * 
	 * The returned rsa_private_key_t must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param pubkey				public key 
	 * @return						private key, or NULL if not found
	 */	
	rsa_private_key_t* (*get_rsa_private_key) (credential_store_t *this, rsa_public_key_t *pubkey);

	/**
	 * @brief Is there a matching RSA private key belonging to an RSA public key?
	 * 
	 * The returned rsa_private_key_t must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param pubkey				public key 
	 * @return						TRUE if matching private key was found 
	 */	
	bool (*has_rsa_private_key) (credential_store_t *this, rsa_public_key_t *pubkey);

	/**
	 * @brief If a certificate does not already exists in the credential store then add it.
	 *
	 * @param this		calling object
	 * @param cert		certificate to be added
	 */
	void (*add_certificate) (credential_store_t *this, x509_t *cert);

	/**
	 * @brief Lists all certificates kept in the local credential store.
	 *
	 * @param this		calling object
	 * @param logger	logger to be used
	 * @param utc		log dates either in UTC or local time
	 */
	void (*log_certificates) (credential_store_t *this, logger_t *logger, bool utc);

	/**
	 * @brief Lists all CA certificates kept in the local credential store.
	 *
	 * @param this		calling object
	 * @param logger	logger to be used
	 * @param utc		log dates either in UTC or local time
	 */
	void (*log_ca_certificates) (credential_store_t *this, logger_t *logger, bool utc);

	/**
	 * @brief Destroys a credential_store_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (credential_store_t *this);
};

#endif /*CREDENTIAL_STORE_H_*/
