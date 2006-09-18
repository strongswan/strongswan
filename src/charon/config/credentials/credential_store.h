/**
 * @file credential_store.h
 * 
 * @brief Interface credential_store_t.
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
	 * @brief Returns the secret shared by two specific IDs.
	 * 
	 * The returned chunk must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param my_id					my ID identifiying the secret.
	 * @param other_id				peer ID identifying the secret.
	 * @param[out] secret			the pre-shared secret will be written there.
	 * @return
	 * 								- NOT_FOUND	if no preshared secrets for specific ID could be found
	 * 								- SUCCESS
	 *
	 */	
	status_t (*get_shared_key) (credential_store_t *this, identification_t *my_id, identification_t *other_id, chunk_t *shared_key);
	
	/**
	 * @brief Returns the RSA public key of a specific ID.
	 * 
	 * @param this					calling object
	 * @param id					identification_t object identifiying the key.
	 * @return						public key, or NULL if not found
	 */
	rsa_public_key_t* (*get_rsa_public_key) (credential_store_t *this, identification_t *id);
	
	/**
	 * @brief Returns the RSA public key of a specific ID if is trusted
	 * 
	 * @param this					calling object
	 * @param id					identification_t object identifiying the key.
	 * @return						public key, or NULL if not found or not trusted
	 */
	rsa_public_key_t* (*get_trusted_public_key) (credential_store_t *this, identification_t *id);
	
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
	 * @param this					calling object
	 * @param pubkey				public key 
	 * @return						TRUE if matching private key was found 
	 */	
	bool (*has_rsa_private_key) (credential_store_t *this, rsa_public_key_t *pubkey);

	/**
	 * @brief Returns the certificate of a specific ID.
	 * 
	 * @param this					calling object
	 * @param id					identification_t object identifiying the key.
	 * @return						certificate, or NULL if not found
	 */
	x509_t* (*get_certificate) (credential_store_t *this, identification_t *id);
	
	/**
	 * @brief Verify an X.509 certificate up to trust anchor including revocation checks
	 *
	 * @param this		calling object
	 * @param cert		certificate to be verified
	 * @param found		found a certificate copy in the credential store
	 * @return			TRUE if trusted
	 */
	bool (*verify) (credential_store_t *this, x509_t *cert, bool *found);

	/**
	 * @brief If an end certificate does not already exists in the credential store then add it.
	 *
	 * @param this		calling object
	 * @param cert		certificate to be added
	 * @return			pointer to the added or already existing certificate
	 */
	x509_t* (*add_end_certificate) (credential_store_t *this, x509_t *cert);

	/**
	 * @brief If a ca certificate does not already exists in the credential store then add it.
	 *
	 * @param this		calling object
	 * @param cert		ca certificate to be added
	 * @return			pointer to the added or already existing certificate
	 */
	x509_t* (*add_ca_certificate) (credential_store_t *this, x509_t *cert);

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
	 * @brief Lists all CRLs kept in the local credential store.
	 *
	 * @param this		calling object
	 * @param logger	logger to be used
	 * @param utc		log dates either in UTC or local time
	 */
	void (*log_crls) (credential_store_t *this, logger_t *logger, bool utc);

	/**
	 * @brief Loads trusted CA certificates from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 * @param path		directory to load certificates from
	 */
	void (*load_ca_certificates) (credential_store_t *this);
	
	/**
	 * @brief Loads CRLs from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 * @param path		directory to load crls from 
	 */
	void (*load_crls) (credential_store_t *this);
	
	/**
	 * @brief Loads secrets in ipsec.secrets
	 * 
	 * Currently, all RSA private key files must be in unencrypted form
     * either in DER or PEM format.
	 * 
	 * @param this			calling object
	 */
	void (*load_secrets) (credential_store_t *this);

	/**
	 * @brief Destroys a credential_store_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (credential_store_t *this);
};

/**
 * @brief Creates a credential_store_t instance.
 *
 * @param  strict		enforce a strict crl policy
 * @return 				credential store instance.
 * 
 * @ingroup config
 */
credential_store_t *credential_store_create(bool strict);


#endif /*CREDENTIAL_STORE_H_*/
