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

typedef struct credential_store_t credential_store_t;

#include <library.h>
#include <crypto/x509.h>
#include <crypto/ca.h>
#include <crypto/rsa/rsa_private_key.h>
#include <crypto/rsa/rsa_public_key.h>
#include <utils/identification.h>


/**
 * @brief The interface for a credential_store backend.
 *
 * @b Constructors:
 *  - stroke_create()
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
	status_t (*get_shared_key) (credential_store_t *this, identification_t *my_id,
								identification_t *other_id, chunk_t *shared_key);
	
	/**
	 * @brief Returns the EAP secret for two specified IDs.
	 * 
	 * The returned chunk must be destroyed by the caller after usage.
	 * 
	 * @param this					calling object
	 * @param my_id					my ID identifiying the secret.
	 * @param other_id				peer ID identifying the secret.
	 * @param[out] eap_key			the EAP secret will be written here
	 * @return
	 * 								- NOT_FOUND	if no preshared secrets for specific ID could be found
	 * 								- SUCCESS
	 *
	 */	
	status_t (*get_eap_key) (credential_store_t *this, identification_t *my_id,
							 identification_t *other_id, chunk_t *eap_key);
	
	/**
	 * @brief Returns the RSA public key of a specific ID.
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
	 * @param this					calling object
	 * @param pubkey				public key 
	 * @return						TRUE if matching private key was found 
	 */	
	bool (*has_rsa_private_key) (credential_store_t *this, rsa_public_key_t *pubkey);

	/**
	 * @brief Returns the certificate of a specific ID.
	 * 
	 * @param this					calling object
	 * @param id					identification_t object identifiying the cert.
	 * @return						certificate, or NULL if not found
	 */
	x509_t* (*get_certificate) (credential_store_t *this, identification_t *id);
	
	/**
	 * @brief Returns the auth certificate of a specific subject distinguished name.
	 * 
	 * @param this					calling object
	 * @param auth_flags			set of allowed authority types
	 * @param id					identification_t object identifiying the cacert.
	 * @return						certificate, or NULL if not found
	 */
	x509_t* (*get_auth_certificate) (credential_store_t *this, u_int auth_flags, identification_t *id);
	
	/**
	 * @brief Returns the ca certificate of a specific keyID.
	 * 
	 * @param this					calling object
	 * @param keyid					identification_t object identifiying the cacert.
	 * @return						certificate, or NULL if not found
	 */
	x509_t* (*get_ca_certificate_by_keyid) (credential_store_t *this, chunk_t keyid);
	
	/**
	 * @brief Returns the issuing ca of a given certificate.
	 * 
	 * @param this					calling object
	 * @param cert					certificate for which issuer ca info is required
	 * @return						ca info, or NULL if not found
	 */
	ca_info_t* (*get_issuer) (credential_store_t *this, const x509_t* cert);

	/**
	 * @brief Verify an RSA signature given the ID of the signer
	 * 
	 * @param this					calling object
	 * @param hash					hash value to be verified.
	 * @param sig					signature to be verified.
	 * @param id					identification_t object identifiying the signer.
	 * @param issuer_p				issuer of the signer's certificate (if not self-signed).
	 * @return						status of the verification - SUCCESS if successful
	 */
	status_t (*verify_signature) (credential_store_t *this, chunk_t hash, chunk_t sig, identification_t *id, ca_info_t **issuer_p);
	
	/**
	 * @brief Verify an X.509 certificate up to trust anchor without any status checks
	 *
	 * @param this		calling object
	 * @param cert		certificate to be verified
	 * @return			TRUE if trusted
	 */
	bool (*is_trusted) (credential_store_t *this, x509_t *cert);

	/**
	 * @brief Verify an X.509 certificate up to trust anchor including status checks
	 *
	 * @param this		calling object
	 * @param cert		certificate to be verified
	 * @param found		found a certificate copy in the credential store
	 * @return			TRUE if valid, trusted, and current status is good
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
	 * @brief If an authority certificate does not already exists in the credential store then add it.
	 *
	 * @param this			calling object
	 * @param cert			authority certificate to be added
	 * @param auth_flag		authority flags to add to the certificate
	 * @return				pointer to the added or already existing certificate
	 */
	x509_t* (*add_auth_certificate) (credential_store_t *this, x509_t *cert, u_int auth_flag);

	/**
	 * @brief If a ca info record does not already exists in the credential store then add it.
	 *
	 * @param this		calling object
	 * @param ca_info	ca info record to be added
	 * @return			pointer to the added or already existing ca_info_t record
	 */
	ca_info_t* (*add_ca_info) (credential_store_t *this, ca_info_t *ca_info);

	/**
	 * @brief Release a ca info record with a given name.
	 *
	 * @param this		calling object
	 * @param name		name of the ca info record to be released
	 * @return
	 * 							- SUCCESS, or
	 * 							- NOT_FOUND
	 */
	status_t (*release_ca_info) (credential_store_t *this, const char *name);

	/**
	 * @brief Create an iterator over all end certificates.
	 *
	 * @param this		calling object
	 * @return 			iterator
	 */
	iterator_t* (*create_cert_iterator) (credential_store_t *this);

	/**
	 * @brief Create an iterator over all authority certificates.
	 *
	 * @param this		calling object
	 * @return 			iterator
	 */
	iterator_t* (*create_auth_cert_iterator) (credential_store_t *this);

	/**
	 * @brief Create an iterator over all CA info records
	 *
	 * @param this		calling object
	 * @return 			iterator
	 */
	iterator_t* (*create_cainfo_iterator) (credential_store_t *this);

	/**
	 * @brief Loads ca certificates from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 */
	void (*load_ca_certificates) (credential_store_t *this);
	
	/**
	 * @brief Loads authorization authority certificates from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 */
	void (*load_aa_certificates) (credential_store_t *this);

	/**
	 * @brief Loads attribute certificates from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 */
	void (*load_attr_certificates) (credential_store_t *this);

	/**
	 * @brief Loads ocsp certificates from a default directory.
	 *
	 * Certificates in both DER and PEM format are accepted
	 *
	 * @param this		calling object
	 */
	void (*load_ocsp_certificates) (credential_store_t *this);
	
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
	 * @param this		calling object
	 */
	void (*load_secrets) (credential_store_t *this);

	/**
	 * @brief Destroys a credential_store_t object.
	 * 
	 * @param this 		calling object
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
