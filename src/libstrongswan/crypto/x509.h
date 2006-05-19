/**
 * @file x509.h
 * 
 * @brief Interface of x509_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef X509_H_
#define X509_H_

#include <types.h>
#include <definitions.h>
#include <crypto/rsa/rsa_public_key.h>
#include <utils/identification.h>
#include <utils/iterator.h>
#include <utils/logger.h>


typedef struct x509_t x509_t;

/**
 * @brief X509 certificate.
 * 
 * @b Constructors:
 *  - x509_create_from_chunk()
 *  - x509_create_from_file()
 * 
 * @todo more code cleanup needed!
 * @todo fix unimplemented functions...
 * @todo handle memory management
 *
 * @ingroup transforms
 */
struct x509_t {

	/**
	 * @brief Get the RSA public key from the certificate.
	 * 
	 * @param this				calling object
	 * @return					public_key
	 */
	rsa_public_key_t *(*get_public_key) (x509_t *this);
		
	/**
	 * @brief Get the certificate issuers ID.
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN.
	 * 
	 * @param this				calling object
	 * @return					issuers ID
	 */
	identification_t *(*get_issuer) (x509_t *this);
		
	/**
	 * @brief Get the subjects ID.
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN. 
	 * 
	 * @param this				calling object
	 * @return					subjects ID
	 */
	identification_t *(*get_subject) (x509_t *this);
	
	/**
	 * @brief Check if a certificate is valid.
	 * 
	 * This function uses the issuers public key to verify 
	 * the validity of a certificate.
	 * 
	 * @todo implement!
	 */
	bool (*verify) (x509_t *this, rsa_public_key_t *signer);
	
	/**
	 * @brief Get the key identifier of the public key.
	 * 
	 * @todo implement!
	 */
	chunk_t (*get_subject_key_identifier) (x509_t *this);
	
	/**
	 * @brief Compare two certificates.
	 * 
	 * Comparison is done via the certificates signature.
	 * 
	 * @param this			first cert for compare
	 * @param other			second cert for compare
	 * @return				TRUE if signature is equal
	 */
	bool (*equals) (x509_t *this, x509_t *that);
	
	/**
	 * @brief Destroys the certificate.
	 * 
	 * @param this			certificate to destroy
	 */
	void (*destroy) (x509_t *this);

	/**
	 * @brief Log x509 certificate info.
	 *
	 * @param this			certificate to log
	 * @param logger		logger to be used
	 * @param utc			log dates either in UTC or local time
	 */
	 void (*log_certificate) (x509_t *this, logger_t *logger, bool utc);
};

/**
 * @brief Read a x509 certificate from a DER encoded blob.
 * 
 * @param chunk 	chunk containing DER encoded data
 * @return 			created x509_t certificate, or NULL if invalid.
 * 
 * @ingroup transforms
 */
x509_t *x509_create_from_chunk(chunk_t chunk);

/**
 * @brief Read a x509 certificate from a DER encoded file.
 * 
 * @param filename 	file containing DER encoded data
 * @return 			created x509_t certificate, or NULL if invalid.
 * 
 * @ingroup transforms
 */
x509_t *x509_create_from_file(const char *filename);

#endif /* X509_H_ */
