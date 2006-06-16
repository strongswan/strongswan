/**
 * @file crl.h
 * 
 * @brief Interface of crl_t.
 * 
 */

/*
 * Copyright (C) 2006 Andreas Steffen
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

#ifndef CRL_H_
#define CRL_H_

#include <types.h>
#include <definitions.h>
#include <crypto/rsa/rsa_public_key.h>
#include <utils/identification.h>
#include <utils/iterator.h>
#include <utils/logger.h>


typedef struct crl_t crl_t;

/**
 * @brief X.509 certificate revocation list
 * 
 * @b Constructors:
 *  - crl_create_from_chunk()
 *  - crl_create_from_file()
 * 
 * @ingroup transforms
 */
struct crl_t {

	/**
	 * @brief Get the crl's issuer ID.
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN.
	 * 
	 * @param this				calling object
	 * @return					issuers ID
	 */
	identification_t *(*get_issuer) (const crl_t *this);
		
	/**
	 * @brief Check if both crls have the same issuer.
	 * 
	 * @param this				calling object
	 * @param other				other crl
	 * @return					TRUE if the same issuer
	 */
	bool (*equals_issuer) (const crl_t *this, const crl_t *other);

	/**
	 * @brief Check if a crl is trustworthy
	 * 
	 * Use the issuer's public key to verify 
	 * the trustworthiness of a crl.
	 * 
	 * @todo implement!
	 */
	bool (*verify) (const crl_t *this, rsa_public_key_t *signer);
	
	/**
	 * @brief Checks the validity interval of the crl
	 * 
	 * @param this			certificate being examined
	 * @param until			until = min(until, nextUpdate) if strict == TRUE
	 * @param strict		nextUpdate restricts the validiat
	 * @return				NULL if the crl is valid
	 */
	err_t (*is_valid) (const crl_t *this, time_t *until, bool strict);
	
	/**
	 * @brief Check if a certificate has been revoked.
	 * 
	 * This function uses the certificate's serialNumber
	 * to get the revocation status.
	 * 
	 */
	bool (*get_status) (const crl_t *this, chunk_t serial);

	/**
	 * @brief Destroys the crl.
	 * 
	 * @param this			crl to destroy
	 */
	void (*destroy) (crl_t *this);

	/**
	 * @brief Log x509 crl info.
	 *
	 * @param this			crl to log
	 * @param logger		logger to be used
	 * @param utc			log dates either in UTC or local time
	 * @param strict		expiry of nextUpdate is fatal with strict == TRUE
	 */
	 void (*log_crl) (const crl_t *this, logger_t *logger, bool utc, bool strict);
};

/**
 * @brief Read a x509 crl from a DER encoded blob.
 * 
 * @param chunk 	chunk containing DER encoded data
 * @return 			created crl_t, or NULL if invalid.
 * 
 * @ingroup transforms
 */
crl_t *crl_create_from_chunk(chunk_t chunk);

/**
 * @brief Read a x509 crl from a DER encoded file.
 * 
 * @param filename 	file containing DER encoded data
 * @return 			created crl_t, or NULL if invalid.
 * 
 * @ingroup transforms
 */
crl_t *crl_create_from_file(const char *filename);

#endif /* CRL_H_ */
