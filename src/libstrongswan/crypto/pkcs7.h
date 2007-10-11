/**
 * @file pkcs7.h
 * 
 * @brief Interface of pkcs7_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2007 Andreas Steffen
 *
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 *
 * RCSID $Id$
 */

#ifndef _PKCS7_H
#define _PKCS7_H

typedef struct pkcs7_t pkcs7_t;

#include <library.h>
#include <crypto/x509.h>
#include <crypto/rsa/rsa_private_key.h>

/* Access structure for a PKCS#7 ContentInfo object */


/**
 * @brief PKCS#7 ContentInfo object.
 * 
 * @b Constructors:
 *  -pkcs7_create_from_chunk()
 *
 * @ingroup crypto
 */
struct pkcs7_t {
	/**
	 * @brief Check if the PKCS#7 contentType is data
	 * 
	 * @param this			calling object
	 * @return				TRUE if the contentType is data
	 */
	bool (*is_data) (pkcs7_t *this);

	/**
	 * @brief Check if the PKCS#7 contentType is signedData
	 * 
	 * @param this			calling object
	 * @return				TRUE if the contentType is signedData
	 */
	bool (*is_signedData) (pkcs7_t *this);

	/**
	 * @brief Check if the PKCS#7 contentType is envelopedData
	 * 
	 * @param this			calling object
	 * @return				TRUE if the contentType is envelopedData
	 */
	bool (*is_envelopedData) (pkcs7_t *this);

	/**
	 * @brief Parse a PKCS#7 data content.
	 * 
	 * @param this			calling object
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_data) (pkcs7_t *this);

	/**
	 * @brief Parse a PKCS#7 signedData content.
	 * 
	 * @param this			calling object
	 * @param cacert		cacert used to verify the signature
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_signedData) (pkcs7_t *this, x509_t *cacert);

	/**
	 * @brief Parse a PKCS#7 envelopedData content.
	 * 
	 * @param this			calling object
	 * @param serialNumber	serialNumber of the request
	 * @param key			RSA private key used to decrypt the symmetric key
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_envelopedData) (pkcs7_t *this, chunk_t serialNumber, rsa_private_key_t *key);

	/**
	 * @brief Returns the parsed data object
	 *
	 * @param this			calling object
	 * @return				chunk containing the data object
	 */
	chunk_t (*get_data) (pkcs7_t *this);

	/**
	 * @brief Destroys the contentInfo object.
	 *
	 * @param this			PKCS#7 contentInfo object to destroy
	 */
	void (*destroy) (pkcs7_t *this);
};

/**
 * @brief Read a PKCS#7 contentInfo object from a DER encoded chunk.
 * 
 * @param chunk		chunk containing DER encoded data
 * @param level		ASN.1 parsing start level
 * @return 			created pkcs7_contentInfo object, or NULL if invalid.
 * 
 * @ingroup crypto
 */
pkcs7_t *pkcs7_create_from_chunk(chunk_t chunk, u_int level);

#endif /* _PKCS7_H */
