/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2008 Andreas Steffen
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
 */

/**
 * @defgroup pkcs7 pkcs7
 * @{ @ingroup crypto
 */

#ifndef PKCS7_H_
#define PKCS7_H_

typedef struct pkcs7_t pkcs7_t;

#include <library.h>
#include <credentials/keys/private_key.h>
#include <crypto/pkcs9.h>
#include <crypto/crypters/crypter.h>
#include <utils/enumerator.h>

/**
 * PKCS#7 contentInfo object.
 */
struct pkcs7_t {

	/**
	 * Check if the PKCS#7 contentType is data
	 *
	 * @return				TRUE if the contentType is data
	 */
	bool (*is_data) (pkcs7_t *this);

	/**
	 * Check if the PKCS#7 contentType is signedData
	 *
	 * @return				TRUE if the contentType is signedData
	 */
	bool (*is_signedData) (pkcs7_t *this);

	/**
	 * Check if the PKCS#7 contentType is envelopedData
	 *
	 * @return				TRUE if the contentType is envelopedData
	 */
	bool (*is_envelopedData) (pkcs7_t *this);

	/**
	 * Parse a PKCS#7 data content.
	 *
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_data) (pkcs7_t *this);

	/**
	 * Parse a PKCS#7 signedData content.  The contained PKCS#7 data is parsed
	 * and verified.
	 *
	 * @param cacert		cacert used to verify the signature
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_signedData) (pkcs7_t *this, certificate_t *cacert);

	/**
	 * Parse a PKCS#7 envelopedData content.
	 *
	 * @param serialNumber	serialNumber of the request
	 * @param key			private key used to decrypt the symmetric key
	 * @return				TRUE if parsing was successful
	 */
	bool (*parse_envelopedData) (pkcs7_t *this, chunk_t serialNumber,
								 private_key_t *key);

	/**
	 * Returns the parsed data object
	 *
	 * @return				chunk containing the data object
	 */
	chunk_t (*get_data) (pkcs7_t *this);

	/**
	 * Returns the a DER-encoded contentInfo object
	 *
	 * @return				chunk containing the contentInfo object
	 */
	chunk_t (*get_contentInfo) (pkcs7_t *this);

	/**
	 * Create an enumerator for the certificates.
	 *
	 * @return				enumerator for the certificates
	 */
	enumerator_t *(*create_certificate_enumerator) (pkcs7_t *this);

	/**
	 * Add a certificate.
	 *
	 * @param cert			certificate to be included (gets adopted)
	 */
	void (*set_certificate) (pkcs7_t *this, certificate_t *cert);

	/**
	 * Add authenticated attributes.
	 *
	 * @param attributes	attributes to be included (gets adopted)
	 */
	void (*set_attributes) (pkcs7_t *this, pkcs9_t *attributes);

	/**
	 * Get attributes.
	 *
	 * @return				attributes (internal data)
	 */
	pkcs9_t *(*get_attributes) (pkcs7_t *this);

	/**
	 * Build a data object
	 *
	 * @return				TRUE if build was successful
	 */
	bool (*build_data) (pkcs7_t *this);

	/**
	 * Build an envelopedData object
	 *
	 * @param cert			receivers's certificate
	 * @param alg			encryption algorithm
	 * @param key_size		key size to use
	 * @return				TRUE if build was successful
	 */
	bool (*build_envelopedData) (pkcs7_t *this, certificate_t *cert,
								 encryption_algorithm_t alg, size_t key_size);

	/**
	 * Build an signedData object
	 *
	 * @param key			signer's private key
	 * @param alg			digest algorithm used for signature
	 * @return				TRUE if build was successful
	 */
	bool (*build_signedData) (pkcs7_t *this, private_key_t *key,
							  hash_algorithm_t alg);

	/**
	 * Destroys the contentInfo object.
	 */
	void (*destroy) (pkcs7_t *this);
};

/**
 * Read a PKCS#7 contentInfo object from a DER encoded chunk.
 *
 * @param chunk		chunk containing DER encoded data
 * @param level		ASN.1 parsing start level
 * @return			created pkcs7_contentInfo object, or NULL if invalid.
 */
pkcs7_t *pkcs7_create_from_chunk(chunk_t chunk, u_int level);

/**
 * Create a PKCS#7 contentInfo object
 *
 * @param data			chunk containing data
 * @return				created pkcs7_contentInfo object.
 */
pkcs7_t *pkcs7_create_from_data(chunk_t data);

#endif /** PKCS7_H_ @}*/
