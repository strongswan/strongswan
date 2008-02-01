/**
 * @file pkcs7.h
 * 
 * @brief Interface of pkcs7_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2008 Andreas Steffen
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
#include <crypto/pkcs9.h>
#include <crypto/rsa/rsa_private_key.h>
#include <crypto/crypters/crypter.h>
#include <utils/iterator.h>

extern const chunk_t ASN1_pkcs7_data_oid;

/**
 * @brief PKCS#7 contentInfo object.
 * 
 * @b Constructors:
 *  -pkcs7_create_from_chunk()
 *  -pkcs7_create_from_data()
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
	 * @brief Returns the a DER-encoded contentInfo object
	 *
	 * @param this			calling object
	 * @return				chunk containing the contentInfo object
	 */
	chunk_t (*get_contentInfo) (pkcs7_t *this);

	/**
	 * @brief Create an iterator for the certificates.
	 * 
	 * @param this			calling object
	 * @return				iterator for the certificates
	 */
	iterator_t *(*create_certificate_iterator) (pkcs7_t *this);

	/**
	 * @brief Add a certificate.
	 * 
	 * @param this			calling object
	 * @param cert			certificate to be included
	 */
	void (*set_certificate) (pkcs7_t *this, x509_t *cert);

	/**
	 * @brief Add authenticated attributes.
	 * 
	 * @param this			calling object
	 * @param attributes	attributes to be included
	 */
	void (*set_attributes) (pkcs7_t *this, pkcs9_t *attributes);

	/**
	 * @brief Build a data object
	 *
	 * @param this			PKCS#7 data to be built
	 * @return				TRUE if build was successful
	 */
	bool (*build_data) (pkcs7_t *this);

	/**
	 * @brief Build an envelopedData object
	 *
	 * @param this			PKCS#7 data object to envelop
	 * @param cert			receivers's certificate
	 * @param alg			encryption algorithm
	 * @return				TRUE if build was successful
	 */
	bool (*build_envelopedData) (pkcs7_t *this, x509_t *cert, encryption_algorithm_t alg);

	/**
	 * @brief Build an signedData object
	 *
	 * @param this			PKCS#7 data object to sign
	 * @param key			signer's RSA private key
	 * @param alg			digest algorithm used for signature
	 * @return				TRUE if build was successful
	 */
	bool (*build_signedData) (pkcs7_t *this, rsa_private_key_t *key, hash_algorithm_t alg);

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

/**
 * @brief Create a PKCS#7 contentInfo object
 * 
 * @param chunk			chunk containing data
 * @return 				created pkcs7_contentInfo object.
 * 
 * @ingroup crypto
 */
pkcs7_t *pkcs7_create_from_data(chunk_t data);

/**
 * @brief Read a X.509 certificate from a DER encoded file.
 * 
 * @param filename 	file containing DER encoded data
 * @param label		label describing kind of PKCS#7 file
 * @return 			created pkcs7_t object, or NULL if invalid.
 * 
 * @ingroup crypto
 */
pkcs7_t *pkcs7_create_from_file(const char *filename, const char *label);


#endif /* _PKCS7_H */
