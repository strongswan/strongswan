/**
 * @file pkcs7.h
 * 
 * @brief Interface of pkcs7_contentInfo_t.
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

typedef struct pkcs7_contentInfo_t pkcs7_contentInfo_t;

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
struct pkcs7_contentInfo_t {
	/**
	 * @brief Is contentInfo object of type signedData?.
	 * 
	 * @param this			calling object
	 * @return				TRUE if of type signedData
	 */
	bool (*is_signedData) (pkcs7_contentInfo_t *this);

	/**
	 * @brief Is contentInfo object of type envelopedData?.
	 * 
	 * @param this			calling object
	 * @return				TRUE if of type envelopedData
	 */
	bool (*is_envelopedData) (pkcs7_contentInfo_t *this);

	/**
	 * @brief Destroys the contentInfo object.
	 * 
	 * @param this			contentInfo object to destroy
	 */
	void (*destroy) (pkcs7_contentInfo_t *this);
};

extern chunk_t pkcs7_contentType_attribute(void);
extern chunk_t pkcs7_messageDigest_attribute(chunk_t content, int digest_alg);
extern chunk_t pkcs7_build_issuerAndSerialNumber(const x509_t *cert);
extern chunk_t pkcs7_build_signedData(chunk_t data, chunk_t attributes
    ,const x509_t *cert, int digest_alg, const rsa_private_key_t *key);
extern chunk_t pkcs7_build_envelopedData(chunk_t data, const x509_t *cert
    , int cipher);

#endif /* _PKCS7_H */
