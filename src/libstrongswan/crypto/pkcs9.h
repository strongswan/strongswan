/**
 * @file pkcs7.h
 * 
 * @brief Interface of pkcs9_t.
 * 
 */

/*
  * Copyright (C) 2008 Andreas Steffen
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
 * RCSID $Id: pkcs7.h 3423 2008-01-22 10:32:37Z andreas $
 */

#ifndef _PKCS9_H
#define _PKCS9_H

typedef struct pkcs9_t pkcs9_t;

#include <library.h>

/**
 * @brief PKCS#9 .
 * 
 * @b Constructors:
 *  -pkcs9_create_from_chunk()
 *  -pkcs9_create()
 *
 * @ingroup crypto
 */
struct pkcs9_t {
	/**
	 * @brief generate ASN.1 encoding of attribute list
	 *
	 * @param this			PKCS#9 attribute list to be encoded
	 */
	void (*build_encoding) (pkcs9_t *this);

	/**
	 * @brief gets ASN.1 encoding of PKCS#9 attribute list
	 *
	 * @param this			calling object
	 * @return				ASN.1 encoded PKCSI#9 list
	 */
	chunk_t (*get_encoding) (pkcs9_t *this);

	/**
	 * @brief gets a PKCS#9 attribute
	 *
	 * @param this			calling object
	 * @param oid			OID of the attribute
	 * @return				ASN.1 encoded value of the attribute
	 */
	chunk_t (*get_attribute) (pkcs9_t *this, int oid);

	/**
	 * @brief adds a PKCS#9 attribute
	 *
	 * @param this			calling object
	 * @param oid			OID of the attribute
	 * @param value			ASN.1 encoded value of the attribute 
	 */
	void (*set_attribute) (pkcs9_t *this, int oid, chunk_t value);

	/**
	 * @brief gets a PKCS#9 messageDigest attribute
	 *
	 * @param this			calling object
	 * @return				messageDigest
	 */
	chunk_t (*get_messageDigest) (pkcs9_t *this);

	/**
	 * @brief add a PKCS#9 messageDigest attribute
	 *
	 * @param this			calling object
	 * @param value			messageDigest 
	 */
	void (*set_messageDigest) (pkcs9_t *this, chunk_t value);

	/**
	 * @brief Destroys the PKCS#9 attribute list.
	 *
	 * @param this			PKCS#9 attribute list to destroy
	 */
	void (*destroy) (pkcs9_t *this);
};

/**
 * @brief Read a PKCS#9 attribute list from a DER encoded chunk.
 * 
 * @param chunk		chunk containing DER encoded data
 * @param level		ASN.1 parsing start level
 * @return 			created pkcs9 attribute list, or NULL if invalid.
 * 
 * @ingroup crypto
 */
pkcs9_t *pkcs9_create_from_chunk(chunk_t chunk, u_int level);

/**
 * @brief Create an empty PKCS#9 attribute list
 * 
 * @param chunk			chunk containing data
 * @return 				created pkcs9 attribute list.
 * 
 * @ingroup crypto
 */
pkcs9_t *pkcs9_create(void);

#endif /* _PKCS9_H */
