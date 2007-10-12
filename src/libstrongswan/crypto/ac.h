/**
 * @file ac.h
 * 
 * @brief Interface of x509ac_t.
 * 
 */

/*
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2007 Andreas Steffen
 *
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
 *
 * RCSID $Id$
 */

#ifndef AC_H_
#define AC_H_

#include <library.h>

typedef struct x509ac_t x509ac_t;

/**
 * @brief X.509 attribute certificate.
 * 
 * @b Constructors:
 *  - x509ac_create_from_chunk()
 *  - x509ac_create_from_file()
 *
 * @ingroup crypto
 */
struct x509ac_t {

	/**
	 * @brief Checks the validity interval of the attribute certificate
	 * 
	 * @param this			certificate being examined
	 * @param until			until = min(until, notAfter)
	 * @return				NULL if the certificate is valid
	 */
	err_t (*is_valid) (const x509ac_t *this, time_t *until);

	/** @brief Checks if this attr cert is newer than the other attr cert
	 * 
	 * @param this			calling object
	 * @param other			other attr cert object
	 * @return				TRUE if this was issued more recently than other
	 */
	bool (*is_newer) (const x509ac_t *this, const x509ac_t *other);

	/**
	 * @brief Checks if two attribute certificates belong to the same holder
	 *
	 * @param this			calling attribute certificate
	 * @param that			other attribute certificate
	 * @return				TRUE if same holder
	 */
	bool (*equals_holder) (const x509ac_t *this, const x509ac_t *other);

	/**
	 * @brief Log the attribute certificate info to out.
	 *
	 * @param this			calling object
	 * @param out			stream to write to
	 * @param utc			TRUE for UTC times, FALSE for local time
	 */
	void (*list)(const x509ac_t *this, FILE *out, bool utc);

	/**
	 * @brief Destroys the attribute certificate.
	 * 
	 * @param this			certificate to destroy
	 */
	void (*destroy) (x509ac_t *this);
};

/**
 * @brief Read a x509 attribute certificate from a DER encoded blob.
 * 
 * @param chunk 	chunk containing DER encoded data
 * @return 			created x509ac_t certificate, or NULL if invalid.
 * 
 * @ingroup crypto
 */
x509ac_t *x509ac_create_from_chunk(chunk_t chunk);

/**
 * @brief Read a x509 attribute certificate from a DER encoded file.
 *
 * @param filename 	file containing DER encoded data
 * @return 		created x509ac_t certificate, or NULL if invalid.
 *
 * @ingroup crypto
 */
x509ac_t *x509ac_create_from_file(const char *filename);

#endif /* AC_H_ */

