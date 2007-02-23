/**
 * @file ca.h
 * 
 * @brief Interface of ca_info_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
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

#ifndef CA_H_
#define CA_H_

typedef struct ca_info_t ca_info_t;

#include <library.h>

#include "x509.h"

/**
 * @brief X.509 certification authority information record
 * 
 * @b Constructors:
 *  - ca_info_create()
 * 
 * @ingroup transforms
 */
struct ca_info_t {

	/**
	 * @brief Adds a CRL URI to a list
	 * 
	 * @param this			ca info object
	 * @param uri			crl uri string to be added
	 */
	void (*add_crluri) (ca_info_t *this, const char* uri);

	/**
	 * @brief Adds a CRL URI to a list
	 * 
	 * @param this			ca info object
	 * @param uri			ocsp uri string to be added
	 */
	void (*add_ocspuri) (ca_info_t *this, const char* uri);

	/**
	 * @brief Destroys a ca info record
	 * 
	 * @param this			ca info to destroy
	 */
	void (*destroy) (ca_info_t *this);
};

/**
 * @brief Create a ca info record
 * 
 * @param name 		name of the ca info record
 * @param cacert	path to the ca certificate
 * @return 			created ca_info_t, or NULL if invalid.
 * 
 * @ingroup transforms
 */
ca_info_t *ca_info_create(const char *name, const x509_t *cacert);

#endif /* CA_H_ */
