/**
 * @file certificate.h
 * 
 * @brief Interface of certificate_t.
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

#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

#include <types.h>
#include <definitions.h>
#include <crypto/rsa/rsa_public_key.h>


typedef struct certificate_t certificate_t;

/**
 * @brief X509 certificate.
 * 
 * @b Constructors:
 *  - certificate_create_from_chunk()
 *
 * @ingroup transforms
 */
struct certificate_t {

	/**
	 * @brief Get the RSA public key from the certificate.
	 * 
	 * @param this				calling object
	 * @return					public_key
	 */
	rsa_public_key_t *(*get_public_key) (certificate_t *this);
	
	/**
	 * @brief Destroys the private key.
	 * 
	 * @param this				private key to destroy
	 */
	void (*destroy) (certificate_t *this);
};

/**
 * @brief Read a certificate from a blob.
 * 
 * @return created certificate_t.
 * 
 * @ingroup transforms
 */
certificate_t *certificate_create_from_chunk(chunk_t chunk);

certificate_t *certificate_create_from_file(char *filename);

#endif /* CERTIFICATE_H_ */
