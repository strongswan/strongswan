/*
 * Copyright (C) 2009 Martin Willi
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

/**
 * @defgroup pem_builder pem_builder
 * @{ @ingroup pem_p
 */

#ifndef PEM_PRIVATE_KEY_H_
#define PEM_PRIVATE_KEY_H_

#include <credentials/certificates/certificate.h>
#include <credentials/credential_factory.h>

/**
 * Builder for PEM encoded private keys of all kind.
 *
 * @param type		type of the key
 * @return 			builder instance
 */
builder_t *private_key_pem_builder(key_type_t type);

/**
 * Builder for PEM encoded public keys of all kind.
 *
 * @param type		type of the key
 * @return 			builder instance
 */
builder_t *public_key_pem_builder(key_type_t type);

/**
 * Builder for PEM encoded certificates of all kind.
 *
 * @param type		type of the key
 * @return 			builder instance
 */
builder_t *certificate_pem_builder(certificate_type_t type);

/**
 * Builder for PEM encoded pluto certificates of all kind.
 *
 * @param type		type of the key
 * @return 			builder instance
 */
builder_t *pluto_pem_builder(certificate_type_t type);

#endif /** PEM_PRIVATE_KEY_H_ @}*/

