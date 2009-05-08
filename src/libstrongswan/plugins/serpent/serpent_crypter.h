/*
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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
 * @defgroup serpent_crypter serpent_crypter
 * @{ @ingroup serpent_p
 */

#ifndef SERPENT_CRYPTER_H_
#define SERPENT_CRYPTER_H_

typedef struct serpent_crypter_t serpent_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Class implementing the Serpent encryption algorithm.
 */
struct serpent_crypter_t {
	
	/**
	 * The crypter_t interface.
	 */
	crypter_t crypter_interface;
};

/**
 * Constructor to create serpent_crypter_t objects.
 * 
 * @param key_size		key size in bytes
 * @param algo			algorithm to implement
 * @return				serpent_crypter_t object, NULL if not supported
 */
serpent_crypter_t *serpent_crypter_create(encryption_algorithm_t algo,
								  size_t key_size);

#endif /** SERPENT_CRYPTER_H_ @}*/
