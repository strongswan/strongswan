/*
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * @defgroup twofish_crypter twofish_crypter
 * @{ @ingroup twofish_p
 */

#ifndef TWOFISH_CRYPTER_H_
#define TWOFISH_CRYPTER_H_

typedef struct twofish_crypter_t twofish_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Class implementing the Twofish encryption algorithm.
 */
struct twofish_crypter_t {
	
	/**
	 * The crypter_t interface.
	 */
	crypter_t crypter_interface;
};

/**
 * Constructor to create twofish_crypter_t objects.
 * 
 * @param key_size		key size in bytes
 * @param algo			algorithm to implement
 * @return				twofish_crypter_t object, NULL if not supported
 */
twofish_crypter_t *twofish_crypter_create(encryption_algorithm_t algo,
								  size_t key_size);

#endif /** TWOFISH_CRYPTER_H_ @}*/
