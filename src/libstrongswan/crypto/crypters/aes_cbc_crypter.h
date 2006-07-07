/**
 * @file aes_cbc_crypter.h
 * 
 * @brief Interface of aes_cbc_crypter_t
 * 
 */

/*
 * Copyright (C) 2001 Dr B. R. Gladman <brg@gladman.uk.net>
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef AES_CBC_CRYPTER_H_
#define AES_CBC_CRYPTER_H_

#include <crypto/crypters/crypter.h>


typedef struct aes_cbc_crypter_t aes_cbc_crypter_t;

/**
 * @brief Class implementing the AES symmetric encryption algorithm.
 * 
 * @b Constructors:
 *  - aes_cbc_crypter_create()
 * 
 * @ingroup crypters
 */
struct aes_cbc_crypter_t {
	
	/**
	 * The crypter_t interface.
	 */
	crypter_t crypter_interface;
};

/**
 * @brief Constructor to create aes_cbc_crypter_t objects.
 * 
 * Supported key sizes are: 16, 24 or 32. 
 * 
 * @param key_size		key size in bytes
 * @return				
 * 						- aes_cbc_crypter_t object
 * 						- NULL if key size not supported
 */
aes_cbc_crypter_t *aes_cbc_crypter_create(size_t key_size);


#endif /* AES_CBC_CRYPTER_H_ */
