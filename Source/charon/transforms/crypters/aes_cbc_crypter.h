/**
 * @file aes_cbc_crypter.h
 * 
 * @brief Interface of aes_cbc_crypter_t
 * 
 */

/*
 * Copyright (C) 2001 Dr B. R. Gladman <brg@gladman.uk.net>
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef _AES_CRYPTER_H_
#define _AES_CRYPTER_H_

#include <transforms/crypters/crypter.h>


typedef struct aes_cbc_crypter_t aes_cbc_crypter_t;

/**
 * @brief Class implementing the AES symmetric encryption algorithm.
 * 
 * @ingroup crypters
 */
struct aes_cbc_crypter_t {
	
	/**
	 * crypter_t interface.
	 */
	crypter_t crypter_interface;
};

/**
 * @brief Constructor to create aes_cbc_crypter_t objects.
 * 
 * @param blocksize		block size of AES crypter
 * 						(16, 24 or 32 are supported)
 * 						Default size is set to 16.
 * @return				aes_cbc_crypter_t if successfully
 */
aes_cbc_crypter_t *aes_cbc_crypter_create(size_t blocksize);


#endif //_AES_CRYPTER_H_
