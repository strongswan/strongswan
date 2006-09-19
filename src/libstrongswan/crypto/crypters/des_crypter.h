/**
 * @file des_crypter.h
 * 
 * @brief Interface of des_crypter_t
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

#ifndef DES_CRYPTER_H_
#define DES_CRYPTER_H_

#include <crypto/crypters/crypter.h>


typedef struct des_crypter_t des_crypter_t;

/**
 * @brief Class implementing the DES and 3DES encryption algorithms.
 * 
 * @b Constructors:
 *  - des_crypter_create()
 * 
 * @ingroup crypters
 */
struct des_crypter_t {
	
	/**
	 * The crypter_t interface.
	 */
	crypter_t crypter_interface;
};

/**
 * @brief Constructor to create des_crypter_t objects.
 * 
 * @param algo		ENCR_DES for single DES, ENCR_3DES for triple DES
 * @return				
 * 					- des_crypter_t object
 * 					- NULL if algo not supported
 */
des_crypter_t *des_crypter_create(encryption_algorithm_t algo);


#endif /* DES_CRYPTER_H_ */
