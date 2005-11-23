/**
 * @file diffie_hellman.h
 * 
 * @brief Class to represent a diffie hellman exchange.
 * 
 */

/*
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

#ifndef DIFFIE_HELLMAN_H_
#define DIFFIE_HELLMAN_H_

#include <types.h>
#include <payloads/transform_substructure.h>

/**
 * Object representing a diffie hellman exchange
 * 
 */
typedef struct diffie_hellman_s diffie_hellman_t;

struct diffie_hellman_s {
		
	/**
	 * @brief Returns the shared secret of this diffie hellman exchange
	 * 	
	 * @warning Space for returned secret is allocated and has to get freed by the caller
	 * 
	 * @param this 			calling diffie_hellman_t object
	 * @param[out] secret 	shared secret will be written into this chunk
	 * @return 				
	 * 						- SUCCESS
	 * 						- FAILED if not both DH values are set
	 * 						- OUT_OF_RES if out of ressources
	 */
	status_t (*get_shared_secret) (diffie_hellman_t *this, chunk_t *secret);
	
	/**
	 * @brief Sets the public value of partner
	 * 	
	 * @warning chunk gets copied
	 * 
	 * @param this 			calling diffie_hellman_t object
	 * @param public_value 	public value of partner
	 * @return 				
	 * 						- SUCCESS
	 * 						- OUT_OF_RES if out of ressources
	 */
	status_t (*set_other_public_value) (diffie_hellman_t *this, chunk_t public_value);
	
	/**
	 * @brief Gets the public value of partner
	 * 	
	 * @warning chunk gets copied
	 * 
	 * @param this 				calling diffie_hellman_t object
	 * @param[out] public_value 	public value of partner is stored at this location
	 * @return 				
	 * 							- SUCCESS
	 * 							- OUT_OF_RES if out of ressources
	 * 							- FAILED if other public value not set
	 */
	status_t (*get_other_public_value) (diffie_hellman_t *this, chunk_t *public_value);
	
	/**
	 * @brief Gets the public value of caller
	 * 	
	 * @warning chunk gets copied
	 * 
	 * @param this 				calling diffie_hellman_t object
	 * @param[out] public_value 	public value of caller is stored at this location
	 * @return 				
	 * 							- SUCCESS
	 * 							- OUT_OF_RES if out of ressources
	 */
	status_t (*get_my_public_value) (diffie_hellman_t *this, chunk_t *public_value);

	/**
	 * @brief Destroys an diffie_hellman_t object.
	 *
	 * @param this 	diffie_hellman_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (diffie_hellman_t *this);
};

/**
 * Creates a new diffie_hellman_t object
 * 
 * The first diffie hellman public value gets automatically created
 * 
 * @param dh_group_number	Diffie Hellman group number to use
 * @return
 * 							- diffie_hellman_t if successfully
 * 							- NULL if out of ressources or dh_group not supported
 */
diffie_hellman_t *diffie_hellman_create(diffie_hellman_group_t dh_group_number);

#endif /*DIFFIE_HELLMAN_H_*/
