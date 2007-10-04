/**
 * @file diffie_hellman.h
 * 
 * @brief Interface of diffie_hellman_t.
 * 
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef DIFFIE_HELLMAN_H_
#define DIFFIE_HELLMAN_H_

typedef enum diffie_hellman_group_t diffie_hellman_group_t;
typedef struct diffie_hellman_t diffie_hellman_t;

#include <library.h>

/**
 * @brief Diffie-Hellman group.
 *
 * The modulus (or group) to use for a Diffie-Hellman calculation.
 *
 * See IKEv2 RFC 3.3.2 and RFC 3526.
 *
 * @ingroup crypto
 */
enum diffie_hellman_group_t {
	MODP_NONE = 0,
	MODP_768_BIT = 1,
	MODP_1024_BIT = 2,
	MODP_1536_BIT = 5,
	MODP_2048_BIT = 14,
	MODP_3072_BIT = 15,
	MODP_4096_BIT = 16,
	MODP_6144_BIT = 17,
	MODP_8192_BIT = 18
};

/**
 * enum name for diffie_hellman_group_t.
 */
extern enum_name_t *diffie_hellman_group_names;

/**
 * @brief Implementation of the Diffie-Hellman algorithm, as in RFC2631.
 * 
 * @b Constructors:
 *  - diffie_hellman_create()
 * 
 * @ingroup crypto
 */
struct diffie_hellman_t {
		
	/**
	 * @brief Returns the shared secret of this diffie hellman exchange.
	 * 	
	 * Space for returned secret is allocated and must be 
	 * freed by the caller.
	 * 
	 * @param this 		calling object
	 * @param secret 	shared secret will be written into this chunk
	 * @return 				
	 * 					- SUCCESS
	 * 					- FAILED if not both DH values are set
	 */
	status_t (*get_shared_secret) (diffie_hellman_t *this, chunk_t *secret);
	
	/**
	 * @brief Sets the public value of partner.
	 * 	
	 * Chunk gets cloned and can be destroyed afterwards.
	 * 
	 * @param this 		calling object
	 * @param value 	public value of partner
	 */
	void (*set_other_public_value) (diffie_hellman_t *this, chunk_t value);
	
	/**
	 * @brief Gets the public value of partner.
	 * 	
	 * Space for returned chunk is allocated and must be freed by the caller.
	 * 
	 * @param this 		calling object
	 * @param value 	public value of partner is stored at this location
	 * @return 				
	 * 					- SUCCESS
	 * 					- FAILED if other public value not set
	 */
	status_t (*get_other_public_value) (diffie_hellman_t *this, chunk_t *value);
	
	/**
	 * @brief Gets the own public value to transmit.
	 * 	
	 * Space for returned chunk is allocated and must be freed by the caller.
	 * 
	 * @param this 		calling object
	 * @param value		public value of caller is stored at this location
	 */
	void (*get_my_public_value) (diffie_hellman_t *this, chunk_t *value);
	
	/**
	 * @brief Get the DH group used.
	 * 
	 * @param this 		calling object
	 * @return			DH group set in construction
	 */
	diffie_hellman_group_t (*get_dh_group) (diffie_hellman_t *this);

	/**
	 * @brief Destroys an diffie_hellman_t object.
	 *
	 * @param this 		diffie_hellman_t object to destroy
	 */
	void (*destroy) (diffie_hellman_t *this);
};

/**
 * @brief Creates a new diffie_hellman_t object.
 * 
 * @param group			Diffie Hellman group number to use
 * @return
 * 						- diffie_hellman_t object
 * 						- NULL if dh group not supported
 * 
 * @ingroup crypto
 */
diffie_hellman_t *diffie_hellman_create(diffie_hellman_group_t group);

#endif /*DIFFIE_HELLMAN_H_*/

