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
 *
 * $Id$
 */
 
/**
 * @defgroup diffie_hellman diffie_hellman
 * @{ @ingroup crypto
 */

#ifndef DIFFIE_HELLMAN_H_
#define DIFFIE_HELLMAN_H_

typedef enum diffie_hellman_group_t diffie_hellman_group_t;
typedef struct diffie_hellman_t diffie_hellman_t;

#include <library.h>

/**
 * Diffie-Hellman group.
 *
 * The modulus (or group) to use for a Diffie-Hellman calculation.
 * See IKEv2 RFC 3.3.2 and RFC 3526.
 * 
 * ECP groups are defined in RFC 4753.
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
	MODP_8192_BIT = 18,
	ECP_256_BIT = 19,
	ECP_384_BIT = 20,
	ECP_521_BIT = 21,
	
};

/**
 * enum name for diffie_hellman_group_t.
 */
extern enum_name_t *diffie_hellman_group_names;

/**
 * Implementation of the Diffie-Hellman algorithm, as in RFC2631.
 */
struct diffie_hellman_t {
		
	/**
	 * Returns the shared secret of this diffie hellman exchange.
	 * 	
	 * Space for returned secret is allocated and must be 
	 * freed by the caller.
	 * 
	 * @param secret 	shared secret will be written into this chunk
	 * @return 			SUCCESS, FAILED if not both DH values are set
	 */
	status_t (*get_shared_secret) (diffie_hellman_t *this, chunk_t *secret);
	
	/**
	 * Sets the public value of partner.
	 * 	
	 * Chunk gets cloned and can be destroyed afterwards.
	 * 
	 * @param value 	public value of partner
	 */
	void (*set_other_public_value) (diffie_hellman_t *this, chunk_t value);
	
	/**
	 * Gets the public value of partner.
	 * 	
	 * Space for returned chunk is allocated and must be freed by the caller.
	 * 
	 * @param value 	public value of partner is stored at this location
	 * @return 			SUCCESS, FAILED if other public value not set
	 */
	status_t (*get_other_public_value) (diffie_hellman_t *this, chunk_t *value);
	
	/**
	 * Gets the own public value to transmit.
	 * 	
	 * Space for returned chunk is allocated and must be freed by the caller.
	 * 
	 * @param value		public value of caller is stored at this location
	 */
	void (*get_my_public_value) (diffie_hellman_t *this, chunk_t *value);
	
	/**
	 * Get the DH group used.
	 * 
	 * @return			DH group set in construction
	 */
	diffie_hellman_group_t (*get_dh_group) (diffie_hellman_t *this);

	/**
	 * Destroys an diffie_hellman_t object.
	 */
	void (*destroy) (diffie_hellman_t *this);
};

#endif /*DIFFIE_HELLMAN_H_ @} */
