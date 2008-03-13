/*
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
 *
 * $Id$
 */

/**
 * @defgroup ke_payload ke_payload
 * @{ @ingroup payloads
 */

#ifndef KE_PAYLOAD_H_
#define KE_PAYLOAD_H_

typedef struct ke_payload_t ke_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <utils/linked_list.h>
#include <crypto/diffie_hellman.h>

/**
 * KE payload length in bytes without any key exchange data.
 */
#define KE_PAYLOAD_HEADER_LENGTH 8

/**
 * Class representing an IKEv2-KE Payload.
 *
 * The KE Payload format is described in RFC section 3.4.
 */
struct ke_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * Returns the currently set key exchange data of this KE payload.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_key_exchange_data) (ke_payload_t *this);
	
	/**
	 * Sets the key exchange data of this KE payload.
	 * 	
	 * Value is getting copied.
	 * 
	 * @param key_exchange_data chunk_t pointing to the value to set
	 */
	void (*set_key_exchange_data) (ke_payload_t *this, chunk_t key_exchange_data);

	/**
	 * Gets the Diffie-Hellman Group Number of this KE payload.
	 * 	
	 * @return 					DH Group Number of this payload
	 */
	diffie_hellman_group_t (*get_dh_group_number) (ke_payload_t *this);

	/**
	 * Sets the Diffie-Hellman Group Number of this KE payload.
	 * 	
	 * @param dh_group_number	DH Group to set
	 */
	void (*set_dh_group_number) (ke_payload_t *this, 
								 diffie_hellman_group_t dh_group_number);

	/**
	 * Destroys an ke_payload_t object.
	 */
	void (*destroy) (ke_payload_t *this);
};

/**
 * Creates an empty ke_payload_t object
 * 
 * @return ke_payload_t object
 */
ke_payload_t *ke_payload_create(void);

/**
 * Creates a ke_payload_t from a diffie_hellman_t
 * 
 * @param diffie_hellman	diffie hellman object containing group and key
 * @return 					ke_payload_t object
 */
ke_payload_t *ke_payload_create_from_diffie_hellman(
											diffie_hellman_t *diffie_hellman);

#endif /* KE_PAYLOAD_H_ @} */
