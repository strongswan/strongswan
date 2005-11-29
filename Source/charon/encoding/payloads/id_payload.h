/**
 * @file id_payload.h
 * 
 * @brief Interface of id_payload_t.
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


#ifndef _ID_PAYLOAD_H_
#define _ID_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a id payload without the data in bytes.
 * 
 * @ingroup payloads
 */
#define ID_PAYLOAD_HEADER_LENGTH 8


typedef enum id_type_t id_type_t;

/**
 * ID Types of a ID payload.
 * 
 * @ingroup payloads
 */
enum id_type_t {
	/**
	 * ID data is a single four (4) octet IPv4 address.
	 */
	ID_IPV4_ADDR = 1,

	/**
	 * ID data is a fully-qualified domain name string.
	 * An example of a ID_FQDN is, "example.com".
	 * The string MUST not contain any terminators (e.g., NULL, CR, etc.).
	 */
	ID_FQDN = 2,
	
	/**
	 * ID data is a fully-qualified RFC822 email address string, An example of
	 * a ID_RFC822_ADDR is, "jsmith@example.com".  The string MUST
	 * not contain any terminators.
	 */
	ID_RFC822_ADDR = 3,
	
	/**
	 * ID data is a single sixteen (16) octet IPv6 address.
	 */
	ID_IPV6_ADDR = 5,
	
	/**
	 * ID data is the binary DER encoding of an ASN.1 X.500 Distinguished Name
     * [X.501].
     */
	ID_DER_ASN1_DN = 9,
	
	/**
	 * ID data is the binary DER encoding of an ASN.1 X.500 GeneralName
     * [X.509].
     */
	ID_DER_ASN1_GN = 10,
	
	/**
	 * ID data is an opaque octet stream which may be used to pass vendor-
     * specific information necessary to do certain proprietary
     * types of identification.
     */
	ID_KEY_ID = 11
};

extern mapping_t id_type_m[];


typedef struct id_payload_t id_payload_t;

/**
 * Object representing an IKEv2 ID payload.
 * 
 * The ID payload format is described in draft section 3.5.
 * 
 * @ingroup payloads
 * 
 */
struct id_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the ID type.
	 * 
	 *
	 * @param this 			calling id_payload_t object
	 * @param type			Type of ID
	 */
	void (*set_id_type) (id_payload_t *this, id_type_t type);
	
	/**
	 * @brief Get the ID type.
	 *
	 * @param this 			calling id_payload_t object
	 * @return				type of the ID 
	 */
	id_type_t (*get_id_type) (id_payload_t *this);
	
	/**
	 * @brief Set the ID data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling id_payload_t object
	 * @param data			ID data as chunk_t
	 */
	void (*set_data) (id_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the ID data.
	 * 
	 * Returned data are a copy of the internal one
	 *
	 * @param this 			calling id_payload_t object
	 * @return				ID data as chunk_t
	 */
	chunk_t (*get_data) (id_payload_t *this);
	
	/**
	 * @brief Get the type of ID payload (IDi or IDr).
	 *
	 * @param this 			calling id_payload_t object
	 * @return
	 * 						- TRUE if this payload is of type IDi
	 * 						- FALSE if this payload is of type IDr
	 * 
	 */
	bool (*get_initiator) (id_payload_t *this);
	
	/**
	 * @brief Set the type of ID payload (IDi or IDr).
	 *
	 * @param this 			calling id_payload_t object
	 * @param is_initiator	
	 * 						- TRUE if this payload is of type IDi
	 * 						- FALSE if this payload is of type IDr
	 * 
	 */
	void (*set_initiator) (id_payload_t *this,bool is_initiator);
	
	/**
	 * @brief Destroys an id_payload_t object.
	 *
	 * @param this 	id_payload_t object to destroy
	 */
	void (*destroy) (id_payload_t *this);
};

/**
 * @brief Creates an empty id_payload_t object.
 * 
 * @param is_initiator	
 * 						- TRUE if this payload is of type IDi
 * 						- FALSE if this payload is of type IDr
 * 
 * @return				created id_payload_t object
 * 
 * @ingroup payloads
 */
id_payload_t *id_payload_create(bool is_initiator);


#endif //_ID_PAYLOAD_H_
