/**
 * @file eap_payload.h
 * 
 * @brief Interface of eap_payload_t.
 * 
 */

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
 */

#ifndef EAP_PAYLOAD_H_
#define EAP_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a EAP payload without the EAP Message in bytes.
 * 
 * @ingroup payloads
 */
#define EAP_PAYLOAD_HEADER_LENGTH 4


typedef struct eap_payload_t eap_payload_t;

/**
 * @brief Class representing an IKEv2 EAP payload.
 * 
 * The EAP payload format is described in RFC section 3.16.
 * 
 * @b Constructors:
 * - eap_payload_create()
 * 
 * @todo Implement functionality for this payload
 * 
 * @ingroup payloads
 */
struct eap_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Set the EAP Message.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling eap_payload_t object
	 * @param message		EAP message as chunk_t
	 */
	void (*set_message) (eap_payload_t *this, chunk_t message);
	
	/**
	 * @brief Get the EAP message.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling eap_payload_t object
	 * @return				EAP message as chunk_t
	 */
	chunk_t (*get_message_clone) (eap_payload_t *this);
	
	/**
	 * @brief Get the EAP message.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling eap_payload_t object
	 * @return				EAP message as chunk_t
	 */
	chunk_t (*get_message) (eap_payload_t *this);
	
	/**
	 * @brief Destroys an eap_payload_t object.
	 *
	 * @param this 	eap_payload_t object to destroy
	 */
	void (*destroy) (eap_payload_t *this);
};

/**
 * @brief Creates an empty eap_payload_t object.
 * 
 * @return eap_payload_t object
 * 
 * @ingroup payloads
 */
eap_payload_t *eap_payload_create(void);


#endif /* EAP_PAYLOAD_H_ */
