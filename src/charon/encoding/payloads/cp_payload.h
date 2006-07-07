/**
 * @file cp_payload.h
 * 
 * @brief Interface of cp_payload_t.
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

#ifndef CP_PAYLOAD_H_
#define CP_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <utils/linked_list.h>

/**
 * CP_PAYLOAD length in bytes without any proposal substructure.
 * 
 * @ingroup payloads
 */
#define CP_PAYLOAD_HEADER_LENGTH 8


typedef enum config_type_t config_type_t;

/**
 * Config Type of an Configuration Payload.
 * 
 * @ingroup payloads
 */
enum config_type_t {
	CFG_REQUEST = 1,
	CFG_REPLY = 2,
	CFG_SET = 3,
	CFG_ACK = 4,
};

/**
 * string mappings for config_type_t.
 * 
 * @ingroup payloads
 */
extern mapping_t config_type_m[];


typedef struct cp_payload_t cp_payload_t;

/**
 * @brief Class representing an IKEv2-CP Payload.
 * 
 * The CP Payload format is described in RFC section 3.15.
 * 
 * @b Constructors:
 * - cp_payload_create()
 * 
 * @ingroup payloads
 */
struct cp_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator of stored configuration_attribute_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 * 
	 * @warning When deleting an attribute using this iterator, 
	 * 			the length of this configuration_attribute_t has to be refreshed 
	 * 			by calling get_length()!
	 *
	 * @param this 			calling cp_payload_t object
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_configuration_attribute_iterator) (cp_payload_t *this, bool forward);
	
	/**
	 * @brief Adds a configuration_attribute_t object to this object.
	 * 
	 * @warning The added configuration_attribute_t object is 
	 * 			getting destroyed in destroy function of cp_payload_t.
	 *
	 * @param this 			calling cp_payload_t object
	 * @param attribute		configuration_attribute_t object to add
	 */
	void (*add_configuration_attribute) (cp_payload_t *this, configuration_attribute_t *attribute);
	
	/**
	 * @brief Set the config type.
	 *
	 * @param this 			calling cp_payload_t object
	 * @param config_type	config_type_t to set
	 */
	void (*set_config_type) (cp_payload_t *this,config_type_t config_type);
	
	/**
	 * @brief Get the config type.
	 *
	 * @param this 			calling cp_payload_t object
	 * @return				config_type_t
	 */
	config_type_t (*get_config_type) (cp_payload_t *this);
	
	/**
	 * @brief Destroys an cp_payload_t object.
	 *
	 * @param this 			cp_payload_t object to destroy
	 */
	void (*destroy) (cp_payload_t *this);
};

/**
 * @brief Creates an empty cp_payload_t object
 * 
 * @return cp_payload_t object
 * 
 * @ingroup payloads
 */
cp_payload_t *cp_payload_create(void);

#endif /*CP_PAYLOAD_H_*/
