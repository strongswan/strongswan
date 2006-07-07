/**
 * @file configuration_attribute.h
 * 
 * @brief Interface of configuration_attribute_t.
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

#ifndef CONFIGURATION_ATTRIBUTE_H_
#define CONFIGURATION_ATTRIBUTE_H_

#include <types.h>
#include <encoding/payloads/payload.h>



/**
 * Configuration attribute header length in bytes.
 * 
 * @ingroup payloads
 */
#define CONFIGURATION_ATTRIBUTE_HEADER_LENGTH 4


typedef enum configuration_attribute_type_t configuration_attribute_type_t;

/**
 * Type of the attribute, as in IKEv2 RFC 3.15.1.
 * 
 * @ingroup payloads
 */
enum configuration_attribute_type_t {
	INTERNAL_IP4_ADDRESS = 1,
	INTERNAL_IP4_NETMASK = 2,
	INTERNAL_IP4_DNS = 3,
	INTERNAL_IP4_NBNS = 4,
	INTERNAL_ADDRESS_EXPIRY = 5,
	INTERNAL_IP4_DHCP = 6,
	APPLICATION_VERSION = 7,
	INTERNAL_IP6_ADDRESS = 8,
	INTERNAL_IP6_DNS = 10,
	INTERNAL_IP6_NBNS = 11,
	INTERNAL_IP6_DHCP = 12,
	INTERNAL_IP4_SUBNET = 13,
	SUPPORTED_ATTRIBUTES = 14,
	INTERNAL_IP6_SUBNET = 15
};

/** 
 * String mappings for configuration_attribute_type_t.
 * 
 * @ingroup payloads
 */
extern mapping_t configuration_attribute_type_m[];

typedef struct configuration_attribute_t configuration_attribute_t;

/**
 * @brief Class representing an IKEv2-CONFIGURATION Attribute.
 * 
 * The CONFIGURATION ATTRIBUTE format is described in RFC section 3.15.1.
 * 
 * @b Constructors:
 * - configuration_attribute_create()
 * 
 * @ingroup payloads
 */
struct configuration_attribute_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Returns the currently set value of the attribute.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling configuration_attribute_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_value) (configuration_attribute_t *this);
	
	/**
	 * @brief Sets the value of the attribute.
	 * 	
	 * @warning Value is getting copied.
	 * 
	 * @param this 	calling configuration_attribute_t object
	 * @param value chunk_t pointing to the value to set
	 */
	void (*set_value) (configuration_attribute_t *this, chunk_t value);

	/**
	 * @brief Sets the type of the attribute.
	 * 	
	 * @param this 	calling configuration_attribute_t object
	 * @param type	type to set (most significant bit is set to zero)
	 */
	void (*set_attribute_type) (configuration_attribute_t *this, u_int16_t type);
	
	/**
	 * @brief get the type of the attribute.
	 * 	
	 * @param this 	calling configuration_attribute_t object
	 * @return 		type of the value
	 */
	u_int16_t (*get_attribute_type) (configuration_attribute_t *this);
	
	/**
	 * @brief get the length of an attribute.
	 * 	
	 * @param this 	calling configuration_attribute_t object
	 * @return 		type of the value
	 */
	u_int16_t (*get_attribute_length) (configuration_attribute_t *this);
	
	/**
	 * @brief Destroys an configuration_attribute_t object.
	 *
	 * @param this 	configuration_attribute_t object to destroy
	 */
	void (*destroy) (configuration_attribute_t *this);
};

/**
 * @brief Creates an empty configuration_attribute_t object.
 * 
 * @return			created configuration_attribute_t object
 * 
 * @ingroup payloads
 */
configuration_attribute_t *configuration_attribute_create(void);

#endif /* CONFIGURATION_ATTRIBUTE_H_*/
