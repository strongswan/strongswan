/*
 * Copyright (C) 2005-2009 Martin Willi
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

/**
 * @defgroup cp_payload cp_payload
 * @{ @ingroup payloads
 */

#ifndef CP_PAYLOAD_H_
#define CP_PAYLOAD_H_

typedef enum config_type_t config_type_t;
typedef struct cp_payload_t cp_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <utils/enumerator.h>

/**
 * CP_PAYLOAD length in bytes without any proposal substructure.
 */
#define CP_PAYLOAD_HEADER_LENGTH 8

/**
 * Config Type of an Configuration Payload.
 */
enum config_type_t {
	CFG_REQUEST = 1,
	CFG_REPLY = 2,
	CFG_SET = 3,
	CFG_ACK = 4,
};

/**
 * enum name for config_type_t.
 */
extern enum_name_t *config_type_names;

/**
 * Class representing an IKEv2-CP Payload.
 *
 * The CP Payload format is described in RFC section 3.15.
 */
struct cp_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Creates an enumerator of stored configuration_attribute_t objects.
	 *
	 * @return			enumerator over configration_attribute_T
	 */
	enumerator_t *(*create_attribute_enumerator) (cp_payload_t *this);

	/**
	 * Adds a configuration attribute to the configuration payload.
	 *
	 * @param attribute	attribute to add
	 */
	void (*add_attribute)(cp_payload_t *this,
						  configuration_attribute_t *attribute);

	/**
	 * Get the configuration payload type.
	 *
	 * @return			type of configuration payload
	 */
	config_type_t (*get_type) (cp_payload_t *this);

	/**
	 * Destroys an cp_payload_t object.
	 */
	void (*destroy) (cp_payload_t *this);
};

/**
 * Creates an empty configuration payload
 *
 * @return		empty configuration payload
 */
cp_payload_t *cp_payload_create();

/**
 * Creates an cp_payload_t with type and value
 *
 * @param config_type	type of configuration payload to create
 * @return				created configuration payload
 */
cp_payload_t *cp_payload_create_type(config_type_t config_type);

#endif /** CP_PAYLOAD_H_ @}*/
