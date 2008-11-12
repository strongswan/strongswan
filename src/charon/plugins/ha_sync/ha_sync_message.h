/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup ha_sync_message ha_sync_message
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_MESSAGE_H_
#define HA_SYNC_MESSAGE_H_

#include <library.h>

/**
 * Protocol version of this implementation
 */
#define HA_SYNC_MESSAGE_VERSION 1

typedef struct ha_sync_message_t ha_sync_message_t;
typedef enum ha_sync_message_type_t ha_sync_message_type_t;
typedef enum ha_sync_message_attribute_t ha_sync_message_attribute_t;
typedef union ha_sync_message_value_t ha_sync_message_value_t;

/**
 * Type of a sync message
 */
enum ha_sync_message_type_t {
	HA_SYNC_CHILD_SA = 0,
	HA_SYNC_IKE_SA,
	HA_SYNC_IKE_MID,
};

/**
 * Type of attributes contained in a message
 */
enum ha_sync_message_attribute_t {
	HA_SYNC_CONFIG_STR = 0,
	HA_SYNC_IPV4_L_CHNK,
	HA_SYNC_IPV4_R_CHNK,
	HA_SYNC_PORT_L_U16,
	HA_SYNC_PORT_R_U16,
	HA_SYNC_SPI_L_U32,
	HA_SYNC_SPI_R_U32,
	HA_SYNC_CPI_L_U16,
	HA_SYNC_CPI_R_U16,
	HA_SYNC_ENCAP_U8,
	HA_SYNC_MODE_U8,
	HA_SYNC_IPCOMP_U8,
	HA_SYNC_NONCE_I_CHNK,
	HA_SYNC_NONCE_R_CHNK,
	HA_SYNC_SECRET_CHNK,
	HA_SYNC_ALG_INTEG_U16,
	HA_SYNC_ALG_ENC_U16,
};

/**
 * Union to enumerate typed attributes in a message
 */
union ha_sync_message_value_t {
	u_int8_t u8;
	u_int32_t u32;
	u_int16_t u16;
	chunk_t chnk;
	char *str;
};

/**
 * Abstracted message passed between nodes in a HA cluster.
 */
struct ha_sync_message_t {

	/**
	 * Get the type of the message.
	 *
	 * @return		message type
	 */
	ha_sync_message_type_t (*get_type)(ha_sync_message_t *this);

	/**
	 * Add an attribute to a message.
	 *
	 * @param attribute		attribute type to add
	 * @param ...			attribute specific data
	 */
	void (*add_attribute)(ha_sync_message_t *this,
						  ha_sync_message_attribute_t attribute, ...);

	/**
	 * Create an enumerator over all attributes in a message.
	 *
	 * @return				enumerator over attribute, ha_sync_message_value_t
	 */
	enumerator_t* (*create_attribute_enumerator)(ha_sync_message_t *this);

	/**
	 * Get the message in a encoded form.
	 *
	 * @return				chunk pointing to internal data
	 */
	chunk_t (*get_encoding)(ha_sync_message_t *this);

	/**
	 * Destroy a ha_sync_message_t.
	 */
	void (*destroy)(ha_sync_message_t *this);
};

/**
 * Create a new ha_sync_message instance, ready for adding attributes
 *
 * @param version			protocol version to create a message from
 * @param type				type of the message
 */
ha_sync_message_t *ha_sync_message_create(ha_sync_message_type_t type);

/**
 * Create a ha_sync_message from encoded data.
 *
 * @param data				encoded message data
 */
ha_sync_message_t *ha_sync_message_parse(chunk_t data);

#endif /* HA_SYNC_MESSAGE_ @}*/
