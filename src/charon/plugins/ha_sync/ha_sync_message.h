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
#include <utils/host.h>
#include <utils/identification.h>
#include <sa/ike_sa_id.h>
#include <config/traffic_selector.h>

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
	/** add a completely new IKE_SA */
	HA_SYNC_IKE_ADD = 1,
	/** update an existing IKE_SA (message IDs, address update, ...) */
	HA_SYNC_IKE_UPDATE,
	/** delete an existing IKE_SA */
	HA_SYNC_IKE_DELETE,
	/** rekeying an existing IKE_SA, transferring CHILD_SAs to a new one */
	HA_SYNC_IKE_REKEY,
	/** add a new CHILD_SA */
	HA_SYNC_CHILD_ADD,
	/** delete an existing CHILD_SA */
	HA_SYNC_CHILD_DELETE,
};

/**
 * Type of attributes contained in a message
 */
enum ha_sync_message_attribute_t {
	/** ike_sa_id_t*, to identify IKE_SA */
	HA_SYNC_IKE_ID = 1,
	/** ike_Sa_id_t*, identifies IKE_SA which gets rekeyed */
	HA_SYNC_IKE_REKEY_ID,
	/** identification_t*, local identity */
	HA_SYNC_LOCAL_ID,
	/** identification_t*, remote identity */
	HA_SYNC_REMOTE_ID,
	/** identification_t*, EAP identity */
	HA_SYNC_EAP_ID,
	/** host_t*, local address */
	HA_SYNC_LOCAL_ADDR,
	/** host_t*, remote address */
	HA_SYNC_REMOTE_ADDR,
	/** char*, name of configuration */
	HA_SYNC_CONFIG_NAME,
	/** u_int32_t, bitset of ike_condition_t */
	HA_SYNC_CONDITIONS,
	/** u_int32_t, bitset of ike_extension_t */
	HA_SYNC_EXTENSIONS,
	/** host_t*, local virtual IP */
	HA_SYNC_LOCAL_VIP,
	/** host_t*, remote virtual IP */
	HA_SYNC_REMOTE_VIP,
	/** host_t*, additional MOBIKE peer address */
	HA_SYNC_ADDITIONAL_ADDR,
	/** chunk_t, initiators nonce */
	HA_SYNC_NONCE_I,
	/** chunk_t, responders nonce */
	HA_SYNC_NONCE_R,
	/** chunk_t, diffie hellman shared secret */
	HA_SYNC_SECRET,
	/** u_int16_t, pseudo random function */
	HA_SYNC_ALG_PRF,
	/** u_int16_t, encryption algorithm */
	HA_SYNC_ALG_ENCR,
	/** u_int16_t, encryption key size in bytes */
	HA_SYNC_ALG_ENCR_LEN,
	/** u_int16_t, integrity protection algorithm */
	HA_SYNC_ALG_INTEG,
	/** u_int8_t, IPsec mode, TUNNEL|TRANSPORT|... */
	HA_SYNC_IPSEC_MODE,
	/** u_int8_t, IPComp protocol */
	HA_SYNC_IPCOMP,
	/** u_int32_t, inbound security parameter index */
	HA_SYNC_INBOUND_SPI,
	/** u_int32_t, outbound security parameter index */
	HA_SYNC_OUTBOUND_SPI,
	/** u_int16_t, inbound security parameter index */
	HA_SYNC_INBOUND_CPI,
	/** u_int16_t, outbound security parameter index */
	HA_SYNC_OUTBOUND_CPI,
	/** traffic_selector_t*, local traffic selector */
	HA_SYNC_LOCAL_TS,
	/** traffic_selector_t*, remote traffic selector */
	HA_SYNC_REMOTE_TS,
};

/**
 * Union to enumerate typed attributes in a message
 */
union ha_sync_message_value_t {
	u_int8_t u8;
	u_int16_t u16;
	u_int32_t u32;
	char *str;
	chunk_t chunk;
	ike_sa_id_t *ike_sa_id;
	identification_t *id;
	host_t *host;
	traffic_selector_t *ts;
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
