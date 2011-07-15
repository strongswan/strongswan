/*
 * Copyright (C) 2007 Tobias Brunner
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

/**
 * @defgroup ike_header ike_header
 * @{ @ingroup payloads
 */

#ifndef IKE_HEADER_H_
#define IKE_HEADER_H_

typedef enum exchange_type_t exchange_type_t;
typedef struct ike_header_t ike_header_t;

#include <library.h>
#include <encoding/payloads/payload.h>

/**
 * Major Version of IKEv2.
 */
#define IKE_MAJOR_VERSION 2

/**
 * Minor Version of IKEv2.
 */
#define IKE_MINOR_VERSION 0

/**
 * Flag in IKEv2-Header. Always 0.
 */
#define HIGHER_VERSION_SUPPORTED_FLAG 0

/**
 * Length of IKE Header in Bytes.
 */
#define IKE_HEADER_LENGTH 28

/**
 * Different types of IKE-Exchanges.
 *
 * See RFC for different types.
 */
enum exchange_type_t{

	/**
	 * EXCHANGE_TYPE_UNDEFINED. In private space, since not a official message type.
	 */
	EXCHANGE_TYPE_UNDEFINED = 255,

	/**
	 * IKE_SA_INIT.
	 */
	IKE_SA_INIT = 34,

	/**
	 * IKE_AUTH.
	 */
	IKE_AUTH = 35,

	/**
	 * CREATE_CHILD_SA.
	 */
	CREATE_CHILD_SA = 36,

	/**
	 * INFORMATIONAL.
	 */
	INFORMATIONAL = 37,

	/**
	 * IKE_SESSION_RESUME (RFC 5723).
	 */
	IKE_SESSION_RESUME = 38,
#ifdef ME
	/**
	 * ME_CONNECT
	 */
	ME_CONNECT = 240
#endif /* ME */
};

/**
 * enum name for exchange_type_t
 */
extern enum_name_t *exchange_type_names;

/**
 * An object of this type represents an IKEv2 header and is used to
 * generate and parse IKEv2 headers.
 *
 * The header format of an IKEv2-Message is compatible to the
 * ISAKMP-Header format to allow implementations supporting
 * both versions of the IKE-protocol.
 */
struct ike_header_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Get the initiator spi.
	 *
	 * @return 				initiator_spi
	 */
	u_int64_t (*get_initiator_spi) (ike_header_t *this);

	/**
	 * Set the initiator spi.
	 *
	 * @param initiator_spi	initiator_spi
	 */
	void (*set_initiator_spi) (ike_header_t *this, u_int64_t initiator_spi);

	/**
	 * Get the responder spi.
	 *
	 * @return 				responder_spi
	 */
	u_int64_t (*get_responder_spi) (ike_header_t *this);

	/**
	 * Set the responder spi.
	 *
	 * @param responder_spi	responder_spi
	 */
	void (*set_responder_spi) (ike_header_t *this, u_int64_t responder_spi);

	/**
	 * Get the major version.
	 *
	 * @return 				major version
	 */
	u_int8_t (*get_maj_version) (ike_header_t *this);

	/**
	 * Set the major version.
	 *
	 * @param major			major version
	 */
	void (*set_maj_version) (ike_header_t *this, u_int8_t major);

	/**
	 * Get the minor version.
	 *
	 * @return 				minor version
	 */
	u_int8_t (*get_min_version) (ike_header_t *this);

	/**
	 * Set the minor version.
	 *
	 * @param minor			minor version
	 */
	void (*set_min_version) (ike_header_t *this, u_int8_t minor);

	/**
	 * Get the response flag.
	 *
	 * @return 				response flag
	 */
	bool (*get_response_flag) (ike_header_t *this);

	/**
	 * Set the response flag-
	 *
	 * @param response		response flag
	 */
	void (*set_response_flag) (ike_header_t *this, bool response);

	/**
	 * Get "higher version supported"-flag.
	 *
	 * @return 				version flag
	 */
	bool (*get_version_flag) (ike_header_t *this);

	/**
	 * Set the "higher version supported"-flag.
	 *
	 * @param version		flag value
	 */
	void (*set_version_flag)(ike_header_t *this, bool version);

	/**
	 * Get the initiator flag.
	 *
	 * @return 				initiator flag
	 */
	bool (*get_initiator_flag) (ike_header_t *this);

	/**
	 * Set the initiator flag.
	 *
	 * @param initiator		initiator flag
	 */
	void (*set_initiator_flag) (ike_header_t *this, bool initiator);

	/**
	 * Get the exchange type.
	 *
	 * @return 				exchange type
	 */
	u_int8_t (*get_exchange_type) (ike_header_t *this);

	/**
	 * Set the  exchange type.
	 *
	 * @param exchange_type	exchange type
	 */
	void (*set_exchange_type) (ike_header_t *this, u_int8_t exchange_type);

	/**
	 * Get the message id.
	 *
	 * @return 				message id
	 */
	u_int32_t (*get_message_id) (ike_header_t *this);

	/**
	 * Set the message id.
	 *
	 * @param initiator_spi	message id
	 */
	void (*set_message_id) (ike_header_t *this, u_int32_t message_id);

	/**
	 * Destroys a ike_header_t object.
	 */
	void (*destroy) (ike_header_t *this);
};

/**
 * Create an ike_header_t object
 *
 * @return ike_header_t object
 */
ike_header_t *ike_header_create(void);

#endif /** IKE_HEADER_H_ @}*/
