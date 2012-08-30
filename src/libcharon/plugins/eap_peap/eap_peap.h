/*
 * Copyright (C) 2011 Andreas Steffen
 * Copyright (C) 2011 HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup eap_peap_i eap_peap
 * @{ @ingroup eap_peap
 */

#ifndef EAP_PEAP_H_
#define EAP_PEAP_H_

typedef struct eap_peap_t eap_peap_t;
typedef struct eap_hdr_t eap_hdr_t;
typedef enum eap_mstlv_type_t eap_mstlv_type_t;
typedef enum eap_mstlv_result_t eap_mstlv_result_t;

#include <sa/eap/eap_method.h>

/**
 * 4 byte EAP header, without type field
 */
struct eap_hdr_t {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;
};

/**
 * TLV types within EAP_MSTLV
 */
enum eap_mstlv_type_t {
	MSTLV_SOH = 1,
	MSTLV_SOH_REQUEST = 2,
	MSTLV_RESULT = 3,
	MSTLV_VENDOR = 7,
	MSTLV_CRYPTO_BINDING = 12,
	/* not a type, but a flag to apply to types */
	MSTLV_MANDATORY = 0x8000,
};

/**
 * TLV result options
 */
enum eap_mstlv_result_t {
	MSTLV_RESULT_SUCCESS = 1,
	MSTLV_RESULT_FAILURE = 2,
};

/**
 * Implementation of eap_method_t using EAP-PEAP.
 */
struct eap_peap_t {

	/**
	 * Implements eap_method_t interface.
	 */
	eap_method_t eap_method;
};

/**
 * Creates the EAP method EAP-PEAP acting as server.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_peap_t object
 */
eap_peap_t *eap_peap_create_server(identification_t *server,
								   identification_t *peer);

/**
 * Creates the EAP method EAP-PEAP acting as peer.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_peap_t object
 */
eap_peap_t *eap_peap_create_peer(identification_t *server,
								 identification_t *peer);

#endif /** EAP_PEAP_H_ @}*/
