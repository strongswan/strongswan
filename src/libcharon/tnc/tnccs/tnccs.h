/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tnccs tnccs
 * @ingroup tnc
 *
 * @defgroup tnccst tnccs
 * @{ @ingroup tnccs
 */

#ifndef TNCCS_H_
#define TNCCS_H_

#include <tncif.h>
#include <tncifimc.h>
#include <tncifimv.h>

#include <library.h>

typedef enum tnccs_type_t tnccs_type_t;

/**
 * Type of TNC Client/Server protocol
 */
enum tnccs_type_t {
	TNCCS_UNKNOWN,
	TNCCS_1_1,
	TNCCS_SOH,
	TNCCS_2_0,
	TNCCS_DYNAMIC
};

/**
 * enum names for tnccs_type_t.
 */
extern enum_name_t *tnccs_type_names;

typedef struct tnccs_t tnccs_t;

/**
 * Constructor definition for a pluggable TNCCS protocol implementation.
 *
 * @param is_server		TRUE if TNC Server, FALSE if TNC Client
 * @return				implementation of the tnccs_t interface
 */
typedef tnccs_t* (*tnccs_constructor_t)(bool is_server);

/**
 * Callback function adding a message to a TNCCS batch
 *
 * @param imc_id		ID of IMC or TNC_IMCID_ANY
 * @param imc_id		ID of IMV or TNC_IMVID_ANY
 * @param msg			message to be added
 * @param msg_len		message length
 * @param msg_type		message type
 * @return			result code
 */
typedef TNC_Result (*tnccs_send_message_t)(tnccs_t* tncss, TNC_IMCID imc_id,
													 TNC_IMVID imv_id,
									 				 TNC_BufferReference msg,
													 TNC_UInt32 msg_len,
													 TNC_MessageType msg_type);

#endif /** TNCCS_H_ @}*/
