/*
 * Copyright (C) 2010 Sansar Choinyambuu
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
 * @defgroup pb_reason_string_message pb_reason_string_message
 * @{ @ingroup tnccs_20
 */

#ifndef PB_REASON_STRING_MESSAGE_H_
#define PB_REASON_STRING_MESSAGE_H_

#include "pb_tnc_message.h"

typedef struct pb_reason_string_message_t pb_reason_string_message_t;

/**
 * Classs representing the PB-Reason-String message type.
 */
struct pb_reason_string_message_t {

	/**
	 * PB-TNC Message interface
	 */
	pb_tnc_message_t pb_interface;

	/**
	 * Get Reason String Length
	 *
	 * @return			Length of reason string
	 */
	chunk_t (*get_reason_string_length)(pb_reason_string_message_t *this);

	/**
	 * Get Reason String
	 *
	 * @return			Reason string
	 */
	chunk_t (*get_reason_string)(pb_reason_string_message_t *this);

	/**
	 * Get Reason String Language Code Length
	 *
	 * @return			Length of language code
	 */
	chunk_t (*get_language_code_length)(pb_reason_string_message_t *this);

	/**
	 * Get Reason String Language Code
	 *
	 * @return			Language code
	 */
	chunk_t (*get_language_code)(pb_reason_string_message_t *this);
};

/**
 * Create a PB-Reason-String message from parameters
 *
 * @param reason_string		Reason string
  * @param language_code	Language code
 */
pb_tnc_message_t* pb_reason_string_message_create(chunk_t reason_string,
							chunk_t language_code);

/**
 * Create an unprocessed PB-Reason-String message from raw data
 *
  * @param data		PB-Reason-String message data
 */
pb_tnc_message_t* pb_reason_string_message_create_from_data(chunk_t data);

#endif /** PB_PA_MESSAGE_H_ @}*/
