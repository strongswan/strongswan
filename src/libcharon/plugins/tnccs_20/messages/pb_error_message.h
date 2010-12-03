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
 * @defgroup pb_error_message pb_error_message
 * @{ @ingroup tnccs_20
 */

#ifndef PB_ERROR_MESSAGE_H_
#define PB_ERROR_MESSAGE_H_

#include "pb_tnc_message.h"

typedef struct pb_error_message_t pb_error_message_t;

/**
 * Classs representing the PB-Error message type.
 */
struct pb_error_message_t {

	/**
	 * PB-TNC Message interface
	 */
	pb_tnc_message_t pb_interface;

	/**
	 * Get PB Error code Vendor ID
	 *
	 * @return			PB Error code Vendor ID
	 */
	u_int32_t (*get_vendor_id)(pb_error_message_t *this);

	/**
	 * Get PB Error Code
	 *
	 * @return				PB Error Code
	 */
	u_int16_t (*get_error_code)(pb_error_message_t *this);

	/**
	 * Get the PB Error Parameters
	 *
	 * @return				PB Error Parameter
	 */
	u_int32_t (*get_parameters)(pb_error_message_t *this);

	/**
	 * Get the fatal flag
	 *
	 * @return				fatal flag
	 */
	bool (*get_fatal_flag)(pb_error_message_t *this);

	/**
	 * Set the fatal flag
	 *
	 * @param excl			fatal flag
	 */
	void (*set_fatal_flag)(pb_error_message_t *this, bool is_fatal);
};

/**
 * Create a PB-Error message from parameters
 *
 * @param vendor_id			Error Code Vendor ID
 * @param error_code		Error Code
 */
pb_tnc_message_t* pb_error_message_create(u_int32_t vendor_id,
						pb_tnc_error_code_t error_code);		
/**
 * Create a PB-Error message from parameters
 *
 * @param vendor_id			Error Code Vendor ID
 * @param error_code		Error Code
 * @param error_parameters	Error parameters
 */
pb_tnc_message_t* pb_error_message_create_with_parameter(u_int32_t vendor_id,
						pb_tnc_error_code_t error_code,
						u_int32_t error_parameters);
/**
 * Create an unprocessed PB-Error message from raw data
 *
 * @param data				PB-Error message data
 */
pb_tnc_message_t* pb_error_message_create_from_data(chunk_t data);

#endif /** PB_PA_MESSAGE_H_ @}*/
