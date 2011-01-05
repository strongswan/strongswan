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
 * @defgroup pb_remediation_parameters_msg pb_remediation_parameters_msg
 * @{ @ingroup tnccs_20
 */

#ifndef PB_REMEDIATION_PARAMETERS_MSG_H_
#define PB_REMEDIATION_PARAMETERS_MSG_H_

typedef enum pb_tnc_remed_param_type_t pb_tnc_remed_param_type_t;
typedef struct pb_remediation_parameters_msg_t pb_remediation_parameters_msg_t;

#include "pb_tnc_msg.h"

/**
 * PB-TNC Remediation Parameter Types as defined in section 4.8.1 of RFC 5793
 */
enum pb_tnc_remed_param_type_t {
	PB_REMEDIATION_URI =			1,
	PB_REMEDIATION_STRING =			2,
};

/**
 * enum name for pb_tnc_remed_param_type_t.
 */
extern enum_name_t *pb_tnc_remed_param_type_names;

/**
 * Class representing the PB-Remediation-Parameters message type.
 */
struct pb_remediation_parameters_msg_t {

	/**
	 * PB-TNC Message interface
	 */
	pb_tnc_msg_t pb_interface;

	/**
	 * Get Remediation Parameters Vendor ID and Type
	 *
	 * @param type				Remediation Parameters Type
	 * @return					Remediation Parameters Vendor ID
	 */
	u_int32_t (*get_vendor_id)(pb_remediation_parameters_msg_t *this,
							   u_int32_t *type);

	/**
	 * Get Remediation String
	 *
	 * @return					Remediation String
	 */
	chunk_t (*get_remediation_string)(pb_remediation_parameters_msg_t *this);

	/**
	 * Get Reason String Language Code
	 *
	 * @return					Language Code
	 */
	chunk_t (*get_language_code)(pb_remediation_parameters_msg_t *this);
};

/**
 * Create a PB-Remediation-Parameters message from parameters
 *
 * @param vendor_id				Remediation Parameters Vendor ID
 * @param type					Remediation Parameters Type		
 * @param remediation_string	Remediation String
 * @param language_code			Language Code
 */
pb_tnc_msg_t* pb_remediation_parameters_msg_create(u_int32_t vendor_id,
												   u_int32_t type,
												   chunk_t remediation_string,
												   chunk_t language_code);

/**
 * Create an unprocessed PB-Remediation-Parameters message from raw data
 *
  * @param data		PB-Remediation-Parameters message data
 */
pb_tnc_msg_t* pb_remediation_parameters_msg_create_from_data(chunk_t data);

#endif /** PB_PA_MSG_H_ @}*/
