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
 * @defgroup pb_access_recommendation_message pb_access_recommendation_message
 * @{ @ingroup tnccs_20
 */

#ifndef PB_ACCESS_RECOMMENDATION_MESSAGE_H_
#define PB_ACCESS_RECOMMENDATION_MESSAGE_H_

#include "pb_tnc_message.h"

typedef struct pb_access_recommendation_message_t pb_access_recommendation_message_t;

/**
 * Classs representing the PB-Access-Recommendation message type.
 */
struct pb_access_recommendation_message_t {

	/**
	 * PB-TNC Message interface
	 */
	pb_tnc_message_t pb_interface;

	/**
	 * Get PB Access Recommendation
	 *
	 * @return			PB Access Recommendation
	 */
	u_int16_t (*get_access_recommendation)(pb_access_recommendation_message_t *this);
};

/**
 * Create a PB-Access-Recommendation message from parameters
 *
 * @param access_recommendation		Access Recommendation code
 */
pb_tnc_message_t* pb_access_recommendation_message_create(u_int16_t recommendation);

/**
 * Create an unprocessed PB-Access-Recommendation message from raw data
 *
  * @param data		PB-Access-Recommendation message data
 */
pb_tnc_message_t* pb_access_recommendation_message_create_from_data(chunk_t data);

#endif /** PB_PA_MESSAGE_H_ @}*/
