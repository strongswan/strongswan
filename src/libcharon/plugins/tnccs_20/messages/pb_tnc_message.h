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
 * @defgroup pb_tnc_message pb_tnc_message
 * @{ @ingroup tnccs_20
 */

#ifndef PB_TNC_MESSAGE_H_
#define PB_TNC_MESSAGE_H_

#include <library.h>
#include <tnccs_20_types.h>

typedef enum pb_tnc_msg_type_t pb_tnc_msg_type_t;

/**
 * PB-TNC Message Types as defined in section 4.3 of RFC 5793
 */
enum pb_tnc_msg_type_t {
	PB_MSG_EXPERIMENTAL =				0,
	PB_MSG_PA =							1,
	PB_MSG_ASSESSMENT_RESULT =			2,
	PB_MSG_ACCESS_RECOMMENDATION =		3,
	PB_MSG_REMEDIATION_PARAMETERS =		4,
	PB_MSG_ERROR =						5,
	PB_MSG_LANGUAGE_PREFERENCE =		6,
	PB_MSG_REASON_STRING =				7,
	PB_MSG_ROOF =						7
};

/**
 * enum name for pb_tnc_msg_type_t.
 */
extern enum_name_t *pb_tnc_msg_type_names;

typedef struct pb_tnc_message_t pb_tnc_message_t;

/**
 * Generic interface for all PB-TNC message types.
 *
 * To handle all messages in a generic way, this interface
 * must be implemented by each message type.
 */
struct pb_tnc_message_t {

	/**
	 * Get the PB-TNC Message Type
	 *
	 * @return					 PB-TNC Message Type
	 */
	pb_tnc_msg_type_t (*get_type)(pb_tnc_message_t *this);

	/**
	 * Get the encoding of the PB-TNC Message Value
	 *
	 * @return					encoded PB-TNC Message Value
	 */
	chunk_t (*get_encoding)(pb_tnc_message_t *this);

	/**
	 * Build the PB-TNC Message Value
	 */
	void (*build)(pb_tnc_message_t *this);

	/**
	 * Process the PB-TNC Message Value
	 *
	 * @return					return processing status
	 */
	status_t (*process)(pb_tnc_message_t *this);

	/**
	 * Get a new reference to the message.
	 *
	 * @return			this, with an increased refcount
	 */
	pb_tnc_message_t* (*get_ref)(pb_tnc_message_t *this);

	/**
	 * Destroys a pb_tnc_message_t object.
	 */
	void (*destroy)(pb_tnc_message_t *this);
};

/**
 * Create an unprocessed PB-TNC message
 *
 * Useful for the parser which wants a generic constructor for all
 * pb_tnc_message_t types.
 *
 * @param type		PB-TNC message type
 * @param value		PB-TNC message value
 */
pb_tnc_message_t* pb_tnc_message_create(pb_tnc_msg_type_t type, chunk_t value);

#endif /** PB_TNC_MESSAGE_H_ @}*/
