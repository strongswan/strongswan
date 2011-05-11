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
 * @defgroup imc_manager imc_manager
 * @{ @ingroup imc
 */

#ifndef IMC_MANAGER_H_
#define IMC_MANAGER_H_

#include "imc.h"

#include <library.h>

typedef struct imc_manager_t imc_manager_t;

/**
 * The IMC manager controls all IMC instances.
 */
struct imc_manager_t {

	/**
	 * Add an IMC instance
	 *
	 * @param imc				IMC instance
	 * @return					TRUE if initialization successful
	 */
	 bool (*add)(imc_manager_t *this, imc_t *imc);

	/**
	 * Remove an IMC instance from the list and return it
	 *
	 * @param id				ID of IMC instance
	 * @return					removed IMC instance
	 */
	imc_t* (*remove)(imc_manager_t *this, TNC_IMCID id);

	/**
	 * Check if an IMC with a given ID is registered with the IMC manager
	 *
	 * @param id				ID of IMC instance
	 * @return					TRUE if registered
	 */
	bool (*is_registered)(imc_manager_t *this, TNC_IMCID id);

	/**
	 * Return the preferred language for recommendations
	 *
	 * @return					preferred language string
	 */
	char* (*get_preferred_language)(imc_manager_t *this);

	/**
	 * Notify all IMC instances
	 *
	 * @param state			communicate the state a connection has reached
	 */
	void (*notify_connection_change)(imc_manager_t *this,
									 TNC_ConnectionID id,
									 TNC_ConnectionState state);

	/**
	 * Begin a handshake between the IMCs and a connection
	 *
	 * @param id				connection ID
	 */
	void (*begin_handshake)(imc_manager_t *this, TNC_ConnectionID id);

	/**
	 * Sets the supported message types reported by a given IMC
	 *
	 * @param id				ID of reporting IMC
	 * @param supported_types	list of messages type supported by IMC
	 * @param type_count		number of supported message types
	 * @return					TNC result code
	 */
	TNC_Result (*set_message_types)(imc_manager_t *this,
									TNC_IMCID id,
									TNC_MessageTypeList supported_types,
									TNC_UInt32 type_count);

	/**
	 * Delivers a message to interested IMCs.
	 *
	 * @param connection_id		ID of connection over which message was received
	 * @param message			message
	 * @param message_len		message length
	 * @param message_type		message type
	 */
	void (*receive_message)(imc_manager_t *this,
							TNC_ConnectionID connection_id,
							TNC_BufferReference message,
							TNC_UInt32 message_len,
							TNC_MessageType message_type);

	/**
	 * Notify all IMCs that all IMV messages received in a batch have been
	 * delivered and this is the IMCs last chance to send a message in the
	 * batch of IMC messages currently being collected.
	 *
	 * @param id				connection ID
	 */
	void (*batch_ending)(imc_manager_t *this, TNC_ConnectionID id);

	/**
	 * Destroy an IMC manager and all its controlled instances.
	 */
	void (*destroy)(imc_manager_t *this);
};

#endif /** IMC_MANAGER_H_ @}*/
