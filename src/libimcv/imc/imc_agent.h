/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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
 *
 * @defgroup imc_agent_t imc_agent
 * @{ @ingroup imc_agent
 */

#ifndef IMC_AGENT_H_
#define IMC_AGENT_H_

#include "imc_state.h"
#include "pa_tnc/pa_tnc_msg.h"

#include <tncifimc.h>
#include <pen/pen.h>

#include <library.h>

typedef struct imc_agent_t imc_agent_t;

/**
 * Core functions of an Integrity Measurement Verifier (IMC)
 */
struct imc_agent_t {

	/**
	 * Ask a TNCC to retry an Integrity Check Handshake
	 *
	 * @param imc_id			IMC ID assigned by TNCC
	 * @param connection_id		network connection ID assigned by TNCC
	 * @param reason			IMC retry reason
	 * @return					TNC result code
	 */
	TNC_Result (*request_handshake_retry)(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason);

	/**
	 * Bind TNCC functions
	 *
	 * @param bind_function		function offered by the TNCC
	 * @return					TNC result code
	 */
	TNC_Result (*bind_functions)(imc_agent_t *this,
								 TNC_TNCC_BindFunctionPointer bind_function);

	/**
	 * Create the IMC state for a TNCCS connection instance
	 *
	 * @param state				internal IMC state instance
	 * @return					TNC result code
	 */
	TNC_Result (*create_state)(imc_agent_t *this, imc_state_t *state);

	/**
	 * Delete the IMC state for a TNCCS connection instance
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*delete_state)(imc_agent_t *this,
							   TNC_ConnectionID connection_id);

	/**
	 * Change the current state of a TNCCS connection
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param new_state			new state of TNCCS connection
	 * @return					TNC result code
	 */
	TNC_Result (*change_state)(imc_agent_t *this,
							   TNC_ConnectionID connection_id,
							   TNC_ConnectionState new_state);

	/**
	 * Get the IMC state for a TNCCS connection instance
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param state				internal IMC state instance
	 * @return					TRUE if the state was found
	 */
	bool (*get_state)(imc_agent_t *this,
					  TNC_ConnectionID connection_id, imc_state_t **state);

	/**
	 * Call when an PA-TNC message is to be sent
	 *
	 * @param connection_id		network connection ID assigned by TNCC
	 * @param msg				message to send
	 * @return					TNC result code
	 */
	TNC_Result (*send_message)(imc_agent_t *this,
							   TNC_ConnectionID connection_id,
							   chunk_t msg);

	/**
	 * Call when a PA-TNC message was received
	 *
	 * @param connection_id		network connection ID assigned by TNCC
	 * @param msg				received unparsed message
	 * @param msg_type			message type of the received message
	 * @param pa_tnc_message	parsed PA-TNC message or NULL if an error occurred
	 * @return					TNC result code
	 */
	TNC_Result (*receive_message)(imc_agent_t *this,
								  TNC_ConnectionID connection_id, chunk_t msg,
								  TNC_MessageType msg_type,
								  pa_tnc_msg_t **pa_tnc_msg);

	/**
	 * Destroys an imc_agent_t object
	 */
	void (*destroy)(imc_agent_t *this);
};

/**
 * Create an imc_agent_t object
 *
 * @param name				name of the IMC
 * @param vendor_id			vendor ID of the IMC
 * @param subtype			message subtype of the IMC
 * @param id				ID of the IMC as assigned by the TNCS
 * @param actual_version	actual version of the IF-IMC API
 *
 */
imc_agent_t *imc_agent_create(const char *name,
							  pen_t vendor_id, u_int32_t subtype,
							  TNC_IMCID id, TNC_Version *actual_version);

#endif /** IMC_AGENT_H_ @}*/
