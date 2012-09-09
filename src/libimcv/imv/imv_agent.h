/*
 * Copyright (C) 2011-2012 Andreas Steffen
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
 *
 * @defgroup imv_agent_t imv_agent
 * @{ @ingroup imv_agent
 */

#ifndef IMV_AGENT_H_
#define IMV_AGENT_H_

#include "imv_state.h"
#include "pa_tnc/pa_tnc_msg.h"

#include <tncifimv.h>
#include <pen/pen.h>
#include <utils/linked_list.h>

#include <library.h>

typedef struct imv_agent_t imv_agent_t;

/**
 * Core functions of an Integrity Measurement Verifier (IMV)
 */
struct imv_agent_t {

	/**
	 * Ask a TNCS to retry an Integrity Check Handshake
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param reason			IMV retry reason
	 * @return					TNC result code
	 */
	TNC_Result (*request_handshake_retry)(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason);

	/**
	 * Bind TNCS functions
	 *
	 * @param bind_function		function offered by the TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*bind_functions)(imv_agent_t *this,
								 TNC_TNCS_BindFunctionPointer bind_function);

	/**
	 * Create the IMV state for a TNCCS connection instance
	 *
	 * @param state				internal IMV state instance
	 * @return					TNC result code
	 */
	TNC_Result (*create_state)(imv_agent_t *this, imv_state_t *state);

	/**
	 * Delete the IMV state for a TNCCS connection instance
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*delete_state)(imv_agent_t *this,
							   TNC_ConnectionID connection_id);

	/**
	 * Change the current state of a TNCCS connection
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param new_state			new state of TNCCS connection
	 * @param state_p			internal IMV state instance [optional argument]
	 * @return					TNC result code
	 */
	TNC_Result (*change_state)(imv_agent_t *this,
							   TNC_ConnectionID connection_id,
							   TNC_ConnectionState new_state,
							   imv_state_t **state_p);

	/**
	 * Get the IMV state for a TNCCS connection instance
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param state				internal IMV state instance
	 * @return					TRUE if the state was found
	 */
	bool (*get_state)(imv_agent_t *this,
					  TNC_ConnectionID connection_id, imv_state_t **state);

	/**
	 * Call when a PA-TNC message is to be sent
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param excl				exclusive flag
	 * @param src_imv_id		IMV ID to be set as source
	 * @param dst_imc_id		IMD ID to be set as destination
	 * @param attr_list			list of PA-TNC attributes to send
	 * @return					TNC result code
	 */
	TNC_Result (*send_message)(imv_agent_t *this,
							   TNC_ConnectionID connection_id, bool excl,
							   TNC_UInt32 src_imv_id, TNC_UInt32 dst_imc_id,
							   linked_list_t *attr_list);

	/**
	 * Call when a PA-TNC message was received
	 *
	 * @param state				state for current connection
	 * @param msg				received unparsed message
	 * @param msg_vid			message vendorID of the received message
	 * @param msg_subtype		message subtype of the received message
	 * @param src_imc_id		source IMC ID
	 * @param dst_imv_id		destination IMV ID
	 * @param pa_tnc_message	parsed PA-TNC message or NULL if an error occurred
	 * @return					TNC result code
	 */
	TNC_Result (*receive_message)(imv_agent_t *this,
								  imv_state_t *state, chunk_t msg,
								  TNC_VendorID msg_vid,
								  TNC_MessageSubtype msg_subtype,
								  TNC_UInt32 src_imc_id,
								  TNC_UInt32 dst_imv_id,
								  pa_tnc_msg_t **pa_tnc_msg);

	/**
	 * Set Action Recommendation and Evaluation Result in the IMV state
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param rec				IMV action recommendation
	 * @param eval				IMV evaluation result
	 * @return					TNC result code
	 */
	TNC_Result (*set_recommendation)(imv_agent_t *this,
									 TNC_ConnectionID connection_id,
									 TNC_IMV_Action_Recommendation rec,
									 TNC_IMV_Evaluation_Result eval);

	/**
	 * Deliver IMV Action Recommendation and IMV Evaluation Result to the TNCS
	 *
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param dst_imc_id		IMD ID to be set as destination
	 * @return					TNC result code
	 */
	TNC_Result (*provide_recommendation)(imv_agent_t *this,
										 TNC_ConnectionID connection_id,
										 TNC_UInt32 dst_imc_id);

	/**
	 * Reserve additional IMV IDs from TNCS
	 *
	 * @param count				number of additional IMV IDs to be assigned
	 * @return					TNC result code
	 */
	TNC_Result (*reserve_additional_ids)(imv_agent_t *this, int count);

	/**
	 * Return the number of additional IMV IDs assigned by the TNCS
	 *
	 * @return					number of additional IMV IDs
	 */
	int (*count_additional_ids)(imv_agent_t *this);

	/**
	 * Create an enumerator for the additional IMV IDs
	 */
	enumerator_t* (*create_id_enumerator)(imv_agent_t *this);

	/**
	 * Destroys an imv_agent_t object
	 */
	void (*destroy)(imv_agent_t *this);
};

/**
 * Create an imv_agent_t object
 *
 * @param name				name of the IMV
 * @param vendor_id			vendor ID of the IMV
 * @param subtype			message subtype of the IMV
 * @param id				ID of the IMV as assigned by the TNCS
 * @param actual_version	actual version of the IF-IMV API
 *
 */
imv_agent_t *imv_agent_create(const char *name,
							  pen_t vendor_id, u_int32_t subtype,
							  TNC_IMVID id, TNC_Version *actual_version);

#endif /** IMV_AGENT_H_ @}*/
