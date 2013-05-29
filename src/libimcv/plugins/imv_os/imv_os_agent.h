/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup imv_os_agent_t imv_os_agent
 * @{ @ingroup imv_os
 */

#ifndef IMV_OS_AGENT_H_
#define IMV_OS_AGENT_H_

#include <imv/imv_state.h>
#include <imv/imv_msg.h>

#include <tncif.h>

typedef struct imv_os_agent_t imv_os_agent_t;

/**
 * Public interface of the OS IMV agent
 */
struct imv_os_agent_t {

	/**
	 * Implements the TNC_IMV_ProvideBindFunction function of the OS IMV
	 *
	 * @param bind_function		Function offered by the TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*bind_functions)(imv_os_agent_t *this,
								 TNC_TNCS_BindFunctionPointer bind_function);

	/**
	 * Implements the TNC_IMV_NotifyConnectionChange() function of the OS IMV
	 *
	 * @param id				Network connection ID assigned by TNCS
	 * @param new_state			New connection state to be set
	 * @return					TNC result code
	 */
	TNC_Result (*notify_connection_change)(imv_os_agent_t *this,
										   TNC_ConnectionID id,
										   TNC_ConnectionState new_state);

	/**
	 * Implements the TNC_IMV_ReceiveMessage() function of the OS IMV
	 *
	 * @param id				Network connection ID assigned by TNCS
	 * @param msg_type			PA-TNC message type
	 * @param msg				Received message
	 * @return					TNC result code
	 */
	TNC_Result (*receive_message)(imv_os_agent_t *this, TNC_ConnectionID id,
								  TNC_MessageType msg_type, chunk_t msg);

	/**
	 * Implements the TNC_IMV_ReceiveMessageLong() function of the OS IMV
	 *
	 * @param id				Network connection ID assigned by TNCS
	 * @param src_imc_id		ID of source IMC
	 * @param dst_imv_id		ID of destination IMV
	 * @param msg_vid			Vendor ID of message type
	 * @param msg_subtype		PA-TNC message subtype
	 * @param msg				Received message
	 * @return					TNC result code
	 */
	TNC_Result (*receive_message_long)(imv_os_agent_t *this,
									   TNC_ConnectionID id,
									   TNC_UInt32 src_imc_id,
									   TNC_UInt32 dst_imv_id,
									   TNC_VendorID msg_vid,
									   TNC_MessageSubtype msg_subtype,
									   chunk_t msg);

	/**
	 * Implements the TNC_IMV_BatchEnding() function of the OS IMV
	 *
	 * @param id				Network connection ID assigned by TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*batch_ending)(imv_os_agent_t *this, TNC_ConnectionID id);

	/**
	 * Implements the TNC_IMV_SolicitRecommendation() function of the OS IMV
	 *
	 * @param id				Network connection ID assigned by TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*solicit_recommendation)(imv_os_agent_t *this,
										 TNC_ConnectionID id);

	/**
	 * Destroys an imv_os_agent_t object
	 */
	void (*destroy)(imv_os_agent_t *this);

};

/**
 * Creates the an OS IMV agent
 *
 * @param name					Name of the IMV
 * @param id					ID of the IMV
 * @param actual_version		TNC IF-IMV version
 */
imv_os_agent_t* imv_os_agent_create(const char* name, TNC_IMVID id,
									TNC_Version *actual_version);

#endif /** IMV_OS_AGENT_H_ @}*/
