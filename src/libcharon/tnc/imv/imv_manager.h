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
 * @defgroup imv_manager imv_manager
 * @{ @ingroup imv
 */

#ifndef IMV_MANAGER_H_
#define IMV_MANAGER_H_

#include "imv.h"
#include "imv_recommendations.h"

#include <library.h>

typedef struct imv_manager_t imv_manager_t;

/**
 * The IMV manager controls all IMV instances.
 */
struct imv_manager_t {

	/**
	 * Add an IMV instance
	 *
	 * @param imv				IMV instance
	 * @return					TRUE if initialization successful
	 */
	bool (*add)(imv_manager_t *this, imv_t *imv);

	/**
	 * Remove an IMV instance from the list and return it
	 *
	 * @param id				ID of IMV instance
	 * @return					removed IMC instance
	 */
	imv_t* (*remove)(imv_manager_t *this, TNC_IMVID id);

	/**
	 * Check if an IMV with a given ID is registered with the IMV manager
	 *
	 * @param id				ID of IMV instance
	 * @return					TRUE if registered
	 */
	bool (*is_registered)(imv_manager_t *this, TNC_IMVID id);


	/**
	 * Get the configured recommendation policy
	 *
	 * @return					configured recommendation policy
	 */
	recommendation_policy_t (*get_recommendation_policy)(imv_manager_t *this);

	/**
	 * Create an empty set of IMV recommendations and evaluations
	 *
	 * @return					instance of a recommendations_t list
	 */
	recommendations_t* (*create_recommendations)(imv_manager_t *this);

	/**
	 * Enforce the TNC recommendation on the IKE_SA by either inserting an
	 * allow|isolate group membership rule (TRUE) or by blocking access (FALSE)
	 *
	 * @param rec				TNC action recommendation
	 * @param eval				TNC evaluation result
	 * @return					TRUE for allow|isolate, FALSE for none
	 */
	bool (*enforce_recommendation)(imv_manager_t *this,
								   TNC_IMV_Action_Recommendation rec,
								   TNC_IMV_Evaluation_Result eval);

	/**
	 * Notify all IMV instances
	 *
	 * @param state			communicate the state a connection has reached
	 */
	void (*notify_connection_change)(imv_manager_t *this,
									 TNC_ConnectionID id,
									 TNC_ConnectionState state);

	/**
	 * Sets the supported message types reported by a given IMV
	 *
	 * @param id				ID of reporting IMV
	 * @param supported_types	list of messages type supported by IMV
	 * @param type_count		number of supported message types
	 * @return					TNC result code
	 */
	TNC_Result (*set_message_types)(imv_manager_t *this,
									TNC_IMVID id,
									TNC_MessageTypeList supported_types,
									TNC_UInt32 type_count);

	/**
	 * Solicit recommendations from IMVs that have not yet provided one
	 *
	 * @param id				connection ID
	 */
	void (*solicit_recommendation)(imv_manager_t *this, TNC_ConnectionID id);

	/**
	 * Delivers a message to interested IMVs.
	 *
	 * @param connection_id		ID of connection over which message was received
	 * @param message			message
	 * @param message_len		message length
	 * @param message_type		message type
	 */
	void (*receive_message)(imv_manager_t *this,
							TNC_ConnectionID connection_id,
							TNC_BufferReference message,
							TNC_UInt32 message_len,
							TNC_MessageType message_type);

	/**
	 * Notify all IMVs that all IMC messages received in a batch have been
	 * delivered and this is the IMVs last chance to send a message in the
	 * batch of IMV messages currently being collected.
	 *
	 * @param id				connection ID
	 */
	void (*batch_ending)(imv_manager_t *this, TNC_ConnectionID id);

	/**
	 * Destroy an IMV manager and all its controlled instances.
	 */
	void (*destroy)(imv_manager_t *this);
};

#endif /** IMV_MANAGER_H_ @}*/
