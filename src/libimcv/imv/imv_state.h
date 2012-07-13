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
 * @defgroup imv_state_t imv_state
 * @{ @ingroup imv_state
 */

#ifndef IMV_STATE_H_
#define IMV_STATE_H_

#include <tncifimv.h>

#include <library.h>

typedef struct imv_state_t imv_state_t;

/**
 * Internal state of an IMV connection instance
 */
struct imv_state_t {

	/**
	 * Get the TNCS connection ID attached to the state
	 *
	 * @return				TNCS connection ID of the state
	 */
	 TNC_ConnectionID (*get_connection_id)(imv_state_t *this);

	/**
	 * Checks if long message types are supported for this TNCCS connection
	 *
	 * @return				TRUE if set, FALSE otherwise
	 */
	bool (*has_long)(imv_state_t *this);

	/**
	 * Checks if the exclusive delivery is supported for this TNCCS connection
	 *
	 * @return				TRUE if set, FALSE otherwise
	 */
	bool (*has_excl)(imv_state_t *this);

	/**
	 * Sets the long message types and exclusive flags for this TNCCS connection
	 *
	 * @param has_long		TNCCS connection supports long message types
	 * @param has_excl		TNCCS connection supports exclusive delivery
	 * @return				TRUE if set, FALSE otherwise
	 */
	void (*set_flags)(imv_state_t *this, bool has_long, bool has_excl);

	/**
	 * Set the maximum size of a PA-TNC message for this TNCCS connection
	 *
	 * @max_msg_len			maximum size of a PA-TNC message
	 */
	void (*set_max_msg_len)(imv_state_t *this, u_int32_t max_msg_len);

	/**
	 * Get the maximum size of a PA-TNC message for this TNCCS connection
	 *
	 * @return				maximum size of a PA-TNC message
	 */
	u_int32_t (*get_max_msg_len)(imv_state_t *this);

	/**
	 * Change the connection state
	 *
	 * @param new_state		new connection state
	 */
	void (*change_state)(imv_state_t *this, TNC_ConnectionState new_state);

	/**
	 * Get IMV action recommendation and evaluation result
	 *
	 * @param rec			IMV action recommendation
	 * @param eval			IMV evaluation result
	 *
	 */
	void (*get_recommendation)(imv_state_t *this,
							   TNC_IMV_Action_Recommendation *rec,
							   TNC_IMV_Evaluation_Result *eval);

	/**
	 * Set IMV action recommendation and evaluation result
	 *
	 * @param rec			IMV action recommendation
	 * @param eval			IMV evaluation result
	 *
	 */
	void (*set_recommendation)(imv_state_t *this,
							   TNC_IMV_Action_Recommendation rec,
							   TNC_IMV_Evaluation_Result eval);

	/**
	 * Get reason string based on the preferred language
	 *
	 * @param preferred_language	preferred language
	 * @param reason_string			reason string
	 * @param language code			language of the returned reason string
	 * @return						TRUE if a reason string was found
	 */
	bool (*get_reason_string)(imv_state_t *this, chunk_t preferred_language,
							  chunk_t *reason_string, chunk_t *language_code);

	/**
	 * Destroys an imv_state_t object
	 */
	void (*destroy)(imv_state_t *this);
};

#endif /** IMV_STATE_H_ @}*/
