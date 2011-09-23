/*
 * Copyright (C) 2011 Sansar Choinyambuu
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
 * @defgroup imv_attestation_state_t imv_attestation_state
 * @{ @ingroup imv_attestation_state
 */

#ifndef IMV_ATTESTATION_STATE_H_
#define IMV_ATTESTATION_STATE_H_

#include <imv/imv_state.h>
#include <pts/pts.h>
#include <library.h>

typedef struct imv_attestation_state_t imv_attestation_state_t;
typedef enum imv_attestation_handshake_state_t imv_attestation_handshake_state_t;

/**
 * IMV Attestation Handshake States (state machine)
 */
enum imv_attestation_handshake_state_t {
	IMV_ATTESTATION_STATE_INIT,
	IMV_ATTESTATION_STATE_TPM_INIT,
	IMV_ATTESTATION_STATE_MEAS,
	IMV_ATTESTATION_STATE_COMP_EVID,
	IMV_ATTESTATION_STATE_END,
};

/**
 * Internal state of an imv_attestation_t connection instance
 */
struct imv_attestation_state_t {

	/**
	 * imv_state_t interface
	 */
	imv_state_t interface;

	/**
	 * Get state of the handshake
	 *
	 * @return					the handshake state of IMV
	 */
	imv_attestation_handshake_state_t (*get_handshake_state)(imv_attestation_state_t *this);
	
	/**
	 * Set state of the handshake
	 *
	 * @param new_state			the handshake state of IMV
	 */
	void (*set_handshake_state)(imv_attestation_state_t *this,
								imv_attestation_handshake_state_t new_state);

	/**
	 * Get the PTS object
	 *
	 * @return					PTS object
	 */
	pts_t* (*get_pts)(imv_attestation_state_t *this);

	/**
	 * Add an entry to the list of pending file/directory measurement requests
	 *
	 * @param file_id			primary key into file table
	 * @param is_dir			TRUE if directory
	 * @return					unique request ID
	 */
	u_int16_t (*add_request)(imv_attestation_state_t *this, int file_id,
							 bool is_dir);

	/**
	 * Returns the number of pending file/directory measurement requests
	 *
	 * @return					number of pending requests
	 */
	int (*get_request_count)(imv_attestation_state_t *this);

	/**
	 * Check for presence of request_id and if found remove it from the list
	 *
	 * @param id				unique request ID
	 * @param file_id			primary key into file table
	 * @param is_dir			return TRUE if request was for a directory
	 * @return					TRUE if request ID found, FALSE otherwise
	 */
	bool (*check_off_request)(imv_attestation_state_t *this, u_int16_t id,
							  int *file_id, bool *is_dir);

};

/**
 * Create an imv_attestation_state_t instance
 *
 * @param id					connection ID
 */
imv_state_t* imv_attestation_state_create(TNC_ConnectionID id);

#endif /** IMV_ATTESTATION_STATE_H_ @}*/
