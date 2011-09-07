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
#include <tcg/pts/pts.h>
#include <library.h>
#include <utils/linked_list.h>

typedef struct imv_attestation_state_t imv_attestation_state_t;
typedef enum imv_attestation_handshake_state_t imv_attestation_handshake_state_t;
typedef struct file_request_t file_request_t;

/**
 * IMV Attestation Handshake States (state machine)
 */
enum imv_attestation_handshake_state_t {
	IMV_ATTESTATION_STATE_INIT,
	IMV_ATTESTATION_STATE_MEAS,
	IMV_ATTESTATION_STATE_COMP_EVID,
	IMV_ATTESTATION_STATE_IML,
	IMV_ATTESTATION_STATE_END,
};

/**
 * Defines an structure to hold requested file/directory
 */
struct file_request_t {
	int request_id;
	int is_dir;
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
	 * Add an entry to list of requested files/directories
	 *
	 * @param request_id				unique request id
	 * @param is_dir					0 for file and 1 for directory
	 */
	void (*add_requested_file)(imv_attestation_state_t *this, int request_id, int is_dir);

	/**
	 * Creates enumerator over the list of requested file/directories
	 *
	 * @return							enumerator over requested files/directories list
	 */
	enumerator_t* (*create_requests_enumerator)(imv_attestation_state_t *this);

	/**
	 * Returns number of entries in the list of requested file/directories
	 *
	 * @return							number of entries in the list of requested file/directories
	 */
	int (*get_requests_count)(imv_attestation_state_t *this);

	/**
	 * Removes an entry with matching request_id from list of requested files/directories
	 *
	 * @param request_id				unique request id
	 * @return							TRUE if request entry found, FALSE otherwise
	 */
	bool (*remove_requested_file)(imv_attestation_state_t *this, int request_id);

	/**
	 * Returns TRUE if entry with given ID is directory and FALSE otherwise
	 *
	 * @param request_id				unique request id
	 * @return							TRUE if request entry found, FALSE otherwise
	 */
	bool (*is_request_dir)(imv_attestation_state_t *this, int request_id, bool *is_dir);
};

/**
 * Create an imv_attestation_state_t instance
 *
 * @param id					connection ID
 */
imv_state_t* imv_attestation_state_create(TNC_ConnectionID id);

#endif /** IMV_ATTESTATION_STATE_H_ @}*/
