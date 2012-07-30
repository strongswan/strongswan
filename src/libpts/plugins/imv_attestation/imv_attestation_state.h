/*
 * Copyright (C) 2011-2012 Sansar Choinyambuu, Andreas Steffen
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
#include <pts/pts_database.h>
#include <pts/components/pts_component.h>
#include <library.h>

typedef struct imv_attestation_state_t imv_attestation_state_t;
typedef enum imv_attestation_handshake_state_t imv_attestation_handshake_state_t;

/**
 * IMV Attestation Handshake States (state machine)
 */
enum imv_attestation_handshake_state_t {
	IMV_ATTESTATION_STATE_INIT,
	IMV_ATTESTATION_STATE_NONCE_REQ,
	IMV_ATTESTATION_STATE_TPM_INIT,
	IMV_ATTESTATION_STATE_MEAS,
	IMV_ATTESTATION_STATE_COMP_EVID,
	IMV_ATTESTATION_STATE_EVID_FINAL,
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
	imv_attestation_handshake_state_t (*get_handshake_state)(
		imv_attestation_state_t *this);
	
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
	u_int16_t (*add_file_meas_request)(imv_attestation_state_t *this,
									   int file_id, bool is_dir);

	/**
	 * Returns the number of pending file/directory measurement requests
	 *
	 * @return					number of pending requests
	 */
	int (*get_file_meas_request_count)(imv_attestation_state_t *this);

	/**
	 * Check for presence of request_id and if found remove it from the list
	 *
	 * @param id				unique request ID
	 * @param file_id			primary key into file table
	 * @param is_dir			return TRUE if request was for a directory
	 * @return					TRUE if request ID found, FALSE otherwise
	 */
	bool (*check_off_file_meas_request)(imv_attestation_state_t *this,
										u_int16_t id, int *file_id, bool *is_dir);

	/**
	 * Create and add an entry to the list of Functional Components
	 *
	 * @param name				Component Functional Name
	 * @param depth				Sub-component Depth
	 * @param pts_db			PTS measurement database
	 * @return					created functional component instance or NULL
	 */
	pts_component_t* (*create_component)(imv_attestation_state_t *this,
										 pts_comp_func_name_t *name,
										 u_int32_t depth,
										 pts_database_t *pts_db);

	/**
	 * Get a Functional Component with a given name
	 *
	 * @param name			 	Name of the requested Functional Component
	 * @return					Functional Component if found, NULL otherwise
	 */
	pts_component_t* (*get_component)(imv_attestation_state_t *this,
									  pts_comp_func_name_t *name);

	/**
	 * Tell the Functional Components to finalize any measurement registrations
	 * and to check if all expected measurements were received
	 */
	void (*finalize_components)(imv_attestation_state_t *this);

	/**
	 * Have the Functional Component measurements been finalized?
	 */
	bool (*components_finalized)(imv_attestation_state_t *this);

	/**
	 * Indicates if a file measurement error occurred
	 *
	 * @return					TRUE in case of measurement error
	 */
	bool (*get_measurement_error)(imv_attestation_state_t *this);

	/**
	 * Call if a file measurement error is encountered
	 */
	void (*set_measurement_error)(imv_attestation_state_t *this);

};

/**
 * Create an imv_attestation_state_t instance
 *
 * @param id					connection ID
 */
imv_state_t* imv_attestation_state_create(TNC_ConnectionID id);

#endif /** IMV_ATTESTATION_STATE_H_ @}*/
