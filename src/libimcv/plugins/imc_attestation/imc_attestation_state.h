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
 * @defgroup imc_attestation_state_t imc_attestation_state
 * @{ @ingroup imc_attestation_state
 */

#ifndef IMC_ATTESTATION_STATE_H_
#define IMC_ATTESTATION_STATE_H_

#include <imc/imc_state.h>
#include <pts/pts.h>
#include <pts/components/pts_comp_evidence.h>
#include <library.h>

typedef struct imc_attestation_state_t imc_attestation_state_t;

/**
 * Internal state of an imc_attestation_t connection instance
 */
struct imc_attestation_state_t {

	/**
	 * imc_state_t interface
	 */
	imc_state_t interface;

	/**
	 * Get the PTS object
	 *
	 * @return					PTS object
	 */
	pts_t* (*get_pts)(imc_attestation_state_t *this);

	/**
	 * Add an entry to the Component Evidence list
	 *
	 * @param entry				Component Evidence entry
	 */
	void (*add_evidence)(imc_attestation_state_t *this, pts_comp_evidence_t *entry);

	/**
	 * Get the number of entries in the Component Evidence list
	 *
	 * @return					number of Component Evidence entries
	 */
	int (*get_evid_count)(imc_attestation_state_t *this);

	/**
	 * Removes next Component Evidence entry from list and returns it
	 *
	 * @return					Next Component Evidence entry
	 */
	pts_comp_evidence_t* (*next_evidence)(imc_attestation_state_t *this);

};

/**
 * Create an imc_attestation_state_t instance
 *
 * @param id					connection ID
 */
imc_state_t* imc_attestation_state_create(TNC_ConnectionID id);

#endif /** IMC_ATTESTATION_STATE_H_ @}*/
