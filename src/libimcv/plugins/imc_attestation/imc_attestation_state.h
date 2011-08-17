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
#include <library.h>

typedef struct imc_attestation_state_t imc_attestation_state_t;
typedef enum imc_attestation_handshake_state_t imc_attestation_handshake_state_t;

/**
 * IMC Attestation Handshake States (state machine)
 */
enum imc_attestation_handshake_state_t {
	IMC_ATTESTATION_STATE_INIT,
	IMC_ATTESTATION_STATE_REQ_PROTO_CAP,
	IMC_ATTESTATION_STATE_REQ_MEAS_ALGO,
	IMC_ATTESTATION_STATE_GET_TPM_INFO,
	IMC_ATTESTATION_STATE_GET_AIK,
	IMC_ATTESTATION_STATE_REQ_FUNCT_COMP_EVID,
	IMC_ATTESTATION_STATE_GEN_ATTEST_EVID,
	IMC_ATTESTATION_STATE_REQ_FILE_METADATA,
	IMC_ATTESTATION_STATE_REQ_FILE_MEAS,
	IMC_ATTESTATION_STATE_REQ_IML,
};

/**
 * Internal state of an imc_attestation_t connection instance
 */
struct imc_attestation_state_t {

	/**
	 * imc_state_t interface
	 */
	imc_state_t interface;
	
	/**
	 * get state of the handshake
	 *
	 * @return				the handshake state of IMC
	 */
	imc_attestation_handshake_state_t (*get_handshake_state)(imc_attestation_state_t *this);
	
	/**
	 * get state of the handshake
	 *
	 * @param new_state			the handshake state of IMC
	 */
	void (*set_handshake_state)(imc_attestation_state_t *this, imc_attestation_handshake_state_t new_state);
};

/**
 * Create an imc_attestation_state_t instance
 *
 * @param id		connection ID
 */
imc_state_t* imc_attestation_state_create(TNC_ConnectionID id);

#endif /** IMC_ATTESTATION_STATE_H_ @}*/
