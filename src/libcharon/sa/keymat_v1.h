/*
 * Copyright (C) 2011 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup keymat_v1 keymat_v1
 * @{ @ingroup sa
 */

#ifndef KEYMAT_V1_H_
#define KEYMAT_V1_H_

#include <sa/keymat.h>

typedef struct keymat_v1_t keymat_v1_t;

/**
 * Derivation and management of sensitive keying material, IKEv1 variant.
 */
struct keymat_v1_t {

	/**
	 * Implements keymat_t.
	 */
	keymat_t keymat;

	/**
	 * Derive keys for the IKE_SA.
	 *
	 * These keys are not handed out, but are used by the associated signers,
	 * crypters and authentication functions.
	 *
	 * @param proposal		selected algorithms
	 * @param dh			diffie hellman key allocated by create_dh()
	 * @param dh_other		public DH value from other peer
	 * @param nonce_i		initiators nonce value
	 * @param nonce_r		responders nonce value
	 * @param id			IKE_SA identifier
	 * @param auth			authentication method
	 * @param shared_key	PSK in case of AUTH_CLASS_PSK, NULL otherwise
	 * @return				TRUE on success
	 */
	bool (*derive_ike_keys)(keymat_v1_t *this, proposal_t *proposal,
							diffie_hellman_t *dh, chunk_t dh_other,
							chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id,
							auth_class_t auth, shared_key_t *shared_key);

	/**
	 * Returns the IV for a message with the given message ID.
	 *
	 * @param mid			message ID
	 * @return				IV (needs to be freed)
	 */
	chunk_t (*get_iv)(keymat_v1_t *this, u_int32_t mid);

	/**
	 * Updates the IV for the next message with the given message ID.
	 *
	 * A call of confirm_iv() is required in order to actually make the IV
	 * available.  This is needed for the inbound case where we store the last
	 * block of the encrypted message but want to update the IV only after
	 * verification of the decrypted message.
	 *
	 * @param mid			message ID
	 * @param last_block	last block of encrypted message (gets cloned)
	 */
	void (*update_iv)(keymat_v1_t *this, u_int32_t mid, chunk_t last_block);

	/**
	 * Confirms the updated IV for the given message ID.
	 *
	 * To actually make the new IV available via get_iv this method has to
	 * be called after update_iv.
	 *
	 * @param mid			message ID
	 */
	void (*confirm_iv)(keymat_v1_t *this, u_int32_t mid);

};

/**
 * Create a keymat instance.
 *
 * @param initiator			TRUE if we are the initiator
 * @return					keymat instance
 */
keymat_v1_t *keymat_v1_create(bool initiator);

#endif /** KEYMAT_V1_H_ @}*/
