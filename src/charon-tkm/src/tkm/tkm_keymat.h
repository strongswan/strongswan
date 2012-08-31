/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#ifndef TKM_KEYMAT_H_
#define TKM_KEYMAT_H_

#include <sa/keymat.h>

typedef struct tkm_keymat_t tkm_keymat_t;

/**
 * Derivation and management of sensitive keying material, TKM variant.
 */
struct tkm_keymat_t {

	/**
	 * Implements keymat_t.
	 */
	keymat_t keymat;

	/**
	 * Use TKM to derive IKE key material.
	 *
	 * @param proposal	selected algorithms
	 * @param dh		diffie hellman key allocated by create_dh()
	 * @param nonce_i	initiators nonce value
	 * @param nonce_r	responders nonce value
	 * @param id		IKE_SA identifier
	 * @param rekey_prf	PRF of old SA if rekeying, PRF_UNDEFINED otherwise
	 * @param rekey_skd	SKd of old SA if rekeying
	 * @return			TRUE on success
	 */
	bool (*derive_ike_keys)(tkm_keymat_t *this, proposal_t *proposal,
							diffie_hellman_t *dh, chunk_t nonce_i,
							chunk_t nonce_r, ike_sa_id_t *id,
							pseudo_random_function_t rekey_function,
							chunk_t rekey_skd);

	/**
	 * Use TKM to derive child key material.
	 *
	 * @param proposal	selected algorithms
	 * @param dh		diffie hellman key allocated by create_dh(), or NULL
	 * @param nonce_i	initiators nonce value
	 * @param nonce_r	responders nonce value
	 * @param encr_i	handle to initiators encryption key
	 * @param integ_i	handle to initiators integrity key
	 * @param encr_r	handle to responders encryption key
	 * @param integ_r	handle to responders integrity key
	 * @return			TRUE on success
	 */
	bool (*derive_child_keys)(tkm_keymat_t *this,
							  proposal_t *proposal, diffie_hellman_t *dh,
							  chunk_t nonce_i, chunk_t nonce_r,
							  chunk_t *encr_i, chunk_t *integ_i,
							  chunk_t *encr_r, chunk_t *integ_r);

	/**
	 * Use TKM to generate auth octets.
	 *
	 * @param verify		TRUE to create for verfification, FALSE to sign
	 * @param ike_sa_init	encoded ike_sa_init message
	 * @param nonce			nonce value
	 * @param id			identity
	 * @param reserved		reserved bytes of id_payload
	 * @param octests		chunk receiving allocated auth octets
	 * @return				TRUE if octets created successfully
	 */
	bool (*get_auth_octets)(tkm_keymat_t *this, bool verify, chunk_t ike_sa_init,
							chunk_t nonce, identification_t *id,
							char reserved[3], chunk_t *octets);

	/**
	 * Get SKd and PRF to derive keymat.
	 *
	 * @param skd	chunk to write SKd to (internal data)
	 * @return		PRF function to derive keymat
	 */
	pseudo_random_function_t (*get_skd)(tkm_keymat_t *this, chunk_t *skd);

	/**
	 * Build the shared secret signature used for PSK and EAP authentication.
	 *
	 * @param verify		TRUE to create for verfification, FALSE to sign
	 * @param ike_sa_init	encoded ike_sa_init message
	 * @param nonce			nonce value
	 * @param secret		optional secret to include into signature
	 * @param id			identity
	 * @param reserved		reserved bytes of id_payload
	 * @param sign			chunk receiving allocated signature octets
	 * @return				TRUE if signature created successfully
	 */
	bool (*get_psk_sig)(tkm_keymat_t *this, bool verify, chunk_t ike_sa_init,
						chunk_t nonce, chunk_t secret,
						identification_t *id, char reserved[3], chunk_t *sig);

	/**
	 * Get ISA context id.
	 *
	 * @return	id of associated ISA context.
	 */
	isa_id_type (*get_isa_id)(tkm_keymat_t * const this);

};

/**
 * Create TKM keymat instance.
 *
 * @param initiator			TRUE if we are the initiator
 * @return					keymat instance
 */
tkm_keymat_t *tkm_keymat_create(bool initiator);

#endif /** KEYMAT_TKM_H_ */
