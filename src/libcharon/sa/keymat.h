/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup keymat keymat
 * @{ @ingroup sa
 */

#ifndef KEYMAT_H_
#define KEYMAT_H_

#include <library.h>
#include <utils/identification.h>
#include <crypto/prfs/prf.h>
#include <crypto/aead.h>
#include <config/proposal.h>
#include <sa/ike_sa_id.h>

typedef struct keymat_t keymat_t;

/**
 * Derivation an management of sensitive keying material.
 */
struct keymat_t {

	/**
	 * Create a diffie hellman object for key agreement.
	 *
	 * The diffie hellman is either for IKE negotiation/rekeying or
	 * CHILD_SA rekeying (using PFS). The resulting DH object must be passed
	 * to derive_keys or to derive_child_keys and destroyed after use.
	 *
	 * Only DH objects allocated through this method are passed to other
	 * keymat_t methods, allowing private DH implementations. In some cases
	 * (such as retrying with a COOKIE), a DH object allocated from a different
	 * keymat_t instance may be passed to other methods.
	 *
	 * @param group			diffie hellman group
	 * @return				DH object, NULL if group not supported
	 */
	diffie_hellman_t* (*create_dh)(keymat_t *this, diffie_hellman_group_t group);

	/**
	 * Derive keys for the IKE_SA.
	 *
	 * These keys are not handed out, but are used by the associated signers,
	 * crypters and authentication functions.
	 *
	 * @param proposal	selected algorithms
	 * @param dh		diffie hellman key allocated by create_dh()
	 * @param nonce_i	initiators nonce value
	 * @param nonce_r	responders nonce value
	 * @param id		IKE_SA identifier
	 * @param rekey_prf	PRF of old SA if rekeying, PRF_UNDEFINED otherwise
	 * @param rekey_sdk	SKd of old SA if rekeying
	 * @return			TRUE on success
	 */
	bool (*derive_ike_keys)(keymat_t *this, proposal_t *proposal,
							diffie_hellman_t *dh, chunk_t nonce_i,
							chunk_t nonce_r, ike_sa_id_t *id,
							pseudo_random_function_t rekey_function,
							chunk_t rekey_skd);
	/**
	 * Derive keys for a CHILD_SA.
	 *
	 * The keys for the CHILD_SA are allocated in the integ and encr chunks.
	 * An implementation might hand out encrypted keys only, which are
	 * decrypted in the kernel before use.
	 * If no PFS is used for the CHILD_SA, dh can be NULL.
	 *
	 * @param proposal	selected algorithms
	 * @param dh		diffie hellman key allocated by create_dh(), or NULL
	 * @param nonce_i	initiators nonce value
	 * @param nonce_r	responders nonce value
	 * @param encr_i	chunk to write initiators encryption key to
	 * @param integ_i	chunk to write initiators integrity key to
	 * @param encr_r	chunk to write responders encryption key to
	 * @param integ_r	chunk to write responders integrity key to
	 * @return			TRUE on success
	 */
	bool (*derive_child_keys)(keymat_t *this,
							  proposal_t *proposal, diffie_hellman_t *dh,
							  chunk_t nonce_i, chunk_t nonce_r,
							  chunk_t *encr_i, chunk_t *integ_i,
							  chunk_t *encr_r, chunk_t *integ_r);
	/**
	 * Get SKd to pass to derive_ikey_keys() during rekeying.
	 *
	 * @param skd		chunk to write SKd to (internal data)
	 * @return			PRF function to derive keymat
	 */
	pseudo_random_function_t (*get_skd)(keymat_t *this, chunk_t *skd);

	/*
	 * Get a AEAD transform to en-/decrypt and sign/verify IKE messages.
	 *
	 * @param in		TRUE for inbound (decrypt), FALSE for outbound (encrypt)
	 * @return			crypter
	 */
	aead_t* (*get_aead)(keymat_t *this, bool in);

	/**
	 * Generate octets to use for authentication procedure (RFC4306 2.15).
	 *
	 * This method creates the plain octets and is usually signed by a private
	 * key. PSK and EAP authentication include a secret into the data, use
	 * the get_psk_sig() method instead.
	 *
	 * @param verify		TRUE to create for verfification, FALSE to sign
	 * @param ike_sa_init	encoded ike_sa_init message
	 * @param nonce			nonce value
	 * @param id			identity
	 * @param reserved		reserved bytes of id_payload
	 * @return				authentication octets
	 */
	chunk_t (*get_auth_octets)(keymat_t *this, bool verify, chunk_t ike_sa_init,
							   chunk_t nonce, identification_t *id,
							   char reserved[3]);
	/**
	 * Build the shared secret signature used for PSK and EAP authentication.
	 *
	 * This method wraps the get_auth_octets() method and additionally
	 * includes the secret into the signature. If no secret is given, SK_p is
	 * used as secret (used for EAP methods without MSK).
	 *
	 * @param verify		TRUE to create for verfification, FALSE to sign
	 * @param ike_sa_init	encoded ike_sa_init message
	 * @param nonce			nonce value
	 * @param secret		optional secret to include into signature
	 * @param id			identity
	 * @param reserved		reserved bytes of id_payload
	 * @return				signature octets
	 */
	chunk_t (*get_psk_sig)(keymat_t *this, bool verify, chunk_t ike_sa_init,
						   chunk_t nonce, chunk_t secret,
						   identification_t *id, char reserved[3]);
	/**
	 * Destroy a keymat_t.
	 */
	void (*destroy)(keymat_t *this);
};

/**
 * Create a keymat instance.
 *
 * @param initiator		TRUE if we are the initiator
 * @return				keymat instance
 */
keymat_t *keymat_create(bool initiator);

#endif /** KEYMAT_H_ @}*/
