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
 *
 * $Id$
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
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <config/proposal.h>
#include <sa/ike_sa_id.h>

typedef struct keymat_t keymat_t;

/**
 * Derivation an management of sensitive keying material.
 */
struct keymat_t {

	/**
	 * Set the diffie hellman group to use.
	 *
	 * @param group		diffie hellman group to use
	 * @return			TRUE if group supported
	 */
	bool (*set_dh_group)(keymat_t *this, diffie_hellman_group_t group);
	
	/**
	 * Get the diffie hellman key agreement interface.
	 *
	 * Call set_dh_group() before acquiring this interface.
	 *
	 * @return			key agreement interface
	 */
	diffie_hellman_t* (*get_dh)(keymat_t *this);
	
	/**
	 * Derive keys from the shared secret.
	 *
	 * @param proposal	selected algorithms
	 * @param nonce_i	initiators nonce value
	 * @param nonce_r	responders nonce value
	 * @param id		IKE_SA identifier
	 * @param rekey		keymat of old SA if we are rekeying
	 * @return			TRUE on success
	 */
	bool (*derive_keys)(keymat_t *this, proposal_t *proposal, chunk_t nonce_i,
						chunk_t nonce_r, ike_sa_id_t *id, keymat_t *rekey);
	/**
	 * Get a signer to sign/verify IKE messages.
	 *
	 * @param in		TRUE for inbound (verify), FALSE for outbound (sign)
	 * @return			signer
	 */
	signer_t* (*get_signer)(keymat_t *this, bool in);
	
	/*
	 * Get a crypter to en-/decrypt IKE messages.
	 *
	 * @param in		TRUE for inbound (decrypt), FALSE for outbound (encrypt)
	 * @return			crypter
	 */
	crypter_t* (*get_crypter)(keymat_t *this, bool in);
	
	/**
	 * Get a keyed PRF to derive keymat for children.
	 *
	 * @return	 		PRF to derive CHILD_SA keymat from
	 */
	prf_t* (*get_child_prf)(keymat_t *this);
	
	/**
	 * Get the selected proposal passed to derive_keys().
	 *
	 * @return			selected proposal
	 */
	proposal_t* (*get_proposal)(keymat_t *this);
	
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
	 * @return				authentication octets
	 */
	chunk_t (*get_auth_octets)(keymat_t *this, bool verify, chunk_t ike_sa_init,
							   chunk_t nonce, identification_t *id);
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
	 * @return				signature octets
	 */
	chunk_t (*get_psk_sig)(keymat_t *this, bool verify, chunk_t ike_sa_init,
						   chunk_t nonce, chunk_t secret, identification_t *id);
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

#endif /* KEYMAT_ @}*/
