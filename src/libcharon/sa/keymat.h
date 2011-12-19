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

typedef struct keymat_t keymat_t;

#include <library.h>
#include <utils/identification.h>
#include <crypto/prfs/prf.h>
#include <crypto/aead.h>
#include <config/proposal.h>
#include <config/peer_cfg.h>
#include <sa/ike_sa_id.h>

/**
 * Derivation an management of sensitive keying material.
 */
struct keymat_t {

	/**
	 * Create a diffie hellman object for key agreement.
	 *
	 * The diffie hellman is either for IKE negotiation/rekeying or
	 * CHILD_SA rekeying (using PFS). The resulting DH object must be passed
	 * to derive_keys or to derive_child_keys and destroyed after use
	 *
	 * @param group			diffie hellman group
	 * @return				DH object, NULL if group not supported
	 */
	diffie_hellman_t* (*create_dh)(keymat_t *this,
								   diffie_hellman_group_t group);

	/*
	 * Get a AEAD transform to en-/decrypt and sign/verify IKE messages.
	 *
	 * @param in		TRUE for inbound (decrypt), FALSE for outbound (encrypt)
	 * @return			crypter
	 */
	aead_t* (*get_aead)(keymat_t *this, bool in);

	/**
	 * Destroy a keymat_t.
	 */
	void (*destroy)(keymat_t *this);
};

/**
 * Create the appropriate keymat_t implementation based on the IKE version.
 *
 * @param version			requested IKE version
 * @param initiator			TRUE if we are initiator
 * @return					keymat_t implmenetation
 */
keymat_t *keymat_create(ike_version_t version, bool initiator);

/**
 * Look up the key length of an encryption algorithm.
 *
 * @param alg				algorithm to get key length for
 * @return					key length in bits
 */
int keymat_get_keylen_encr(encryption_algorithm_t alg);

/**
 * Look up the key length of an integrity algorithm.
 *
 * @param alg				algorithm to get key length for
 * @return					key length in bits
 */
int keymat_get_keylen_integ(integrity_algorithm_t alg);

#endif /** KEYMAT_H_ @}*/
