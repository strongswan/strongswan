/*
 * Copyright (C) 2008-2009 Martin Willi
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
 * @defgroup sim_manager sim_manager
 * @{ @ingroup eap
 */

#ifndef SIM_MANAGER_H_
#define SIM_MANAGER_H_

#include <crypto/hashers/hasher.h>
#include <utils/identification.h>
#include <utils/enumerator.h>

typedef struct sim_manager_t sim_manager_t;
typedef struct sim_card_t sim_card_t;
typedef struct sim_provider_t sim_provider_t;

#define SIM_RAND_LEN	16
#define SIM_SRES_LEN	 4
#define SIM_KC_LEN		 8

#define AKA_RAND_LEN	16
#define AKA_RES_LEN		16
#define AKA_CK_LEN		16
#define AKA_IK_LEN		16
#define AKA_AUTN_LEN	16
#define AKA_AUTS_LEN	14

/**
 * Interface for a (U)SIM card (used as EAP client).
 *
 * The SIM card completes triplets/quintuplets requested in a challenge
 * received from the server.
 * An implementation supporting only one of SIM/AKA authentication may
 * implement the other methods with return_false()/return NOT_SUPPORTED/NULL.
 */
struct sim_card_t {

	/**
	 * Calculate SRES/KC from a RAND for SIM authentication.
	 *
	 * @param id		permanent identity to get a triplet for
	 * @param rand		RAND input buffer, fixed size 16 bytes
	 * @param sres		SRES output buffer, fixed size 4 byte
	 * @param kc		KC output buffer, fixed size 8 bytes
	 * @return			TRUE if SRES/KC calculated, FALSE on error/wrong identity
	 */
	bool (*get_triplet)(sim_card_t *this, identification_t *id,
						char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN],
						char kc[SIM_KC_LEN]);

	/**
	 * Calculate CK/IK/RES from RAND/AUTN for AKA authentication.
	 *
	 * If the received sequence number (in autn) is out of sync, INVALID_STATE
	 * is returned.
	 *
	 * @param id		permanent identity to request quintuplet for
	 * @param rand		random value rand
	 * @param autn		authentication token autn
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param res		buffer receiving authentication result res
	 * @return			SUCCESS, FAILED, or INVALID_STATE if out of sync
	 */
	status_t (*get_quintuplet)(sim_card_t *this, identification_t *id,
							   char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
							   char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
							   char res[AKA_RES_LEN]);

	/**
	 * Calculate AUTS from RAND for AKA resynchronization.
	 *
	 * @param id		permanent identity to request quintuplet for
	 * @param rand		random value rand
	 * @param auts		resynchronization parameter auts
	 * @return			TRUE if parameter generated successfully
	 */
	bool (*resync)(sim_card_t *this, identification_t *id,
				   char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);

	/**
	 * Set the pseudonym to use for next authentication.
	 *
	 * @param id		permanent identity of the peer
	 * @param pseudonym	pseudonym identity received from the server
	 */
	void (*set_pseudonym)(sim_card_t *this, identification_t *id,
						  identification_t *pseudonym);

	/**
	 * Get the pseudonym previously stored via set_pseudonym().
	 *
	 * @param id		permanent identity of the peer
	 * @return			associated pseudonym identity, NULL if none stored
	 */
	identification_t* (*get_pseudonym)(sim_card_t *this, identification_t *id);

	/**
	 * Store parameters to use for the next fast reauthentication.
	 *
	 * @param id		permanent identity of the peer
	 * @param next		next fast reauthentication identity to use
	 * @param mk		master key MK to store for reauthentication
	 * @param counter	counter value to store, host order
	 */
	void (*set_reauth)(sim_card_t *this, identification_t *id,
					   identification_t *next, char mk[HASH_SIZE_SHA1],
					   u_int16_t counter);

	/**
	 * Retrieve parameters for fast reauthentication stored via set_reauth().
	 *
	 * @param id		permanent identity of the peer
	 * @param mk		buffer receiving master key MK
	 * @param counter	pointer receiving counter value, in host order
	 */
	identification_t* (*get_reauth)(sim_card_t *this, identification_t *id,
									char mk[HASH_SIZE_SHA1], u_int16_t *counter);
};

/**
 * Interface for a triplet/quintuplet provider (used as EAP server).
 *
 * A SIM provider hands out triplets for SIM authentication and quintuplets
 * for AKA authentication. Multiple SIM provider instances can serve as
 * authentication backend to authenticate clients using SIM/AKA.
 * An implementation supporting only one of SIM/AKA authentication may
 * implement the other methods with return_false().
 */
struct sim_provider_t {

	/**
	 * Create a challenge for SIM authentication.
	 *
	 * @param id		permanent identity of peer to gen triplet for
	 * @param rand		RAND output buffer, fixed size 16 bytes
	 * @param sres		SRES output buffer, fixed size 4 byte
	 * @param kc		KC output buffer, fixed size 8 bytes
	 * @return			TRUE if triplet received, FALSE otherwise
	 */
	bool (*get_triplet)(sim_provider_t *this, identification_t *id,
						char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN],
						char kc[SIM_KC_LEN]);

	/**
	 * Create a challenge for AKA authentication.
	 *
	 * @param id		permanent identity of peer to create challenge for
	 * @param rand		buffer receiving random value rand
	 * @param xres		buffer receiving expected authentication result xres
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param autn		authentication token autn
	 * @return			TRUE if quintuplet generated successfully
	 */
	bool (*get_quintuplet)(sim_provider_t *this, identification_t *id,
						   char rand[AKA_RAND_LEN], char xres[AKA_RES_LEN],
						   char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
						   char autn[AKA_AUTN_LEN]);

	/**
	 * Process AKA resynchroniusation request of a peer.
	 *
	 * @param id		permanent identity of peer requesting resynchronisation
	 * @param rand		random value rand
	 * @param auts		synchronization parameter auts
	 * @return			TRUE if resynchronized successfully
	 */
	bool (*resync)(sim_provider_t *this, identification_t *id,
				   char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);

	/**
	 * Check if peer uses a pseudonym, get permanent identity.
	 *
	 * @param id		pseudonym identity candidate
	 * @return			permanent identity, NULL if id not a pseudonym
	 */
	identification_t* (*is_pseudonym)(sim_provider_t *this,
									  identification_t *id);

	/**
	 * Generate a pseudonym identitiy for a given peer identity.
	 *
	 * @param id		permanent identity to generate a pseudonym for
	 * @return			generated pseudonym, NULL to not use a pseudonym identity
	 */
	identification_t* (*gen_pseudonym)(sim_provider_t *this,
									   identification_t *id);

	/**
	 * Check if peer uses reauthentication, retrieve reauth parameters.
	 *
	 * @param id		reauthentication identity (candidate)
	 * @param mk		buffer receiving master key MK
	 * @param counter	pointer receiving current counter value, host order
	 * @return			permanent identity, NULL if id not a reauth identity
	 */
	identification_t* (*is_reauth)(sim_provider_t *this, identification_t *id,
								   char mk[HASH_SIZE_SHA1], u_int16_t *counter);

	/**
	 * Generate a fast reauthentication identity, associated to a master key.
	 *
	 * @param id		permanent peer identity
	 * @param mk		master key to store along with generated identity
	 * @return			fast reauthentication identity, NULL to not use reauth
	 */
	identification_t* (*gen_reauth)(sim_provider_t *this, identification_t *id,
									char mk[HASH_SIZE_SHA1]);
};

/**
 * The SIM manager handles multiple (U)SIM cards and providers.
 */
struct sim_manager_t {

	/**
	 * Register a SIM card (client) at the manager.
	 *
	 * @param card		sim card to register
	 */
	void (*add_card)(sim_manager_t *this, sim_card_t *card);

	/**
	 * Unregister a previously registered card from the manager.
	 *
	 * @param card		sim card to unregister
	 */
	void (*remove_card)(sim_manager_t *this, sim_card_t *card);

	/**
	 * Create an enumerator over all registered cards.
	 *
	 * @return			enumerator over sim_card_t's
	 */
	enumerator_t* (*create_card_enumerator)(sim_manager_t *this);

	/**
	 * Register a triplet provider (server) at the manager.
	 *
	 * @param card		sim card to register
	 */
	void (*add_provider)(sim_manager_t *this, sim_provider_t *provider);

	/**
	 * Unregister a previously registered provider from the manager.
	 *
	 * @param card		sim card to unregister
	 */
	void (*remove_provider)(sim_manager_t *this, sim_provider_t *provider);

	/**
	 * Create an enumerator over all registered provider.
	 *
	 * @return			enumerator over sim_provider_t's
	 */
	enumerator_t* (*create_provider_enumerator)(sim_manager_t *this);

	/**
	 * Destroy a manager instance.
	 */
	void (*destroy)(sim_manager_t *this);
};

/**
 * Create an SIM manager to handle multiple (U)SIM cards/providers.
 *
 * @return			sim_t object
 */
sim_manager_t *sim_manager_create();

#endif /** SIM_MANAGER_H_ @}*/
