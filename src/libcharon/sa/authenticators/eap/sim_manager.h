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
#include <sa/authenticators/eap/eap_method.h>

typedef struct sim_manager_t sim_manager_t;

/** implemented in libsimaka, but we need it for the message hook */
typedef struct simaka_message_t simaka_message_t;

#define SIM_RAND_LEN	16
#define SIM_SRES_LEN	 4
#define SIM_KC_LEN		 8

#define AKA_RAND_LEN	16
#define AKA_RES_MAX		16
#define AKA_CK_LEN		16
#define AKA_IK_LEN		16
#define AKA_AUTN_LEN	16
#define AKA_AUTS_LEN	14

#include <sa/authenticators/eap/sim_card.h>
#include <sa/authenticators/eap/sim_provider.h>
#include <sa/authenticators/eap/sim_hooks.h>

/**
 * The SIM manager handles multiple (U)SIM cards/providers and hooks.
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
	 * Calculate SIM triplets on one of the registered SIM cards.
	 *
	 * @param id		permanent identity to get a triplet for
	 * @param rand		RAND input buffer, fixed size 16 bytes
	 * @param sres		SRES output buffer, fixed size 4 byte
	 * @param kc		KC output buffer, fixed size 8 bytes
	 * @return			TRUE if calculated, FALSE if no matching card found
	 */
	bool (*card_get_triplet)(sim_manager_t *this, identification_t *id,
							 char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN],
							 char kc[SIM_KC_LEN]);

	/**
	 * Calculate AKA quitpulets on one of the registered SIM cards.
	 *
	 * @param id		permanent identity to request quintuplet for
	 * @param rand		random value rand
	 * @param autn		authentication token autn
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param res		buffer receiving authentication result res
	 * @param res_len	nubmer of bytes written to res buffer
	 * @return			SUCCESS, FAILED, or INVALID_STATE if out of sync
	 */
	status_t (*card_get_quintuplet)(sim_manager_t *this, identification_t *id,
								char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
								char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
								char res[AKA_RES_MAX], int *res_len);

	/**
	 * Calculate resynchronization data on one of the registered SIM cards.
	 *
	 * @param id		permanent identity to request quintuplet for
	 * @param rand		random value rand
	 * @param auts		resynchronization parameter auts
	 * @return			TRUE if calculated, FALSE if no matcing card found
	 */
	bool (*card_resync)(sim_manager_t *this, identification_t *id,
						char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);

	/**
	 * Store a received pseudonym on one of the registered SIM cards.
	 *
	 * @param id		permanent identity of the peer
	 * @param pseudonym	pseudonym identity received from the server
	 */
	void (*card_set_pseudonym)(sim_manager_t *this, identification_t *id,
							   identification_t *pseudonym);

	/**
	 * Get a stored pseudonym from one of the registerd SIM cards.
	 *
	 * @param id		permanent identity of the peer
	 * @return			associated pseudonym identity, NULL if none found
	 */
	identification_t* (*card_get_pseudonym)(sim_manager_t *this,
											identification_t *id);

	/**
	 * Store fast reauthentication parameters on one of the registered cards.
	 *
	 * @param id		permanent identity of the peer
	 * @param next		next fast reauthentication identity to use
	 * @param mk		master key MK to store for reauthentication
	 * @param counter	counter value to store, host order
	 */
	void (*card_set_reauth)(sim_manager_t *this, identification_t *id,
							identification_t *next, char mk[HASH_SIZE_SHA1],
							u_int16_t counter);

	/**
	 * Retrieve fast reauthentication parameters from one of the registerd cards.
	 *
	 * @param id		permanent identity of the peer
	 * @param mk		buffer receiving master key MK
	 * @param counter	pointer receiving counter value, in host order
	 * @return			fast reauthentication identity, NULL if none found
	 */
	identification_t* (*card_get_reauth)(sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter);

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
	 * Get a SIM triplet from one of the registered providers.
	 *
	 * @param id		permanent identity of peer to gen triplet for
	 * @param rand		RAND output buffer, fixed size 16 bytes
	 * @param sres		SRES output buffer, fixed size 4 byte
	 * @param kc		KC output buffer, fixed size 8 bytes
	 * @return			TRUE if triplet received, FALSE if no match found
	 */
	bool (*provider_get_triplet)(sim_manager_t *this, identification_t *id,
							char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN],
							char kc[SIM_KC_LEN]);

	/**
	 * Get a AKA quintuplet from one of the registered providers.
	 *
	 * @param id		permanent identity of peer to create challenge for
	 * @param rand		buffer receiving random value rand
	 * @param xres		buffer receiving expected authentication result xres
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param autn		authentication token autn
	 * @return			TRUE if quintuplet received, FALSE if no match found
	 */
	bool (*provider_get_quintuplet)(sim_manager_t *this, identification_t *id,
							char rand[AKA_RAND_LEN],
							char xres[AKA_RES_MAX], int *xres_len,
							char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
							char autn[AKA_AUTN_LEN]);

	/**
	 * Pass AKA resynchronization data to one of the registered providers.
	 *
	 * @param id		permanent identity of peer requesting resynchronisation
	 * @param rand		random value rand
	 * @param auts		synchronization parameter auts
	 * @return			TRUE if resynchronized, FALSE if not handled
	 */
	bool (*provider_resync)(sim_manager_t *this, identification_t *id,
							char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);

	/**
	 * Check if a peer uses a pseudonym using one of the registered providers.
	 *
	 * @param id		pseudonym identity candidate
	 * @return			permanent identity, NULL if id not a pseudonym
	 */
	identification_t* (*provider_is_pseudonym)(sim_manager_t *this,
											   identification_t *id);

	/**
	 * Generate a new pseudonym using one of the registered providers.
	 *
	 * @param id		permanent identity to generate a pseudonym for
	 * @return			generated pseudonym, NULL to not use a pseudonym identity
	 */
	identification_t* (*provider_gen_pseudonym)(sim_manager_t *this,
												identification_t *id);

	/**
	 * Check if a peer uses a reauth id using one of the registered providers.
	 *
	 * @param id		reauthentication identity (candidate)
	 * @param mk		buffer receiving master key MK
	 * @param counter	pointer receiving current counter value, host order
	 * @return			permanent identity, NULL if not a known reauth identity
	 */
	identification_t* (*provider_is_reauth)(sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter);

	/**
	 * Generate a fast reauth id using one of the registered providers.
	 *
	 * @param id		permanent peer identity
	 * @param mk		master key to store along with generated identity
	 * @return			fast reauthentication identity, NULL to not use reauth
	 */
	identification_t* (*provider_gen_reauth)(sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1]);

	/**
	 * Register a set of hooks to the manager.
	 *
	 * @param hooks		hook interface implementation to register
	 */
	void (*add_hooks)(sim_manager_t *this, sim_hooks_t *hooks);

	/**
	 * Unregister a set of hooks from the manager.
	 *
	 * @param hooks		hook interface implementation to unregister
	 */
	void (*remove_hooks)(sim_manager_t *this, sim_hooks_t *hooks);

	/**
	 * Invoke SIM/AKA message hook.
	 *
	 * @param message	SIM message
	 * @param inbound	TRUE for incoming messages, FALSE for outgoing
	 * @param decrypted	TRUE if AT_ENCR_DATA has been decrypted
	 */
	void (*message_hook)(sim_manager_t *this, simaka_message_t *message,
						 bool inbound, bool decrypted);

	/**
	 * Invoke SIM/AKA key hook.
	 *
	 * @param k_encr	SIM/AKA encryption key k_encr
	 * @param k_auth	SIM/AKA authentication key k_auth
	 */
	void (*key_hook)(sim_manager_t *this, chunk_t k_encr, chunk_t k_auth);

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
