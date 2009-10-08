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
 * @defgroup usim_manager usim_manager
 * @{ @ingroup eap
 */

#ifndef USIM_MANAGER_H_
#define USIM_MANAGER_H_

#include <utils/identification.h>
#include <utils/enumerator.h>

typedef struct usim_manager_t usim_manager_t;
typedef struct usim_card_t usim_card_t;
typedef struct usim_provider_t usim_provider_t;

#define AKA_RAND_LEN	16
#define AKA_RES_LEN		16
#define AKA_CK_LEN		16
#define AKA_IK_LEN		16
#define AKA_AUTN_LEN	16
#define AKA_AUTS_LEN	14

/**
 * Interface for a USIM card (used by EAP-AKA client).
 */
struct usim_provider_t {

	/**
	 * Create a challenge for AKA authentication.
	 *
	 * @param imsi		peer identity to create challenge for
	 * @param rand		buffer receiving random value rand
	 * @param xres		buffer receiving expected authentication result xres
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param autn		authentication token autn
	 * @return			TRUE if quintuplet generated successfully
	 */
	bool (*get_quintuplet)(usim_provider_t *this, identification_t *imsi,
						   char rand[AKA_RAND_LEN], char xres[AKA_RES_LEN],
						   char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
						   char autn[AKA_AUTN_LEN]);

	/**
	 * Process resynchroniusation request of a peer.
	 *
	 * @param imsi		peer identity requesting resynchronisation
	 * @param rand		random value rand
	 * @param auts		synchronization parameter auts
	 * @return			TRUE if resynchronized successfully
	 */
	bool (*resync)(usim_provider_t *this, identification_t *imsi,
				   char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);
};

/**
 * Interface for a quintuplet provider (used by EAP-AKA server).
 */
struct usim_card_t {

	/**
	 * Process authentication data and complete the quintuplet.
	 *
	 * If the received sequence number (in autn) is out of synf, INVALID_STATE
	 * is returned.
	 *
	 * @param imsi		peer identity requesting quintuplet for
	 * @param rand		random value rand
	 * @param autn		authentication token autn
	 * @param ck		buffer receiving encryption key ck
	 * @param ik		buffer receiving integrity key ik
	 * @param res		buffer receiving authentication result res
	 * @return			SUCCESS, FAILED, or INVALID_STATE if out of sync
	 */
	status_t (*get_quintuplet)(usim_card_t *this, identification_t *imsi,
							   char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
							   char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
							   char res[AKA_RES_LEN]);

	/**
	 * Request parameter to start resynchronization.
	 *
	 * @param imsi		peer identity requesting quintuplet for
	 * @param in		random value rand
	 * @param auts		resynchronization parameter auts
	 * @return			TRUE if parameter generated successfully
	 */
	bool (*resync)(usim_card_t *this, identification_t *imsi,
				   char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]);
};

/**
 * The EAP-AKA USIM manager handles multiple USIM cards and providers.
 */
struct usim_manager_t {

	/**
	 * Register a USIM card (client) at the manager.
	 *
	 * @param card		usim card to register
	 */
	void (*add_card)(usim_manager_t *this, usim_card_t *card);

	/**
	 * Unregister a previously registered card from the manager.
	 *
	 * @param card		usim card to unregister
	 */
	void (*remove_card)(usim_manager_t *this, usim_card_t *card);

	/**
	 * Create an enumerator over all registered cards.
	 *
	 * @return			enumerator over usim_card_t's
	 */
	enumerator_t* (*create_card_enumerator)(usim_manager_t *this);

	/**
	 * Register a triplet provider (server) at the manager.
	 *
	 * @param card		usim card to register
	 */
	void (*add_provider)(usim_manager_t *this, usim_provider_t *provider);

	/**
	 * Unregister a previously registered provider from the manager.
	 *
	 * @param card		usim card to unregister
	 */
	void (*remove_provider)(usim_manager_t *this, usim_provider_t *provider);

	/**
	 * Create an enumerator over all registered provider.
	 *
	 * @return			enumerator over Usim_provider_t's
	 */
	enumerator_t* (*create_provider_enumerator)(usim_manager_t *this);

	/**
	 * Destroy a manager instance.
	 */
	void (*destroy)(usim_manager_t *this);
};

/**
 * Create an USIM manager to handle multiple USIM cards/providers.
 *
 * @return			usim_t object
 */
usim_manager_t *usim_manager_create();

#endif /** USIM_MANAGER_H_ @}*/
