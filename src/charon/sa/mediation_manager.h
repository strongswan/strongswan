/**
 * @file mediation_manager.h
 * 
 * @brief Interface of mediation_manager_t.
 * 
 */

/*
 * Copyright (C) 2007 Tobias Brunner
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

#ifndef MEDIATION_MANAGER_H_
#define MEDIATION_MANAGER_H_

typedef struct mediation_manager_t mediation_manager_t;

#include <sa/ike_sa_id.h>
#include <utils/identification.h>

/**
 * @brief The mediation manager is responsible for managing currently online
 * peers and registered requests for offline peers on the mediation server.
 * 
 * @b Constructors:
 * - mediation_manager_create()
 * 
 * @ingroup sa
 */
struct mediation_manager_t {
	
	/**
	 * @brief Remove the IKE_SA of a peer.
	 * 
	 * @param this 				the manager object
	 * @param ike_sa_id			the IKE_SA ID of the peer's SA
	 */
	void (*remove) (mediation_manager_t* this, ike_sa_id_t *ike_sa_id);
	
	/**
	 * @brief Update the ike_sa_id that is assigned to a peer's ID. If the peer
	 * is new, it gets a new record assigned. 
	 * 
	 * @param this 				the manager object
	 * @param peer_id			the peer's ID
	 * @param ike_sa_id			the IKE_SA ID of the peer's SA
	 */
	void (*update_sa_id) (mediation_manager_t* this, identification_t *peer_id,
			ike_sa_id_t *ike_sa_id);
	
	/**
	 * @brief Checks if a specific peer is online.
	 * 
	 * @param this 				the manager object
	 * @param peer_id			the peer's ID
	 * @returns 					
	 * 							- IKE_SA ID of the peer's SA.
	 * 							- NULL, if the peer is not online.
	 */
	ike_sa_id_t* (*check) (mediation_manager_t* this,
			identification_t *peer_id);
	
	/**
	 * @brief Checks if a specific peer is online and registers the requesting
	 * peer if it is not.
	 * 
	 * @param this 				the manager object
	 * @param peer_id			the peer's ID
	 * @param requester			the requesters ID
	 * @returns 					
	 * 							- IKE_SA ID of the peer's SA.
	 * 							- NULL, if the peer is not online.
	 */
	ike_sa_id_t* (*check_and_register) (mediation_manager_t* this,
			identification_t *peer_id, identification_t *requester);
	
	/**
	 * @brief Destroys the manager with all data.
	 * 
	 * @param this				 the manager object
	 */
	void (*destroy) (mediation_manager_t *this);
};

/**
 * @brief Create a manager.
 * 
 * @returns 	mediation_manager_t object
 * 
 * @ingroup sa
 */
mediation_manager_t *mediation_manager_create(void);

#endif /*MEDIATION_MANAGER_H_*/
