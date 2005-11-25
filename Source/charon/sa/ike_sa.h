/**
 * @file ike_sa.h
 *
 * @brief Class ike_sa_t. An object of this type is managed by an
 * ike_sa_manager_t object and represents an IKE_SA
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef IKE_SA_H_
#define IKE_SA_H_

#include <types.h>
#include <encoding/message.h>
#include <sa/ike_sa_id.h>
#include <utils/logger.h>
#include <utils/randomizer.h>
#include <sa/states/state.h>
#include <transforms/prfs/prf.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>



/**
 * Nonce size in bytes of all sent nonces
 */
#define NONCE_SIZE 16

typedef struct ike_sa_t ike_sa_t;

/**
 * @brief This class is used to represent an IKE_SA
 *
 */
struct ike_sa_t {

	/**
	 * @brief Processes a incoming IKEv2-Message of type message_t
	 *
	 * @param this ike_sa_t object object
 	 * @param[in] message message_t object to process
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*process_message) (ike_sa_t *this,message_t *message);

	/**
	 * Initiate a new connection with given configuration name
	 * 
	 * @param this 			calling object
	 * @param name 			name of the configuration
	 * @return				TODO
	 */
	status_t (*initialize_connection) (ike_sa_t *this, char *name);

	/**
	 * @brief Get the id of the SA
	 *
	 * @param this ike_sa_t-message_t object object
	 * @return ike_sa's ike_sa_id_t
	 */
	ike_sa_id_t* (*get_id) (ike_sa_t *this);

	/**
	 * @brief Destroys a ike_sa_t object
	 *
	 * @param this ike_sa_t object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (ike_sa_t *this);
};

typedef struct protected_ike_sa_t protected_ike_sa_t;

/**
 * Protected data of an ike_sa_t object
 */
struct protected_ike_sa_t {

	/**
	 * Public part of a ike_sa_t object
	 */
	ike_sa_t public;
	
	/**
	 * Builds an empty IKEv2-Message and fills in default informations.
	 * 
	 * Depending on the type of message (request or response), the message id is 
	 * either message_id_out or message_id_in.
	 * 
	 * Used in every state.
	 * 
	 * @param this		calling object
	 * @param type		exchange type of new message
	 * @param request	TRUE, if message has to be a request
	 * @param message	new message is stored at this location
	 * @return			
	 * 					- SUCCESS
	 * 					- OUT_OF_RES
	 */
	status_t (*build_message) (protected_ike_sa_t *this, exchange_type_t type, bool request, message_t **message);

	/**
	 * Initiate a new connection with given configuration name
	 * 
	 * @param this 				calling object
	 * @param dh_shared_secret	shared secret of diffie hellman exchange
	 * @param initiator_nonce	nonce of initiator
	 * @param responder_nonce	nonce of responder
	 * @return					TODO
	 */
	status_t (*compute_secrets) (protected_ike_sa_t *this,chunk_t dh_shared_secret,chunk_t initiator_nonce, chunk_t responder_nonce);
	
	/**
	 * Gets the internal stored logger_t object for given ike_sa_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored logger_t object
	 */
	logger_t *(*get_logger) (protected_ike_sa_t *this);
	

	/**
	 * Gets the internal stored host_t object for my host.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored host_t object
	 */
	host_t *(*get_my_host) (protected_ike_sa_t *this);

	/**
	 * Gets the internal stored host_t object for other host.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored host_t object
	 */
	host_t *(*get_other_host) (protected_ike_sa_t *this);
	
	/**
	 * Sets the internal stored host_t object for my host.
	 * 
	 * Allready existing object gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param my_host			pointer to the new host_t object
	 */
	void (*set_my_host) (protected_ike_sa_t *this,host_t * my_host);

	/**
	 * Sets the internal stored host_t object for other host.
	 * 
	 * Allready existing object gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param other_host			pointer to the new host_t object
	 */
	void (*set_other_host) (protected_ike_sa_t *this,host_t *other_host);
	
	/**
	 * Sets the internal stored prf_t object.
	 * 
	 * Allready existing object gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param prf				pointer to the new prf_t object
	 */
	void (*set_prf) (protected_ike_sa_t *this,prf_t *prf);
	
	/**
	 * Sets the last requested message.
	 * 
	 * Allready set last requested message gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the new last requested message
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*set_last_requested_message) (protected_ike_sa_t *this,message_t * message);

	/**
	 * Sets the last responded message.
	 * 
	 * Allready set last requested message gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the new last responded message
	 * return					
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*set_last_responded_message) (protected_ike_sa_t *this,message_t * message);
	
	/**
	 * Gets the internal stored randomizer_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal randomizer_t object
	 */
	randomizer_t *(*get_randomizer) (protected_ike_sa_t *this);
	
	/**
	 * Sets the new state_t object of the IKE_SA object.
	 * 
	 * The old state_t object gets not destroyed. It's the callers duty to 
	 * make sure old state is destroyed (Normally the old state is the caller ).
	 * 
	 * @param this 				calling object
	 * @param state				pointer to the new state_t object
	 */
	void (*set_new_state) (protected_ike_sa_t *this,state_t *state);
};



/**
 * Creates an ike_sa_t object with a specific ike_sa_id_t object
 *
 * @param[in] ike_sa_id ike_sa_id_t object to associate with new IKE_SA.
 *  			 			The object is internal getting cloned
 * 			  			and so has to be destroyed by the caller.
 *
 * @warning the Content of internal ike_sa_id_t object can change over time
 * 			e.g. when a IKE_SA_INIT has been finished
 *
 * @return created ike_sa_t object
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id);

#endif /*IKE_SA_H_*/
