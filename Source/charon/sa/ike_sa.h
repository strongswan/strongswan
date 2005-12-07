/**
 * @file ike_sa.h
 *
 * @brief Interface of ike_sa_id_t.
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
#include <encoding/payloads/proposal_substructure.h>
#include <sa/ike_sa_id.h>
#include <config/configuration_manager.h>
#include <utils/logger.h>
#include <utils/randomizer.h>
#include <sa/states/state.h>
#include <transforms/prfs/prf.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>

/**
 * Nonce size in bytes of all sent nonces
 * 
 * @ingroup sa
 */
#define NONCE_SIZE 16

typedef struct ike_sa_t ike_sa_t;

/**
 * @brief Class ike_sa_t. An object of this type is managed by an
 * ike_sa_manager_t object and represents an IKE_SA. Message processing
 * is split up in different states. They will handle all related things
 * for their state.
 * 
 * @b Constructors:
 * - ike_sa_create()
 * 
 * @ingroup sa
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
	 * @brief Initiate a new connection with given configuration name.
	 * 
	 * @param this 			calling object
	 * @param name 			name of the configuration
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- FAILED if in wrong state
	 * 						- DELETE_ME if initialization faild and SA should be deleted
	 */
	status_t (*initialize_connection) (ike_sa_t *this, char *name);
	
	/**
	 * @brief Retransmits a request.
	 * 
	 * @param this 			calling object
	 * @param message_id	ID of the request to retransmit
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND if request doesn't have to be retransmited
	 */
	status_t (*retransmit_request) (ike_sa_t *this, u_int32_t message_id);

	/**
	 * @brief Get the id of the SA.
	 *
	 * @param this 			ike_sa_t object object
	 * @return 				ike_sa's ike_sa_id_t
	 */
	ike_sa_id_t* (*get_id) (ike_sa_t *this);
	
	/**
	 * @brief Get the state of type of associated state object.
	 *
	 * @param this 			ike_sa_t object object
	 * @return 				state of IKE_SA
	 */
	ike_sa_state_t (*get_state) (ike_sa_t *this);

	/**
	 * @brief Destroys a ike_sa_t object.
	 *
	 * @param this 			ike_sa_t object
	 */
	void (*destroy) (ike_sa_t *this);
};


typedef struct protected_ike_sa_t protected_ike_sa_t;

/**
 * @brief Protected data of an ike_sa_t object.
 * 
 * This members should only be accessed from 
 * the varius state classes.
 * 
 * @ingroup sa
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
	 * @param this				calling object
	 * @param type				exchange type of new message
	 * @param request			TRUE, if message has to be a request
	 * @param message			new message is stored at this location
	 */
	void (*build_message) (protected_ike_sa_t *this, exchange_type_t type, bool request, message_t **message);

	/**
	 * Initiate a new connection with given configuration name
	 * 
	 * @param this 				calling object
	 * @param dh_shared_secret	shared secret of diffie hellman exchange
	 * @param initiator_nonce	nonce of initiator
	 * @param responder_nonce	nonce of responder
	 */
	void (*compute_secrets) (protected_ike_sa_t *this,chunk_t dh_shared_secret,chunk_t initiator_nonce, chunk_t responder_nonce);
	
	/**
	 * Gets the internal stored logger_t object for given ike_sa_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored logger_t object
	 */
	logger_t *(*get_logger) (protected_ike_sa_t *this);
	
	/**
	 * Gets the internal stored init_config_t object.
	 * 
	 * Returned value has to get checked for NULL value!
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored init_config_t object
	 */
	init_config_t *(*get_init_config) (protected_ike_sa_t *this);
	
	/**
	 * Sets the internal init_config_t object.
	 * 
	 * @param this 				calling object
	 * @param init_config		object of type init_config_t
	 */
	void (*set_init_config) (protected_ike_sa_t *this,init_config_t *init_config);
	
	/**
	 * Gets the internal stored sa_config_t object.
	 * 
	 * Returned value has to get checked for NULL value!
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored sa_config_t object
	 */
	sa_config_t *(*get_sa_config) (protected_ike_sa_t *this);
	
	/**
	 * Sets the internal sa_config_t object.
	 * 
	 * @param this 				calling object
	 * @param sa_config			object of type sa_config_t
	 */
	void (*set_sa_config) (protected_ike_sa_t *this,sa_config_t *sa_config);

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
	 * Creates all needed transform objects for given ike_sa_t using 
	 * the informations stored in a ike_proposal_t object
	 * 
	 * Allready existing objects get destroyed.
	 * 
	 * @param this 				calling object
	 * @param proposal			proposal used to get informations for transform
	 * 							objects (algorithms, key lengths, etc.)
	 */
	status_t (*create_transforms_from_proposal) (protected_ike_sa_t *this,ike_proposal_t * proposal);
	
	/**
	 * Sends the next request message.
	 * 
	 * Also the first retransmit job is created.
	 * 
	 * Stored requested message gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the message which should be sent
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*send_request) (protected_ike_sa_t *this,message_t * message);

	/**
	 * Sends the next response message.
	 * 
	 * Stored responded message gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the message which should be sent
	 * return					
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*send_response) (protected_ike_sa_t *this,message_t * message);
	
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
	
	/**
	 * Sets the last replied message id.
	 * 
	 * @param this 				calling object
	 * @param message_id		message id
	 */
	void (*set_last_replied_message_id) (protected_ike_sa_t *this,u_int32_t message_id);
	
	/**
	 * Gets the internal stored initiator crypter_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to crypter_t object
	 */
	crypter_t *(*get_crypter_initiator) (protected_ike_sa_t *this);
	
	/**
	 * Gets the internal stored initiator signer object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to signer_t object
	 */
	signer_t *(*get_signer_initiator) (protected_ike_sa_t *this);
	
	/**
	 * Gets the internal stored responder crypter_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to crypter_t object
	 */
	crypter_t *(*get_crypter_responder) (protected_ike_sa_t *this);
	
	/**
	 * Gets the internal stored responder signer object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to signer_t object
	 */
	signer_t *(*get_signer_responder) (protected_ike_sa_t *this);
	
	/**
	 * Gets the internal stored prf_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_prf) (protected_ike_sa_t *this);
	
	/**
	 * Gets the last responded message.
	 *  
	 * @param this 				calling object
	 * @return					
	 * 							- last received as message_t object 
	 * 							- NULL if no last request available
	 */
	message_t *(*get_last_responded_message) (protected_ike_sa_t *this);
	
	/**
	 * Gets the last requested message.
	 *  
	 * @param this 				calling object
	 * @return					
	 * 							- last sent as message_t object 
	 * 							- NULL if no last request available
	 */
	message_t *(*get_last_requested_message) (protected_ike_sa_t *this);

	/**
	 * Gets the Shared key SK_pr.
	 * 
	 * Returned value is not cloned!
	 * 
	 * @param this 				calling object
	 * @return					SK_pr key
	 */
	chunk_t (*get_key_pr) (protected_ike_sa_t *this);
	
	/**
	 * Gets the Shared key SK_pi.
	 * 
	 * Returned value is not cloned!
	 * 
	 * @param this 				calling object
	 * @return					SK_pr key
	 */
	chunk_t (*get_key_pi) (protected_ike_sa_t *this);

	/**
	 * Resets message id counters and does destroy stored received and sent messages.
	 * 
	 * @param this 				calling object
	 */	
	void (*reset_message_buffers) (protected_ike_sa_t *this);
	
	/**
	 * Creates a job of type DELETE_ESTABLISHED_IKE_SA for the current IKE_SA.
	 * 
	 * 
	 * @param this 				calling object
	 * @param timeout			timeout after the IKE_SA gets deleted
	 * 
	 */	
	void (*create_delete_established_ike_sa_job) (protected_ike_sa_t *this,u_int32_t timeout);
};



/**
 * Creates an ike_sa_t object with a specific ike_sa_id_t object
 *
 * @param[in] ike_sa_id 	ike_sa_id_t object to associate with new IKE_SA.
 *				 			The object is internal getting cloned
 *							and so has to be destroyed by the caller.
 *
 * @warning the Content of internal ike_sa_id_t object can change over time
 * 			e.g. when a IKE_SA_INIT has been finished.
 *
 * @return 					ike_sa_t object
 * 
 * @ingroup sa
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id);

#endif /*IKE_SA_H_*/
