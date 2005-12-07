/**
 * @file ike_sa.h
 *
 * @brief Interface of ike_sa_t.
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
 * Nonce size in bytes for nonces sending to other peer.
 * 
 * @warning Nonce size MUST be between 16 and 256 bytes.
 * 
 * @ingroup sa
 */
#define NONCE_SIZE 16


typedef struct ike_sa_t ike_sa_t;

/**
 * @brief Class ike_sa_t representing an IKE_SA. 
 * 
 * An object of this type is managed by an ike_sa_manager_t object 
 * and represents an IKE_SA. Message processing is split up in different states. 
 * They will handle all related things for the state they represent.
 * 
 * @b Constructors:
 * - ike_sa_create()
 * 
 * @ingroup sa
 */
struct ike_sa_t {

	/**
	 * @brief Processes a incoming IKEv2-Message of type message_t.
	 *
	 * @param this ike_sa_t object object
 	 * @param[in] message message_t object to process
	 * @return 				
	 * 						- SUCCESS
	 * 						- FAILED
	 * 						- DELETE_ME if this IKE_SA MUST be deleted
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
	 * 						- DELETE_ME if initialization failed and IKE_SA MUST be deleted
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
	 * Returned ike_sa_id_t object is not getting cloned!
	 *
	 * @param this 			calling object
	 * @return 				ike_sa's ike_sa_id_t
	 */
	ike_sa_id_t* (*get_id) (ike_sa_t *this);
	
	/**
	 * @brief Get the state of type of associated state object.
	 *
	 * @param this 			calling object
	 * @return 				state of IKE_SA
	 */
	ike_sa_state_t (*get_state) (ike_sa_t *this);

	/**
	 * @brief Destroys a ike_sa_t object.
	 *
	 * @param this 			calling object
	 */
	void (*destroy) (ike_sa_t *this);
};


typedef struct protected_ike_sa_t protected_ike_sa_t;

/**
 * @brief Protected functions of an ike_sa_t object.
 * 
 * This members are only accessed out from 
 * the various state_t implementations.
 * 
 * @ingroup sa
 */
struct protected_ike_sa_t {

	/**
	 * Public interface of an ike_sa_t object.
	 */
	ike_sa_t public;
	
	/**
	 * @brief Build an empty IKEv2-Message and fills in default informations.
	 * 
	 * Depending on the type of message (request or response), the message id is 
	 * either message_id_out or message_id_in.
	 * 
	 * Used in state_t Implementation to build an empty IKEv2-Message.
	 * 
	 * @param this				calling object
	 * @param type				exchange type of new message
	 * @param request			TRUE, if message has to be a request
	 * @param message			new message is stored at this location
	 */
	void (*build_message) (protected_ike_sa_t *this, exchange_type_t type, bool request, message_t **message);

	/**
	 * @brief Compute the shared secrets needed for encryption, signing, etc.
	 * 
	 * Preconditions:
	 *  - Call of function protected_ike_sa_t.create_transforms_from_proposal
	 * 
	 * @param this 				calling object
	 * @param dh_shared_secret	shared secret of diffie hellman exchange
	 * @param initiator_nonce	nonce of initiator
	 * @param responder_nonce	nonce of responder
	 */
	void (*compute_secrets) (protected_ike_sa_t *this,
								chunk_t dh_shared_secret,
								chunk_t initiator_nonce,
								chunk_t responder_nonce);
	
	/**
	 * @brief Get the internal stored logger_t object for given ike_sa_t object.
	 * 
	 * @warning Returned logger_t object is original one and managed by this object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored logger_t object
	 */
	logger_t *(*get_logger) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the internal stored init_config_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored init_config_t object
	 */
	init_config_t *(*get_init_config) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the internal init_config_t object.
	 * 
	 * @param this 				calling object
	 * @param init_config		object of type init_config_t
	 */
	void (*set_init_config) (protected_ike_sa_t *this,init_config_t *init_config);
	
	/**
	 * @brief Get the internal stored sa_config_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored sa_config_t object
	 */
	sa_config_t *(*get_sa_config) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the internal sa_config_t object.
	 * 
	 * @param this 				calling object
	 * @param sa_config			object of type sa_config_t
	 */
	void (*set_sa_config) (protected_ike_sa_t *this,sa_config_t *sa_config);

	/**
	 * @brief Get the internal stored host_t object for my host.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored host_t object
	 */
	host_t *(*get_my_host) (protected_ike_sa_t *this);

	/**
	 * @brief Get the internal stored host_t object for other host.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored host_t object
	 */
	host_t *(*get_other_host) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the internal stored host_t object for my host.
	 * 
	 * Allready existing object gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param my_host			pointer to the new host_t object
	 */
	void (*set_my_host) (protected_ike_sa_t *this,host_t * my_host);

	/**
	 * @brief Set the internal stored host_t object for other host.
	 * 
	 * Allready existing object gets destroyed. object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param other_host			pointer to the new host_t object
	 */
	void (*set_other_host) (protected_ike_sa_t *this,host_t *other_host);
	
	/**
	 * @brief Create all needed transform objects for this IKE_SA using 
	 * the informations stored in a ike_proposal_t object.
	 * 
	 * Allready existing objects get destroyed.
	 * 
	 * @param this 				calling object
	 * @param proposal			proposal used to get informations for transform
	 * 							objects (algorithms, key lengths, etc.)
	 */
	status_t (*create_transforms_from_proposal) (protected_ike_sa_t *this,ike_proposal_t * proposal);
	
	/**
	 * @brief Send the next request message.
	 * 
	 * Also the first retransmit job is created.
	 * 
	 * Last stored requested message gets destroyed. Object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the message which should be sent
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*send_request) (protected_ike_sa_t *this,message_t * message);

	/**
	 * @brief Send the next response message.
	 * 
	 * Last stored responded message gets destroyed. Object gets not cloned!
	 * 
	 * @param this 				calling object
	 * @param message			pointer to the message which should be sent
	 * return					
	 * 							- SUCCESS
	 * 							- FAILED if message id is not next expected one
	 */
	status_t (*send_response) (protected_ike_sa_t *this,message_t * message);

	/**
	 * @brief Send a notify reply message.
	 * 
	 * @param this 				calling object
	 * @param exchange_type		type of exchange in which the notify should be wrapped
	 * @param type				type of the notify message to send
	 * @param data				notification data
	 */
	void (*send_notify) (protected_ike_sa_t *this, exchange_type_t exchange_type, notify_message_type_t type, chunk_t data);
	
	/**
	 * @brief Get the internal stored randomizer_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal randomizer_t object
	 */
	randomizer_t *(*get_randomizer) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the new state_t object of the IKE_SA object.
	 * 
	 * The old state_t object gets not destroyed. It's the callers duty to 
	 * make sure old state is destroyed (Normally the old state is the caller).
	 * 
	 * @param this 				calling object
	 * @param state				pointer to the new state_t object
	 */
	void (*set_new_state) (protected_ike_sa_t *this,state_t *state);
	
	/**
	 * @brief Set the last replied message id.
	 * 
	 * @param this 				calling object
	 * @param message_id		message id
	 */
	void (*set_last_replied_message_id) (protected_ike_sa_t *this,u_int32_t message_id);
	
	/**
	 * @brief Get the internal stored initiator crypter_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to crypter_t object
	 */
	crypter_t *(*get_crypter_initiator) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the internal stored initiator signer_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to signer_t object
	 */
	signer_t *(*get_signer_initiator) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the internal stored responder crypter_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to crypter_t object
	 */
	crypter_t *(*get_crypter_responder) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the internal stored responder signer object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to signer_t object
	 */
	signer_t *(*get_signer_responder) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the internal stored prf_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_prf) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the last responded message.
	 *  
	 * @param this 				calling object
	 * @return					
	 * 							- last received as message_t object 
	 * 							- NULL if no last request available
	 */
	message_t *(*get_last_responded_message) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the last requested message.
	 *  
	 * @param this 				calling object
	 * @return					
	 * 							- last sent as message_t object 
	 * 							- NULL if no last request available
	 */
	message_t *(*get_last_requested_message) (protected_ike_sa_t *this);

	/**
	 * @brief Get the Shared key SK_pr.
	 * 
	 * Returned value is not cloned!
	 * 
	 * @param this 				calling object
	 * @return					SK_pr key
	 */
	chunk_t (*get_key_pr) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the Shared key SK_pi.
	 * 
	 * Returned value is not cloned!
	 * 
	 * @param this 				calling object
	 * @return					SK_pi key
	 */
	chunk_t (*get_key_pi) (protected_ike_sa_t *this);

	/**
	 * @brief Resets message counters and does destroy stored received and sent messages.
	 * 
	 * @param this 				calling object
	 */	
	void (*reset_message_buffers) (protected_ike_sa_t *this);
	
	/**
	 * @brief Creates a job of type DELETE_ESTABLISHED_IKE_SA for the current IKE_SA.
	 * 
	 * @param this 				calling object
	 * @param timeout			timeout after the IKE_SA gets deleted
	 * 
	 */	
	void (*create_delete_established_ike_sa_job) (protected_ike_sa_t *this,u_int32_t timeout);
};


/**
 * @brief Creates an ike_sa_t object with a specific ID.
 * 
 * @warning the Content of internal ike_sa_id_t object can change over time
 * 			e.g. when a IKE_SA_INIT has been finished.
 *
 * @param[in] ike_sa_id 	ike_sa_id_t object to associate with new IKE_SA.
 *				 			The object is internal getting cloned
 *							and so has to be destroyed by the caller.
 * @return 					ike_sa_t object
 * 
 * @ingroup sa
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id);

#endif /*IKE_SA_H_*/
