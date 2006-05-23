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
#include <sa/child_sa.h>
#include <sa/states/state.h>
#include <config/configuration.h>
#include <utils/logger.h>
#include <utils/randomizer.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <config/connections/connection.h>
#include <config/policies/policy.h>
#include <utils/logger.h>

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
	 * 						- DESTROY_ME if this IKE_SA MUST be deleted
	 */
	status_t (*process_message) (ike_sa_t *this,message_t *message);

	/**
	 * @brief Initiate a new connection with given connection_t object.
	 * 
	 * The connection_t object is owned by the IKE_SA after the call, so
	 * do not modify or destroy it.
	 * 
	 * @param this 			calling object
	 * @param connection	connection to initiate
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- FAILED if in wrong state
	 * 						- DESTROY_ME if initialization failed and IKE_SA MUST be deleted
	 */
	status_t (*initiate_connection) (ike_sa_t *this, connection_t *connection);
	
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
	 * @brief Get local peer address of the IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				local host_t
	 */
	host_t* (*get_my_host) (ike_sa_t *this);

	/**
	 * @brief Get remote peer address of the IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				remote host_t
	 */
	host_t* (*get_other_host) (ike_sa_t *this);

	/**
	 * @brief Get own ID of the IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				local identification_t
	 */
	identification_t* (*get_my_id) (ike_sa_t *this);

	/**
	 * @brief Get remote ID the IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				remote identification_t
	 */
	identification_t* (*get_other_id) (ike_sa_t *this);

	/**
	 * @brief Get the connection of the IKE_SA.
	 * 
	 * The internal used connection specification 
	 * can be queried to get some data of an IKE_SA.
	 * The connection is still owned to the IKE_SA
	 * and must not be manipulated.
	 *
	 * @param this 			calling object
	 * @return 				connection_t
	 */
	connection_t* (*get_connection) (ike_sa_t *this);
	
	/**
	 * @brief Get the state of type of associated state object.
	 *
	 * @param this 			calling object
	 * @return 				state of IKE_SA
	 */
	ike_sa_state_t (*get_state) (ike_sa_t *this);
	
	/**
	 * @brief Log the status of a the ike sa to a logger.
	 *
	 * The status of the IKE SA and all child SAs is logged.
	 * Supplying NULL as logger uses the internal child_sa logger
	 * to do the logging. The log is only done if the supplied
	 * connection name is NULL or matches the connections name.
	 *
	 * @param this 		calling object
	 * @param logger	logger to use for logging
	 * @param name		name of the connection
	 */	
	void (*log_status) (ike_sa_t *this, logger_t *logger, char *name);
	
	/**
	 * @brief Initiates the deletion of an IKE_SA.
	 * 
	 * Sends a delete message to the remote peer and waits for
	 * its response. If the response comes in, or a timeout occur,
	 * the IKE SA gets deleted.
	 * 
	 * @param this 			calling object
	 * @return
	 * 						- SUCCESS if deletion is initialized
	 * 						- INVALID_STATE, if the IKE_SA is not in 
	 * 						  an established state and can not be
	 * 						  delete (but destroyed).
	 */
	status_t (*delete) (ike_sa_t *this);

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
	 * @brief Get the internal stored connection_t object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored connection_t object
	 */
	connection_t *(*get_connection) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the internal connection object.
	 * 
	 * @param this 				calling object
	 * @param connection		object of type connection_t
	 */
	void (*set_connection) (protected_ike_sa_t *this, connection_t *connection);
	
	/**
	 * @brief Get the internal stored policy object.
	 * 
	 * @param this 				calling object
	 * @return					pointer to the internal stored policy_t object
	 */
	policy_t *(*get_policy) (protected_ike_sa_t *this);
	
	/**
	 * @brief Set the internal policy_t object.
	 * 
	 * @param this 				calling object
	 * @param policy			object of type policy_t
	 */
	void (*set_policy) (protected_ike_sa_t *this,policy_t *policy);
	
	/**
	 * @brief Derive all keys and create the transforms for IKE communication.
	 * 
	 * Keys are derived using the diffie hellman secret, nonces and internal
	 * stored SPIs. 
	 * Already existing objects get destroyed.
	 * 
	 * @param this 				calling object
	 * @param proposal			proposal which contains algorithms to use
	 * @param dh				diffie hellman object with shared secret
	 * @param nonce_i			initiators nonce
	 * @param nonce_r			responders nonce
	 */
	status_t (*build_transforms) (protected_ike_sa_t *this, proposal_t* proposal,
								 diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r);
	
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
	 * @brief Get the multi purpose prf.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_prf) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the prf-object, which is used to derive keys for child SAs.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_child_prf) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the prf used for authentication of initiator.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_prf_auth_i) (protected_ike_sa_t *this);
	
	/**
	 * @brief Get the prf used for authentication of responder.
	 * 
	 * @param this 				calling object
	 * @return					pointer to prf_t object
	 */
	prf_t *(*get_prf_auth_r) (protected_ike_sa_t *this);
	
	/**
	 * @brief Associates a child SA to this IKE SA
	 * 
	 * @param this 				calling object
	 * @param child_sa			child_sa to add
	 */
	void (*add_child_sa) (protected_ike_sa_t *this, child_sa_t *child_sa);
	
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
	 * @brief Resets message counters and does destroy stored received and sent messages.
	 * 
	 * @param this 				calling object
	 */	
	void (*reset_message_buffers) (protected_ike_sa_t *this);
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
