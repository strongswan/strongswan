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
#include <ike_sa_id.h>
#include <utils/logger.h>
#include <utils/randomizer.h>
#include <states/state.h>
#include <transforms/prfs/prf.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>



/**
 * Nonce size in bytes of all sent nonces
 */
#define NONCE_SIZE 16

/**
 * @brief This class is used to represent an IKE_SA
 *
 */
typedef struct ike_sa_s ike_sa_t;

struct ike_sa_s {

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

/**
 * Protected data of an ike_sa_t object
 */
typedef struct protected_ike_sa_s protected_ike_sa_t;

struct protected_ike_sa_s {

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
	 * Creates a job to delete the given IKE_SA
	 */
	status_t (*create_delete_job) (protected_ike_sa_t *this);

	/**
	 * Resends the last sent reply
	 */
	status_t (*resend_last_reply) (protected_ike_sa_t *this);
	
	
	/* protected values */
	
	/**
	 * Identifier for the current IKE_SA
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Linked List containing the child sa's of the current IKE_SA
	 */
	linked_list_t *child_sas;

	/**
	 * Current state of the IKE_SA
	 */
	state_t *current_state;
	
	/**
	 * this SA's source for random data
	 */
	randomizer_t *randomizer;
	
	/**
	 * contains the last responded message
	 * 
	 */
	message_t *last_responded_message;

	/**
	 * contains the last requested message
	 * 
	 */
	message_t *last_requested_message;
	
	/**
	 * Informations of this host
	 */
	struct {
		host_t *host;
	} me;

	/**
	 * Informations of the other host
	 */	
	struct {
		host_t *host;
	} other;
	
	/**
	 * Crypter object for initiator
	 */
	crypter_t *crypter_initiator;
	
	/**
	 * Crypter object for responder
	 */
	crypter_t *crypter_responder;
	
	/**
	 * Signer object for initiator
	 */
	signer_t *signer_initiator;
	
	/**
	 * Signer object for responder
	 */
	signer_t *signer_responder;
	
	/**
	 * prf function
	 */
	prf_t *prf;
	
	
	
	/**
	 * Shared secrets
	 */
	struct {
		/**
		 * Key used for deriving other keys
		 */
		chunk_t d_key;
		
		/**
		 * Key for authenticate (initiator)
		 */
		chunk_t ai_key;
		
		/**
		 * Key for authenticate (responder)
		 */
		chunk_t ar_key;

		/**
		 * Key for encryption (initiator)
		 */
		chunk_t ei_key;	

		/**
		 * Key for encryption (responder)
		 */
		chunk_t er_key;	

		/**
		 * Key for generating auth payload (initiator)
		 */
		chunk_t pi_key;	

		/**
		 * Key for generating auth payload (responder)
		 */
		chunk_t pr_key;	

	} secrets;

	/**
	 * next message id to receive
	 */
	u_int32_t message_id_in;
	
	/**
	 * next message id to send
	 */
	u_int32_t message_id_out;
	
	/**
	 * a logger for this IKE_SA
	 */
	logger_t *logger;
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
