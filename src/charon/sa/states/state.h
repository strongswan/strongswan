/**
 * @file state.h
 * 
 * @brief Interface state_t.
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

#ifndef STATE_H_
#define STATE_H_

#include <definitions.h>
#include <types.h>
#include <encoding/message.h>

typedef enum ike_sa_state_t ike_sa_state_t;

/**
 * States in which a IKE_SA can be.
 * 
 * @todo Support of more states (CHILD_SA_REQUESTED, etc...)
 * 
 * @ingroup states
 */
enum ike_sa_state_t {

	/**
	 * @brief IKE_SA is in initial state as initiator and is going to initiate a new connection.
	 * 
	 * Next state following this state is IKE_SA_INIT_REQUESTED.
	 * 
	 * Implemented in class initiator_init_t.
	 */
	INITIATOR_INIT = 1,

	/**
	 * @brief IKE_SA is in initial state as responder and is going to respond to a initiated connection.
	 * 
	 * Next state following this state is IKE_SA_INIT_RESPONDED.
	 * 
	 * Implemented in class responder_init_t.
	 */
	RESPONDER_INIT = 2,

	/**
	 * @brief A IKE_SA_INIT request was sent. In this state a reply of type IKE_SA_INIT is expected.
	 * 
	 * Two states are possible as next states:
	 *  - IKE_AUTH_REQUESTED if IKE_SA_INIT reply could successfully processed and IKE_AUTH request could be sent.
	 *  - INITIATOR_INIT if selected DH group was not the one selected by other peer.
	 * 
	 * Implemented in class ike_sa_init_requested_t.
	 */
	IKE_SA_INIT_REQUESTED = 3,

	/**
	 * @brief A IKE_SA_INIT response was sent. In this state a request of type IKE_AUTH is expected.
	 * 
 	 * Next state following this state is IKE_SA_ESTABLISHED.
 	 * 
 	 * Implemented in class ike_sa_init_responded_t.
	 */
	IKE_SA_INIT_RESPONDED = 4,

	/**
	 * @brief An IKE_AUTH request was sent after a successful IKE_SA_INIT-exchange.
	 * 
 	 * Next state following this state is IKE_SA_ESTABLISHED.
 	 * 
 	 * Implemented in class ike_auth_requested_t.
	 */
	IKE_AUTH_REQUESTED = 5,

	/**
	 * @brief An IKE_AUTH exchange was successfuly handled either as initiator or responder.
	 * 
	 * In this state, all the informations for an IKE_SA and one CHILD_SA are known.
	 * 
 	 * Implemented in class ike_sa_established_t.
	 */
	IKE_SA_ESTABLISHED = 6
};


/**
 * String mappings for ike_sa_state_t.
 */
extern mapping_t ike_sa_state_m[];


typedef struct state_t state_t;

/**
 * @brief This interface represents an IKE_SA state.
 * 
 * A state_t object is responsible to handle incoming messages.
 * 
 * It's the responsibility of the state_t object to parse the body of the message and to process each 
 * payload.
 * 
 * Needed Configurations and transform objects can be retrieved over an internal stored protected_ike_sa_t object 
 * which is passed to a state_t object when creating it (see different constructors).
 * 
 * The following states are supported and implemented:
 * - INITIATOR_INIT: implemented in initiator_init_t
 * - RESPONDER_INIT: implemented in responder_init_t
 * - IKE_SA_INIT_REQUESTED: implemented in ike_sa_init_requested_t
 * - IKE_SA_INIT_RESPONDED: implemented in ike_sa_init_responded_t
 * - IKE_AUTH_REQUESTED: implemented in ike_auth_requested_t
 * - IKE_SA_ESTABLISHED: implemented in ike_sa_established_t
 * 
 * @b Constructors:
 *  - initiator_init_create()
 *  - responder_init_create()
 *  - ike_sa_init_requested_create()
 *  - ike_sa_init_responded_create()
 *  - ike_auth_requested_create()
 *  - ike_sa_established_create()
 * 
 * @ingroup states
 */
struct state_t {

	/**
	 * @brief Processes a incoming IKEv2-Message of type message_t.
	 *
	 * @param this 			calling object
 	 * @param[in] 			message message_t object to process
	 * @return 				
	 * 						- SUCCESSFUL
	 * 						- FAILED
	 * 						- DELETE_ME if belonging IKE_SA should be deleted
	 */
	status_t (*process_message) (state_t *this,message_t *message);

	/**
	 * @brief Get the current state representing by this state_t object.
	 *
	 * @param this 	calling object
	 * @return 		state 
	 */
	ike_sa_state_t (*get_state) (state_t *this);

	/**
	 * @brief Destroys a state_t object.
	 *
	 * @param this 	calling object
	 */
	void (*destroy) (state_t *this);
};

#endif /*STATE_H_*/
