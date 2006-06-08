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
 * @see state_t for state diagram
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
	RESPONDER_INIT,

	/**
	 * @brief A IKE_SA_INIT request was sent. In this state a reply of type IKE_SA_INIT is expected.
	 * 
	 * Two states are possible as next states:
	 *  - IKE_AUTH_REQUESTED if IKE_SA_INIT reply could successfully processed and IKE_AUTH request could be sent.
	 *  - INITIATOR_INIT if selected DH group was not the one selected by other peer.
	 * 
	 * Implemented in class ike_sa_init_requested_t.
	 */
	IKE_SA_INIT_REQUESTED,

	/**
	 * @brief A IKE_SA_INIT response was sent. In this state a request of type IKE_AUTH is expected.
	 * 
 	 * Next state following this state is IKE_SA_ESTABLISHED.
 	 * 
 	 * Implemented in class ike_sa_init_responded_t.
	 */
	IKE_SA_INIT_RESPONDED,

	/**
	 * @brief An IKE_AUTH request was sent after a successful IKE_SA_INIT-exchange.
	 * 
 	 * Next state following this state is IKE_SA_ESTABLISHED.
 	 * 
 	 * Implemented in class ike_auth_requested_t.
	 */
	IKE_AUTH_REQUESTED,

	/**
	 * @brief An IKE_AUTH exchange was successfuly handled either as initiator or responder.
	 * 
	 * In this state, all the informations for an IKE_SA and one CHILD_SA are known.
	 * 
	 * Implemented in class ike_sa_established_t.
	 */
	IKE_SA_ESTABLISHED,

	/**
	 * @brief A rekeying/create CHILD_SA request was sent.
	 * 
	 * Implemented in class create_child_sa_requested.
	 */
	CREATE_CHILD_SA_REQUESTED,

	/**
	 * @brief A delete CHILD_SA request was sent.
	 * 
	 * Implemented in class delete_child_sa_requested.
	 */
	DELETE_CHILD_SA_REQUESTED,

	/**
	 * @brief An IKE SA has sent a DELETE IKE_SA to the other peer.
	 * 
	 * After a call to ike_sa.close(), the IKE_SA sends a delete message 
	 * to the remote peer and switches to this state. It waits until the
	 * message is aknowledged, or a certain timout occurs.
	 * 
	 * Implemented in class delete_requested.
	 */
	DELETE_IKE_SA_REQUESTED,
};


/**
 * String mappings for ike_sa_state_t.
 */
extern mapping_t ike_sa_state_m[];


typedef struct state_t state_t;

/**
 * @brief This interface represents an IKE_SA state.
 *
 * A state_t object is responsible to handle incoming messages. States
 * are exclusive, an IKE_SA is exactly in one state. They are used on IKE_SA
 * setup, as there is a strict scheme message exchange follow. This can be
 * mapped in a state machine. Every state is represented in a single class, 
 * and the IKE_SA may switch these states by replacing the owned state.
 @verbatim
           initiator                                  responder
           ---------                                  ---------

                ¦                                        ¦
                V                                        ¦
    +-----------------------+                            ¦
    ¦     initiator_init    ¦      msg1                  V
    +-----------------------+     ----->      +-----------------------+
                ¦                  msg2       ¦     responder_init    ¦
                V                 <-----      +-----------------------+
    +-----------------------+                            ¦
    ¦ ike_sa_init_requested ¦      msg3                  V
    +-----------------------+     ----->      +-----------------------+
                ¦                  msg4       ¦ ike_sa_init_requested ¦
                V                 <-----      +-----------------------+
    +-----------------------+                   ¦
    ¦  ike_auth_requested   ¦                   ¦
    +-----------------------+                   ¦
                          ¦                     ¦
                          V                     V
                       +---------------------------+
                       ¦    ike_sa_established     ¦
                       +---------------------------+
                                     ¦
                                     V
                       +---------------------------+
                       ¦     delete_requested      ¦
                       +---------------------------+

  msg1 = IKE_SA_INIT request
  msg2 = IKE_SA_INIT response
  msg3 = IKE_AUTH request
  msg4 = IKE_AUTH response
 @endverbatim
 * Every state can be left by deleting the IKE_SA, except the state
 * ike_sa_established: it must switch to the delete_requested state first,
 * as the peer must be informed about the delete.
 * 
 * For the handling of message in a established IKE_SA, another concept is used.
 * The state-concept is good if a single state is possible. But in a established
 * IKE_SA, there is no strict message order, and if a window size > 1 is used, 
 * multiple "states" would be possible. We call this transactions, better 
 * descripted in the transaction_t interface.
 *
 * @b Constructors:
 *  - initiator_init_create()
 *  - responder_init_create()
 *  - ike_sa_init_requested_create()
 *  - ike_sa_init_responded_create()
 *  - ike_auth_requested_create()
 *  - ike_sa_established_create()
 *  - delete_requested_create()
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
	 * 						- DESTROY_ME if belonging IKE_SA should be deleted
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

#endif /* STATE_H_ */
