/**
 * @file state.h
 * 
 * @brief Interface ike_sa_sate_t.
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

extern mapping_t ike_sa_state_m[];

typedef enum ike_sa_state_t ike_sa_state_t;

/**
 * States in which a IKE_SA can actually be
 * 
 * @ingroup states
 */
enum ike_sa_state_t {

	/**
	 * IKE_SA is is not in a state as initiator
	 */
	INITIATOR_INIT = 1,

	/**
	 * IKE_SA is is not in a state as responder
	 */
	RESPONDER_INIT = 2,

	/**
	 * A IKE_SA_INIT-message was sent: role initiator
	 */
	IKE_SA_INIT_REQUESTED = 3,

	/**
	 * A IKE_SA_INIT-message was replied: role responder
	 */
	IKE_SA_INIT_RESPONDED = 4,

	/**
	 * An IKE_AUTH-message was sent after a successful
	 * IKE_SA_INIT-exchange: role initiator
	 */
	IKE_AUTH_REQUESTED = 5,

	/**
	 * An IKE_AUTH-message was replied: role responder.
	 * In this state, all the informations for an IKE_SA
	 * and one CHILD_SA are known.
	 */
	IKE_SA_ESTABLISHED = 6
};

/**
 * string mappings for ike_sa_state_t
 */
extern mapping_t ike_sa_state_m[];

typedef struct state_t state_t;

/**
 * @brief This interface represents an IKE_SA state
 * 
 * @ingroup states
 */
struct state_t {

	/**
	 * @brief Processes a incoming IKEv2-Message of type message_t.
	 *
	 * @param this 			state_t object
 	 * @param[in] 			message message_t object to process
	 * @return 				
	 * 						- SUCCESSFUL if succeeded
	 * 						- FAILED otherwise
	 */
	status_t (*process_message) (state_t *this,message_t *message);

	/**
	 * @brief Get the current state.
	 *
	 * @param this 	state_t object
	 * @return 		state 
	 */
	ike_sa_state_t (*get_state) (state_t *this);

	/**
	 * @brief Destroys a state_t object.
	 *
	 * @param this 	state_t object to destroy
	 */
	void (*destroy) (state_t *this);
};

#endif /*STATE_H_*/
