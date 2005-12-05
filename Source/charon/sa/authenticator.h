/**
 * @file authenticator.h
 *
 * @brief Interface of authenticator_t.
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

#ifndef _AUTHENTICATOR_H_
#define _AUTHENTICATOR_H_

#include <types.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/id_payload.h>
#include <network/packet.h>
#include <sa/ike_sa.h>


typedef struct authenticator_t authenticator_t;

/**
 * @brief Class authenticator_t. Used to authenticate a peer.
 * 
 * Currently the following two AUTH methods are supported:
 *  - SHARED_KEY_MESSAGE_INTEGRITY_CODE
 *  - RSA_DIGITAL_SIGNATURE
 * 
 * This class retrieves needed data for specific AUTH methods (RSA keys, shared secrets, etc.)
 * over an internal stored protected_ike_sa_t object or directly from the configuration_manager_t over
 * the daemon_t object charon.
 * 
 * @ingroup sa
 */
struct authenticator_t {

	/**
	 * @brief Verify's given authentication data. 
	 * 
	 * To verify a received AUTH payload the following data must be provided:
	 * - the last received IKEv2 Message from the other peer in binary form
	 * - the nonce value sent to the other peer
	 * - the ID payload of the other peer
	 *
	 * @param this 					authenticator_t object
	 * @param last_received_packet	binary representation of the last received IKEv2-Message
	 * @param my_nonce				The sent nonce (without payload header)
	 * @param other_id_payload		The ID payload received from other peer
	 * @param initiator				Type of other peer. TRUE, if it is original initiator, FALSE otherwise
	 * 
	 * @return
	 * 								- SUCCESS if verification could be processed (does not mean the data could be verified)
	 * 								- FAILED if verification failed
	 * 								- NOT_SUPPORTED if AUTH method not supported
	 * 								- NOT_FOUND if the data for specific AUTH method could not be found (e.g. shared secret, rsa key)
	 * 								- TODO rsa errors!!
	 */
	status_t (*verify_auth_data) (authenticator_t *this,
									auth_payload_t *auth_payload, 
									chunk_t last_received_packet,
									chunk_t my_nonce,
									id_payload_t *other_id_payload, 
									bool initiator);

	/**
	 * @brief Computes authentication data and creates specific AUTH payload.
	 * 
	 * To create an AUTH payload, the following data must be provided:
	 * - the last sent IKEv2 Message in binary form
	 * - the nonce value received from the other peer
	 * - the ID payload of myself
	 * 
	 * @param this 					authenticator_t object
	 * @param[out] auth_payload		The object of typee auth_payload_t will be created at pointing location
	 * @param last_sent_packet		binary representation of the last sent IKEv2-Message
	 * @param other_nonce			The received nonce (without payload header)
	 * @param my_id_payload			The ID payload going to send to other peer
	 * @param initiator				Type of myself. TRUE, if I'm original initiator, FALSE otherwise

	 * @return
	 * 								- SUCCESS if authentication data could be computed
	 * 								- NOT_SUPPORTED if AUTH method not supported
	 * 								- NOT_FOUND if the data for AUTH method could not be found
	 * 								- TODO rsa errors!!
	 */
	status_t (*compute_auth_data) (authenticator_t *this,
									auth_payload_t **auth_payload,
									chunk_t last_sent_packet,
									chunk_t other_nonce,
									id_payload_t *my_id_payload,
									bool initiator);

	/**
	 * @brief Destroys a authenticator_t object.
	 *
	 * @param this 			authenticator_t object
	 */
	void (*destroy) (authenticator_t *this);
};

/**
 * @brief Creates an authenticator object.
 * 
 * @warning: The following functions of the assigned protected_ike_sa_t object 
 * must return a valid value:
 * - protected_ike_sa_t.get_sa_config
 * - protected_ike_sa_t.get_prf
 * - protected_ike_sa_t.get_logger
 * This preconditions are not given in IKE_SA states INITIATOR_INIT or RESPONDER_INIT!
 * 
 * @param ike_sa		object of type protected_ike_sa_t
 * 
 * @ingroup sa
 */
authenticator_t *authenticator_create(protected_ike_sa_t *ike_sa);

#endif //_AUTHENTICATOR_H_
