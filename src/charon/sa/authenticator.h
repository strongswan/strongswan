/**
 * @file authenticator.h
 *
 * @brief Interface of authenticator_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef AUTHENTICATOR_H_
#define AUTHENTICATOR_H_

#include <types.h>
#include <sa/ike_sa.h>
#include <network/packet.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/id_payload.h>


typedef struct authenticator_t authenticator_t;

/**
 * @brief Class used to authenticate a peer.
 * 
 * Currently the following two AUTH methods are supported:
 *  - SHARED_KEY_MESSAGE_INTEGRITY_CODE
 *  - RSA_DIGITAL_SIGNATURE
 * 
 * This class retrieves needed data for specific AUTH methods (RSA keys, shared secrets, etc.)
 * over an internal stored protected_ike_sa_t object or directly from the configuration_t over
 * the daemon_t object "charon".
 * 
 * @b Constructors:
 *  - authenticator_create()
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
	 * @param this 					calling object
	 * @param last_received_packet	binary representation of the last received IKEv2-Message
	 * @param my_nonce				the sent nonce (without payload header)
	 * @param my_id					my ID
	 * @param other_id				peer ID
	 * @param initiator				type of peer. TRUE, if it is original initiator, FALSE otherwise
	 * 
	 * @todo Document RSA error status types
	 * 
	 * @return
	 * 								- SUCCESS if verification successful
	 * 								- FAILED if verification failed
	 * 								- NOT_SUPPORTED if AUTH method not supported
	 * 								- NOT_FOUND if the data for specific AUTH method could not be found 
	 * 									(e.g. shared secret, rsa key)
	 */
	status_t (*verify_auth_data) (authenticator_t *this,
								  auth_payload_t *auth_payload, 
								  chunk_t last_received_packet,
								  chunk_t my_nonce,
								  identification_t *my_id,
								  identification_t *other_id,
								  bool initiator);

	/**
	 * @brief Computes authentication data and creates specific AUTH payload.
	 * 
	 * To create an AUTH payload, the following data must be provided:
	 * - the last sent IKEv2 Message in binary form
	 * - the nonce value received from the other peer
	 * - the ID payload of myself
	 * 
	 * @param this 					calling object
	 * @param[out] auth_payload		The object of typee auth_payload_t will be created at pointing location
	 * @param last_sent_packet		binary representation of the last sent IKEv2-Message
	 * @param other_nonce			the received nonce (without payload header)
	 * @param my_id					my ID
	 * @param other_id				peer ID
	 * @param initiator				type of myself. TRUE, if I'm original initiator, FALSE otherwise
	 *
	 * @todo Document RSA error status types
	 * 
	 * @return
	 * 								- SUCCESS if authentication data could be computed
	 * 								- NOT_SUPPORTED if AUTH method not supported
	 * 								- NOT_FOUND if the data for AUTH method could not be found
	 */
	status_t (*compute_auth_data) (authenticator_t *this,
								   auth_payload_t **auth_payload,
								   chunk_t last_sent_packet,
								   chunk_t other_nonce,
								   identification_t *my_id,
								   identification_t *other_id,
								   bool initiator);

	/**
	 * @brief Destroys a authenticator_t object.
	 *
	 * @param this 			calling object
	 */
	void (*destroy) (authenticator_t *this);
};

/**
 * @brief Creates an authenticator object.
 * 
 * @param ike_sa		associated ike_sa
 * @param auth_method	authentication method to use for own signature/mac
 * 
 * @return				authenticator_t object
 * 
 * @ingroup sa
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, auth_method_t auth_method);

#endif /* AUTHENTICATOR_H_ */
