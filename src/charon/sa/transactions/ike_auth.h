/**
 * @file ike_auth.h
 * 
 * @brief Interface of transaction ike_auth.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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


#ifndef IKE_AUTH_H_
#define IKE_AUTH_H_

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>


typedef struct ike_auth_t ike_auth_t;

/**
 * @brief A transaction for the second message exchange to authenticate an IKE_SA.
 *
 * The second transaction is encrypted and authenticates the peers. It also
 * sets up a first CHILD_SA.
 *
 * @b Constructors:
 *  - ike_auth_create()
 *  - transaction_create() with the appropriate message
 *
 * @ingroup transactions
 */
struct ike_auth_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
	
	/**
	 * @brief Set the config used for the ike_auth exchange.
	 *
	 * The connection definition is used to complete IKE_SA setup, the
	 * policy defines the CHILD_SA which is created along with the ike_auth
	 * exchange.
	 *
	 * @param this			calling object
	 * @param connection	connection definition
	 * @param policy		policy definition
	 */
	void (*set_config) (ike_auth_t* this, 
						connection_t *connection, policy_t *policy);

	/**
	 * @brief Set the reqid used for CHILD_SA setup.
	 *
	 * The first two message exchanges may set up an associated
	 * CHILD_SA. If we acquire, we must use the same reqid as the
	 * installed policy.
	 * 
	 * @param this			calling object
	 * @param reqid			reqid to use for the CHILD_SA
	 */
	void (*set_reqid) (ike_auth_t* this, u_int32_t reqid);
	
	/**
	 * @brief Set the nonces used in the previous ike_sa_init transaction.
	 * 
	 * The nonces are used to create the authentication data.
	 * 
	 * @param this		calling object
	 * @param nonce_i	initiator chosen nonce
	 * @param nonce_r	responder chosen nonce
	 */
	void (*set_nonces) (ike_auth_t* this, chunk_t nonce_i, chunk_t nonce_r);
	
	/**
	 * @brief Set the messages used in the previous ike_sa_init transaction.
	 * 
	 * The messages are used to create the authentication data.
	 * 
	 * @param this		calling object
	 * @param request	encoded request message as a chunk
	 * @param response	encoded response message as a chunk
	 */
	void (*set_init_messages) (ike_auth_t* this, chunk_t request, chunk_t response);
};

/**
 * @brief Create a new transaction which processes IKE_AUTH exchanges.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created ike_auth transaction
 *
 * @ingroup transactions
 */
ike_auth_t *ike_auth_create(ike_sa_t *ike_sa);

#endif /* IKE_AUTH_H_ */
