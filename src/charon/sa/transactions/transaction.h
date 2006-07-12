/**
 * @file transaction.h
 * 
 * @brief Interface transaction_t.
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

#ifndef TRANSACTION_H_
#define TRANSACTION_H_


typedef struct transaction_t transaction_t;

#include <types.h>
#include <encoding/message.h>
#include <sa/ike_sa.h>



/**
 * @brief This interface represents a transaction an established IKE_SA can do.
 *
 * To every transaction, a message ID is associated. IKEv2 uses strict message
 * IDs, which are equal for a request/response pair in a transaction.
 * An initiator of a transaction does the following:
 * - create the transaction using a specific constructor
 * - call request() to get the message for initiaton
 * - call conclude() to process received reply
 * The other peer does the following:
 * - create a transanction using the generic transaction constructor
 * - call respond() to get a reply to send
 *
 * The responder must not destroy the transaction, until the 
 * initiator initiates another transaction (or a number of transactions
 * > window size). This allows us to redo a transaction in case of a
 * message loss. The initiator can destroy the the transaction once
 * the conclude() function is called.
 * 
 * @b Constructors:
 *  - transaction_create()
 *  - ike_sa_init_create()
 *  - ike_auth_create()
 * 
 * @ingroup transactions
 */
struct transaction_t {

	/**
	 * @brief Get the request to use for initiating the transaction.
	 * 
	 * A transaction creates a request only once. The request is stored
	 * internally and may be queried multiple times for retransmission.
	 * The transaction is not responsible for generating/encrypting the
	 * message, this is the job of the caller. But it MAY be already
	 * generated when calling get_request() the second time.
	 *
	 * @param this 			calling object
	 * @param[out] request	resultin request
	 * @return
	 * 						- FAILED if transaction failed
	 * 						- DESTROY_ME if transaction failed and IKE SA
	 * 						  must be deleted
	 * 						- SUCCESS
	 */
	status_t (*get_request) (transaction_t *this, message_t **request);

	/**
	 * @brief Build the response for a received request.
	 * 
	 * A transaction creates a response only once for a unique request.
	 * This allows the use of get_response multiple times for retransmission
	 * purposes.
	 * The transaction is not responsible for generating/encrypting the
	 * response, nor is it responsible for decrypting/parsing the request.
	 * This is the job of the caller. But the response MAY be already
	 * generated when calling get_request() the second time.
	 * The initiator waits for a response, so we send one in every case. This
	 * means response points always to a valid message. This message
	 * may not be modified or destroyed, it gets destroyed along with the
	 * transaction.
	 * The get_response() function may return a next transaction. This allows
	 * passing of informations from one transaction to a next one.
	 *
	 * @param this 			calling object
	 * @param request		received request
	 * @param[out] response	resulting response
	 * @param[out] next		transaction expected as next, or NULL
	 * @return
	 * 						- FAILED if transaction failed
	 * 						- DESTROY_ME if transaction failed and IKE SA
	 * 						  must be deleted
	 * 						- SUCCESS
	 */
	status_t (*get_response) (transaction_t *this, message_t *request, 
							  message_t **response, transaction_t **next);
	
	/**
	 * @brief Conclude an initiated transaction with a received response.
	 *
	 * The response must be decrypted and parsed. The conclude function 
	 * may return a new transaction. This transaction has to be executed
	 * next to complete a multi-exchange scenario. It allows a clean
	 * transaction mechanism, as the transaction knows best whats to do
	 * after it completes. It must only be executed if conclude returns
	 * SUCCESS.
	 * 
	 * @param this 				calling object
	 * @param response			received response
	 * @param[out] next			transaction to execute as next, or NULL
	 * @return
	 * 						- FAILED if transaction failed
	 * 						- DESTROY_ME if transaction failed and IKE SA
	 * 						  must be deleted
	 * 						- SUCCESS
	 */
	status_t (*conclude) (transaction_t *this, message_t *response, 
						  transaction_t **next);
	
	/**
	 * @brief Get the message ID associated with this transaction.
	 *
	 * Every transaction consists of a message pair with the same 
	 * message ID. This ID can be queried with get_message_id().
	 * 
	 * @param this 			calling object
	 * @return				message id
	 */
	u_int32_t (*get_message_id) (transaction_t *this);
	
	/**
	 * @brief Times we already sent the request (retransmitted).
	 *
	 * The transaction stores an internal counter to see how
	 * many times we sent the request. This counter is incremented
	 * each time after a call to requested().
	 *
	 * @param this 			calling object
	 * @return				message id
	 */
	u_int32_t (*requested) (transaction_t *this);
	
	/**
	 * @brief Destroys a transaction_t object.
	 *
	 * @param this 			calling object
	 */
	void (*destroy) (transaction_t *this);
};

/**
 * @brief Create a transaction instance based on a received request.
 *
 * Incoming requests are handled by a transaction. But as we don't
 * know what kind of transaction we use for a specific request, we use
 * a generic constructor. This constructor decides which instance will
 * handle the transaction, and creates it.
 * 
 * @param ike_sa 		ike_sa associated with this transaction
 * @param request		received request
 * @return
 * 						- created transaction, or 
 * 						- NULL no transaction needed
 * 
 * @ingroup transactions
 */
transaction_t *transaction_create(ike_sa_t *ike_sa, message_t* request);

#endif /* TRANSACTION_H_ */
