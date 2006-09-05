/**
 * @file create_child_sa.h
 * 
 * @brief Interface of transaction create_child_sa.
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

#ifndef CREATE_CHILD_SA_H_
#define CREATE_CHILD_SA_H_

#include <sa/ike_sa.h>
#include <sa/child_sa.h>
#include <sa/transactions/transaction.h>


typedef struct create_child_sa_t create_child_sa_t;

/**
 * @brief A transaction to create a new or rekey an existing CHILD_SA.
 *
 * If the CHILD_SA is intended to create a new CHILD_SA, set the policy
 * with set_policy(). If it is intended to rekey an existing CHILD_SA,
 * set the appropriate CHILD_SA with rekeys_child().
 *
 * Rekeying of an CHILD_SA works the same way as creating a new one,
 * but includes an additional REKEY_SA notify and deletes the old
 * one (in a separate transaction).
 * 
 *                     __________  _________
 *                       Cyq     \/    Czq  
 *                     __________/\_________
 *              detect __________  _________ detect
 *                       Czp     \/    Czp  
 * compare nonces, won __________/\_________ compare nonces, lost
 *                                          
 *        delete old   __________           
 *                       Dxq     \__________
 *                                __________
 *                     __________/    Dxp   
 *                                __________ delete created
 *                     __________/    Dzq   
 *                     __________           
 *                       Dzp     \__________
 * 
 *
 * @b Constructors:
 *  - create_child_sa_create()
 *  - transaction_create() with the appropriate message
 *
 * @ingroup transactions
 */
struct create_child_sa_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
	
	/**
	 * @brief Set the policy to use for creating a new CHILD_SA.
	 *
	 * @param this		calling object
	 * @param policy	policy for CHILD_SA
	 */
	void (*set_policy) (create_child_sa_t* this, policy_t *policy);

	/**
	 * @brief Set the reqid used for CHILD_SA setup.
	 *
	 * If we acquire, we must use the same reqid as the
	 * installed policy.
	 * 
	 * @param this			calling object
	 * @param reqid			reqid to use for the CHILD_SA
	 */
	void (*set_reqid) (create_child_sa_t* this, u_int32_t reqid);
	
	/**
	 * @brief Set the CHILD_SA which gets rekeyed by the new one.
	 *
	 * @param this		calling object
	 * @param child_sa	CHILD_SA to rekey
	 */
	void (*rekeys_child) (create_child_sa_t* this, child_sa_t *child_sa);
	
	/**
	 * @brief Cancel the request.
	 *
	 * Cancelling the request will set a flag in the transaction. When
	 * the response for the transaction is received, the created CHILD_SA
	 * gets deleted afterwards.
	 *
	 * @param this		calling object
	 * @param child_sa	CHILD_SA to rekey
	 */
	void (*cancel) (create_child_sa_t* this);
};

/**
 * @brief Create a new transaction which creates/rekeys CHILD_SAs.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created create_child_sa transaction
 *
 * @ingroup transactions
 */
create_child_sa_t *create_child_sa_create(ike_sa_t *ike_sa);

#endif /* CREATE_CHILD_SA_H_ */
