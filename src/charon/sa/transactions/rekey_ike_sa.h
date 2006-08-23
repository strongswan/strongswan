/**
 * @file rekey_ike_sa.h
 * 
 * @brief Interface of transaction rekey_ike_sa.
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

#ifndef REKEY_IKE_SA_H
#define REKEY_IKE_SA_H

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>
#include <crypto/diffie_hellman.h>


typedef struct rekey_ike_sa_t rekey_ike_sa_t;

/**
 * @brief A transaction to rekey an established IKE_SA
 *
 * @b Constructors:
 *  - rekey_ike_sa_create()
 *  - transaction_create() with the appropriate message
 *
 * @ingroup transactions
 */
struct rekey_ike_sa_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
	
	/**
	 * @brief Set the Diffie Hellman group to use for initiating.
	 * 
	 * If a first exchange fails with a INVALID_KE_PAYLOAD, the second
	 * try uses the DH group proposed by the responder.
	 * 
	 * @param this		calling object
	 * @param dh_group	diffie hellman group to use
	 */
	void (*use_dh_group) (rekey_ike_sa_t* this, diffie_hellman_group_t dh_group);
	
	/**
	 * @brief Cancel the request.
	 *
	 * Cancelling the request will set a flag in the transaction. 
	 *
	 * @param this		calling object
	 * @param child_sa	CHILD_SA to rekey
	 */
	void (*cancel) (rekey_ike_sa_t* this);
};

/**
 * @brief Create a new transaction to rekey an existing IKE_SA.
 *
 * @param ike_sa		existing IKE_SA
 * @return				created rekey_ike_sa transaction
 *
 * @ingroup transactions
 */
rekey_ike_sa_t *rekey_ike_sa_create(ike_sa_t *ike_sa);

#endif /* REKEY_IKE_SA_H */
