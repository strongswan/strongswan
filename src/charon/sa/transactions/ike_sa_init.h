/**
 * @file ike_sa_init.h
 * 
 * @brief Interface of transaction ike_sa_init.
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


#ifndef IKE_SA_INIT_H_
#define IKE_SA_INIT_H_

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>


typedef struct ike_sa_init_t ike_sa_init_t;

/**
 * @brief A transaction for the first message exchange to set up an IKE_SA.
 * 
 * @b Constructors:
 *  - ike_sa_init_create()
 *  - transaction_create() with the appropriate message
 * 
 * @ingroup transactions
 */
struct ike_sa_init_t {
	
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
	 * @return			FALSE, if DH group not allowed/supported
	 */
	bool (*use_dh_group) (ike_sa_init_t* this, diffie_hellman_group_t dh_group);
};

/**
 * @brief Create a new transaction which processes IKE_SA_INIT exchanges.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created ike_sa_init transaction
 *
 * @ingroup transactions
 */
ike_sa_init_t *ike_sa_init_create(ike_sa_t *ike_sa);

#endif /* IKE_SA_INIT_H_ */
