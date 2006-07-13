/**
 * @file delete_child_sa.h
 * 
 * @brief Interface of transaction delete_child_sa.
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


#ifndef DELETE_CHILD_SA_H_
#define DELETE_CHILD_SA_H_

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>


typedef struct delete_child_sa_t delete_child_sa_t;

/**
 * @brief A transaction used to delete a CHILD_SA.
 *
 * @b Constructors:
 *  - delete_child_sa_create()
 *  - transaction_create() with the appropriate message
 *
 * @ingroup transactions
 */
struct delete_child_sa_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
	
	/**
	 * @brief Set the CHILD_SA to delete.
	 *
	 * @param this		calling object
	 * @param child_sa	CHILD_SA to rekey
	 */
	void (*set_child_sa) (delete_child_sa_t* this, child_sa_t *child_sa);
};

/**
 * @brief Create a new transaction which deletes a CHILD_SA.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created delete_child_sa transaction
 *
 * @ingroup transactions
 */
delete_child_sa_t *delete_child_sa_create(ike_sa_t *ike_sa);

#endif /* DELETE_CHILD_SA_H_ */
