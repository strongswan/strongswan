/**
 * @file delete_ike_sa.h
 * 
 * @brief Interface of transaction delete_ike_sa.
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


#ifndef DELETE_IKE_SA_H_
#define DELETE_IKE_SA_H_

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>


typedef struct delete_ike_sa_t delete_ike_sa_t;

/**
 * @brief A transaction used to delete the IKE_SA.
 *
 * Notation as follows:
 * Mx{D} means: Message, with message ID "x", containing a Delete payload
 *
 * The clarifcation Document says in 5.8, that a IKE_SA delete should not
 * be acknowledged with the same delete. This only makes sense for CHILD_SAs,
 * as they are paired. IKE_SAs are not, there is only one for both ends.
 *
 * Normal case:
 * ----------------
 * Mx{D}  -->
 *       <--      Mx{}
 * Delete request is sent, and we wait for the acknowledge.
 *
 * Special case 1:
 * ---------------
 * Mx{D}  -->
 *       <--      My{D}
 * My{}   -->
 *       <--      Mx{}
 * Both initate a delete at the same time. We ack the delete, but wait for
 * our delete to be acknowledged.
 *
 * @b Constructors:
 *  - delete_ike_sa_create()
 *  - transaction_create() with the appropriate message
 *
 * @ingroup transactions
 */
struct delete_ike_sa_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
};

/**
 * @brief Create a new transaction which deletes the IKE_SA.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created delete_ike_sa transaction
 *
 * @ingroup transactions
 */
delete_ike_sa_t *delete_ike_sa_create(ike_sa_t *ike_sa);

#endif /* DELETE_IKE_SA_H_ */
