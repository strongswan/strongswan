/**
 * @file ike_sa_manager.h
 * 
 * @brief Central point for managing IKE-SAs (creation, locking, deleting...)
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

#ifndef IKE_SA_MANAGER_H_
#define IKE_SA_MANAGER_H_

#include "types.h"
#include "ike_sa.h"


/**
 * @brief The IKE_SA-Manager manages the IKE_SAs ;-). 
 * 
 * To avoid access from multiple threads, IKE_SAs must be checked out from
 * the manager, and checked back in after usage. 
 * The manager also handles deletion of SAs.
 * 
 */
typedef struct ike_sa_manager_s ike_sa_manager_t;
struct ike_sa_manager_s {

	status_t (*checkout_ike_sa) (ike_sa_manager_t*, ike_sa_id_t *sa_id, ike_sa_t **ike_sa);
	status_t (*checkin_ike_sa) (ike_sa_manager_t*, ike_sa_t *ike_sa);
	status_t (*delete_ike_sa_by_id) (ike_sa_manager_t*, ike_sa_id_t *ike_sa_id);
	status_t (*delete_ike_sa_by_sa) (ike_sa_manager_t*, ike_sa_t *ike_sa);
	
	/**
	 * @brief Destroys a linked_list object
	 * 
	 * @warning all items are removed before deleting the list. The
	 *          associated values are NOT destroyed. 
	 * 			Destroying an list which is not empty may cause
	 * 			memory leaks!
	 * 
	 * @param linked_list calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (ike_sa_manager_t *isam);
};

/**
 * @brief Create the IKE_SA-Manager
 */
ike_sa_manager_t *ike_sa_manager_create();

#endif /*IKE_SA_MANAGER_H_*/
