/**
 * @file ike_sa_manager.h
 * 
 * @brief Interface of ike_sa_manager_t.
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

#ifndef IKE_SA_MANAGER_H_
#define IKE_SA_MANAGER_H_

#include <types.h>
#include <sa/ike_sa.h>
#include <utils/logger.h>


typedef struct ike_sa_manager_t ike_sa_manager_t;

/**
 * @brief The IKE_SA-Manager is responsible for managing all initiated and responded IKE_SA's.
 *
 * To avoid access from multiple threads, IKE_SAs must be checked out from
 * the manager, and checked in after usage. 
 * The manager also handles deletion of SAs.
 *
 * @todo checking of double-checkouts from the same threads would be nice.
 * This could be done by comparing thread-ids via pthread_self()...
 * 
 * @todo Managing of ike_sa_t objects in a hash table instead of linked list.
 * 
 * @b Constructors:
 * - ike_sa_manager_create()
 * 
 * @ingroup sa
 */
struct ike_sa_manager_t {
	/**
	 * @brief Checkout an IKE_SA, create it when necesarry.
	 * 
	 * Checks out a SA by its ID. An SA will be created, when the responder
	 * SPI is not set (when received an IKE_SA_INIT from initiator).
	 * Management of SPIs is the managers job, he will set it.
	 * This function blocks until SA is available for checkout.
	 * 
	 * @warning checking out two times without checking in will
	 * result in a deadlock!
	 * 
	 * @param this 				the manager object
	 * @param[in/out] ike_sa_id	the SA identifier, will be updated
	 * @returns 					
	 * 							- checked out IKE_SA if found
	 * 							- NULL, if no such IKE_SA available
	 */
	ike_sa_t* (*checkout) (ike_sa_manager_t* this, ike_sa_id_t *sa_id);
	
	/**
	 * @brief Checkout an existing IKE_SA by hosts and identifications.
	 *
	 * Allows the lookup of an IKE_SA by user IDs and hosts. It returns the
	 * first found occurence, if there are multiple candidates. Supplied IDs
	 * may contain wildcards, hosts may be %any. 
	 * If no IKE_SA is found, a new one is created.
	 *
	 * @param this			 	the manager object
	 * @param my_host			address of our host
	 * @param other_id			address of remote host
	 * @param my_id				ID used by us
	 * @param other_id			ID used by remote
	 * @return					checked out/created IKE_SA
	 */
	ike_sa_t* (*checkout_by_id) (ike_sa_manager_t* this,
								  host_t *my_host, host_t* other_host,
								  identification_t *my_id, 
								  identification_t *other_id);
	
	/**
	 * @brief Check out an IKE_SA by protocol and SPI of one of its CHILD_SA.
	 *
	 * The kernel sends us expire messages for IPsec SAs. To fullfill
	 * this request, we must check out the IKE SA which contains the
	 * CHILD_SA the kernel wants to modify.
	 *
	 * @param this				the manager object
	 * @param reqid				reqid of the CHILD_SA
	 * @return
	 * 							- checked out IKE_SA, if found
	 * 							- NULL, if not found
	 */
	ike_sa_t* (*checkout_by_child) (ike_sa_manager_t* this, u_int32_t reqid);
	
	/**
	 * @brief Get a list of all IKE_SA SAs currently set up.
	 * 
	 * The resulting list with all IDs must be destroyed by 
	 * the caller. There is no guarantee an ike_sa with the 
	 * corrensponding ID really exists, since it may be deleted
	 * in the meantime by another thread.
	 * 
	 * @param this			 	the manager object
	 * @return					a list with ike_sa_id_t s
	 */
	linked_list_t *(*get_ike_sa_list) (ike_sa_manager_t* this);
	
	/**
	 * @brief Log the status of the IKE_SA's in the manager.
	 *
	 * A informational log is done to the supplied logger. If logger is 
	 * NULL, an internal logger is used. If a name is supplied,
	 * only connections with the matching name will be logged.
	 * 
	 * @param this			 	the manager object
	 * @param logger			logger to do the log, or NULL
	 * @param name				name of a connection, or NULL
	 */
	void (*log_status) (ike_sa_manager_t* this, logger_t* logger, char* name);
	
	/**
	 * @brief Checkin the SA after usage.
	 * 
	 * @warning the SA pointer MUST NOT be used after checkin! 
	 * The SA must be checked out again!
	 *  
	 * @param this			 	the manager object
	 * @param[in/out] ike_sa_id	the SA identifier, will be updated
	 * @param[out] ike_sa		checked out SA
	 * @returns 				
	 * 							- SUCCESS if checked in
	 * 							- NOT_FOUND when not found (shouldn't happen!)
	 */
	status_t (*checkin) (ike_sa_manager_t* this, ike_sa_t *ike_sa);
	
	/**
	 * @brief Delete a SA, which was not checked out.
	 *
	 * If the state allows it, the IKE SA is destroyed immediately. If it is
	 * in the state ESTABLSIHED, a delete message
	 * is sent to the remote peer, which has to be acknowledged.
	 *
	 * @warning do not use this when the SA is already checked out, this will
	 * deadlock!
	 *
	 * @param this			 	the manager object
	 * @param[in/out] ike_sa_id	the SA identifier
	 * @returns 				
	 * 							- SUCCESS if found
	 * 							- NOT_FOUND when no such SA is available
	 */
	status_t (*delete) (ike_sa_manager_t* this, ike_sa_id_t *ike_sa_id);
	
	/**
	 * @brief Delete a SA identified by its name, which was not checked out.
	 *
	 * Using delete_by_name allows the delete of IKE_SAs and CHILD_SAs.
	 * The supplied name may have one of the following format:
	 *
	 * name{x}		=> delete IKE_SA with "name" and unique id "x"
	 * name{}		=> delete all IKE_SAs with "name"
	 * name[x]		=> delete CHILD_SA with "name" and unique id "x"
	 * name[]		=> delete all CHILD_SAs with "name"
	 * name			=> delete all CHILD_SAs or IKE_SAs with "name"
	 *
	 * @warning do not use this when the SA is already checked out, this will
	 * deadlock!
	 *
	 * @param this			 	the manager object
	 * @param name				name in one of the format described above
	 * @returns 				
	 * 							- SUCCESS if found
	 * 							- NOT_FOUND when no such SA is available
	 */
	status_t (*delete_by_name) (ike_sa_manager_t* this, char *name);
	
	/**
	 * @brief Destroy a checked out SA.
	 *
	 * The IKE SA is destroyed without notification of the remote peer.
	 * Use this only if the other peer doesn't respond or behaves not
	 * as predicted.
	 * Checking in and destruction is an atomic operation (for the IKE_SA),
	 * so this can be called if the SA is in a "unclean" state, without the
	 * risk that another thread can get the SA.
	 *
	 * @param this			 	the manager object
	 * @param ike_sa			SA to delete
	 * @returns 				
	 * 							- SUCCESS if found
	 * 							- NOT_FOUND when no such SA is available
	 */
	status_t (*checkin_and_destroy) (ike_sa_manager_t* this, ike_sa_t *ike_sa);
	
	/**
	 * @brief Destroys the manager with all associated SAs.
	 * 
	 * Threads will be driven out, so all SAs can be deleted cleanly.
	 * 
	 * @param this				 the manager object
	 */
	void (*destroy) (ike_sa_manager_t *this);
};

/**
 * @brief Create a manager.
 * 
 * @returns 	ike_sa_manager_t object
 * 
 * @ingroup sa
 */
ike_sa_manager_t *ike_sa_manager_create(void);

#endif /*IKE_SA_MANAGER_H_*/
