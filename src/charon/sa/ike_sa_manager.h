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

typedef struct ike_sa_manager_t ike_sa_manager_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <encoding/message.h>
#include <config/peer_cfg.h>

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
	 * @brief Checkout an existing IKE_SA.
	 * 
	 * @param this 				the manager object
	 * @param ike_sa_id			the SA identifier, will be updated
	 * @returns 					
	 * 							- checked out IKE_SA if found
	 * 							- NULL, if specified IKE_SA is not found.
	 */
	ike_sa_t* (*checkout) (ike_sa_manager_t* this, ike_sa_id_t *sa_id);
	
	/**
	 * @brief Create and check out a new IKE_SA.
	 * 
	 * @param this 				the manager object
	 * @param initiator			TRUE for initiator, FALSE otherwise
	 * @returns 				created andchecked out IKE_SA
	 */
	ike_sa_t* (*checkout_new) (ike_sa_manager_t* this, bool initiator);
	
	/**
	 * @brief Checkout an IKE_SA by a message.
	 * 
	 * In some situations, it is necessary that the manager knows the
	 * message to use for the checkout. This has the folloing reasons:
	 * 
	 * 1. If the targeted IKE_SA is already processing a message, we do not
	 *    check it out if the message ID is the same.
	 * 2. If it is an IKE_SA_INIT request, we have to check if it is a 
	 *    retransmission. If so, we have to drop the message, we would
	 *    create another unneded IKE_SA for each retransmitted packet.
	 *
	 * A call to checkout_by_message() returns a (maybe new created) IKE_SA.
	 * If processing the message does not make sense (for the reasons above),
	 * NULL is returned.
	 * 
	 * @param this 				the manager object
	 * @param ike_sa_id			the SA identifier, will be updated
	 * @returns 					
	 * 							- checked out/created IKE_SA
	 * 							- NULL to not process message further
	 */
	ike_sa_t* (*checkout_by_message) (ike_sa_manager_t* this, message_t *message);
	
	/**
	 * @brief Checkout an IKE_SA for initiation by a peer_config.
	 *
	 * To initiate, a CHILD_SA may be established within an existing IKE_SA.
	 * This call checks for an existing IKE_SA by comparing the configuration.
	 * If the CHILD_SA can be created in an existing IKE_SA, the matching SA
	 * is returned.
	 * If no IKE_SA is found, a new one is created. This is also the case when
	 * the found IKE_SA is in the DELETING state.
	 *
	 * @param this			 	the manager object
	 * @param peer_cfg			configuration used to find an existing IKE_SA
	 * @return					checked out/created IKE_SA
	 */
	ike_sa_t* (*checkout_by_config) (ike_sa_manager_t* this,
								 	 peer_cfg_t *peer_cfg);
	
	/**
	 * @brief Check out an IKE_SA a unique ID.
	 *
	 * Every IKE_SA and every CHILD_SA is uniquely identified by an ID. 
	 * These checkout function uses, depending
	 * on the child parameter, the unique ID of the IKE_SA or the reqid
	 * of one of a IKE_SAs CHILD_SA.
	 *
	 * @param this				the manager object
	 * @param id				unique ID of the object
	 * @param child				TRUE to use CHILD, FALSE to use IKE_SA
	 * @return
	 * 							- checked out IKE_SA, if found
	 * 							- NULL, if not found
	 */
	ike_sa_t* (*checkout_by_id) (ike_sa_manager_t* this, u_int32_t id,
								 bool child);
	
	/**
	 * @brief Check out an IKE_SA by the policy/connection name.
	 *
	 * Check out the IKE_SA by the connections name or by a CHILD_SAs policy
	 * name.
	 *
	 * @param this				the manager object
	 * @param name				name of the connection/policy
	 * @param child				TRUE to use policy name, FALSE to use conn name
	 * @return
	 * 							- checked out IKE_SA, if found
	 * 							- NULL, if not found
	 */
	ike_sa_t* (*checkout_by_name) (ike_sa_manager_t* this, char *name,
								   bool child);
	
	/**
	 * @brief Create an iterator over all stored IKE_SAs.
	 *
	 * The avoid synchronization issues, the iterator locks access
	 * to the manager exclusively, until it gets destroyed.
	 * This iterator is for reading only! Writing will corrupt the manager.
	 *
	 * @param this			 	the manager object
	 * @return					iterator over all IKE_SAs.
	 */
	iterator_t *(*create_iterator) (ike_sa_manager_t* this);
	
	/**
	 * @brief Checkin the SA after usage.
	 * 
	 * @warning the SA pointer MUST NOT be used after checkin! 
	 * The SA must be checked out again!
	 *  
	 * @param this			 	the manager object
	 * @param ike_sa_id			the SA identifier, will be updated
	 * @param ike_sa			checked out SA
	 * @returns 				
	 * 							- SUCCESS if checked in
	 * 							- NOT_FOUND when not found (shouldn't happen!)
	 */
	status_t (*checkin) (ike_sa_manager_t* this, ike_sa_t *ike_sa);
	
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
	 * @brief Get the number of IKE_SAs which are in the connecting state.
	 *
	 * To prevent the server from resource exhaustion, cookies and other
	 * mechanisms are used. The number of half open IKE_SAs is a good
	 * indicator to see if a peer is flooding the server.
	 * If a host is supplied, only the number of half open IKE_SAs initiated
	 * from this IP are counted.
	 * Only SAs for which we are the responder are counted.
	 * 
	 * @param this				the manager object
	 * @param ip				NULL for all, IP for half open IKE_SAs with IP
	 * @return					number of half open IKE_SAs
	 */
	int (*get_half_open_count) (ike_sa_manager_t *this, host_t *ip);
	
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
