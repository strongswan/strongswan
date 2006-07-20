/**
 * @file policy_store.h
 * 
 * @brief Interface policy_store_t.
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

#ifndef POLICY_STORE_H_
#define POLICY_STORE_H_

#include <types.h>
#include <config/policies/policy.h>
#include <utils/linked_list.h>


typedef struct policy_store_t policy_store_t;

/**
 * @brief The interface for a store of policy_t's.
 *
 * The store uses reference counting to manage their lifetime. Call
 * destroy() for a policy which is returned from the store after usage.
 *
 * @b Constructors:
 * - stroke_create()
 * 
 * @ingroup config
 */
struct policy_store_t {

	/**
	 * @brief Returns a policy identified by two IDs and a set of traffic selectors.
	 *
	 * other_id must be fully qualified. my_id may be %any, as the
	 * other peer may not include an IDr Request.
	 *
	 * @param this			calling object
	 * @param my_id			own ID of the policy
	 * @param other_id		others ID of the policy
	 * @param my_ts			traffic selectors requested for local host
	 * @param other_ts		traffic selectors requested for remote host
	 * @param my_host		host to use for wilcards in TS compare
	 * @param other_host	host to use for wildcards in TS compare
	 * @return
	 *						- matching policy_t, if found
	 *						- NULL otherwise
	 */
	policy_t *(*get_policy) (policy_store_t *this, 
							 identification_t *my_id, identification_t *other_id,
							 linked_list_t *my_ts, linked_list_t *other_ts,
							 host_t *my_host, host_t* other_host);

	/**
	 * @brief Returns a policy identified by a connection name.
	 *
	 * @param this		calling object
	 * @param name		name of the policy
	 * @return
	 *					- matching policy_t, if found
	 *					- NULL otherwise
	 */
	policy_t *(*get_policy_by_name) (policy_store_t *this, char *name);

	/**
	 * @brief Add a policy to the list.
	 *
	 * The policy is owned by the store after the call. Do
	 * not modify nor free.
	 *
	 * @param this		calling object
	 * @param policy	policy to add
	 */
	void (*add_policy) (policy_store_t *this, policy_t *policy);

	/**
	 * @brief Delete a policy from the store.
	 *
	 * Remove a policy from the store identified by its name.
	 *
	 * @param this		calling object
	 * @param policy	policy to add
	 * @return
	 *					- SUCCESS, or
	 *					- NOT_FOUND
	 */
	status_t (*delete_policy) (policy_store_t *this, char *name);
	
	/**
	 * @brief Destroys a policy_store_t object.
	 *
	 * @param this 					calling object
	 */
	void (*destroy) (policy_store_t *this);
};

#endif /*POLICY_STORE_H_*/
