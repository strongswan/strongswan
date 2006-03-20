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
#include <config/policy.h>


typedef struct policy_store_t policy_store_t;

/**
 * @brief The interface for a store of policy_t's.
 * 
 * @b Constructors:
 * - stroke_create()
 * 
 * @ingroup config
 */
struct policy_store_t { 

	/**
	 * @brief Returns a policy identified by two IDs.
	 * 
	 * The returned policy gets created/cloned and therefore must be
	 * destroyed by the caller.
	 * 
	 * @param this		calling object
	 * @param my_id		own ID of the policy
	 * @param other_id	others ID of the policy
	 * @return
	 *					- matching policy_t, if found
	 * 					- NULL otherwise
	 */
	policy_t *(*get_policy) (policy_store_t *this, identification_t *my_id, identification_t *other_id);
	
	/**
	 * @brief Destroys a policy_store_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (policy_store_t *this);
};

#endif /*POLICY_STORE_H_*/
