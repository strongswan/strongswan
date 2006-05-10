/**
 * @file local_policy_store.h
 *
 * @brief Interface of local_policy_store_t.
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
 
#ifndef LOCAL_POLICY_STORE_H_
#define LOCAL_POLICY_STORE_H_

#include <types.h>
#include <config/policies/policy_store.h>


typedef struct local_policy_store_t local_policy_store_t;

/**
 * @brief A policy_store_t implementation using a simple policy lists.
 *
 * The local_policy_store_t class implements the policy_store_t interface
 * as simple as possible. The policies are stored in a in-memory list.
 *
 * @b Constructors:
 *  - local_policy_store_create()
 * 
 * @ingroup config
 */
struct local_policy_store_t {
	
	/**
	 * Implements policy_store_t interface
	 */
	policy_store_t policy_store;
};

/**
 * @brief Creates a local_policy_store_t instance.
 *
 * @return policy store instance.
 * 
 * @ingroup config
 */
local_policy_store_t *local_policy_store_create(void);

#endif /* LOCAL_POLICY_STORE_H_ */
