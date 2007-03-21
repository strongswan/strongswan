/**
 * @file child_create.h
 * 
 * @brief Interface child_create_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef CHILD_CREATE_H_
#define CHILD_CREATE_H_

typedef struct child_create_t child_create_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>
#include <config/policies/policy.h>

/**
 * @brief Task of type CHILD_CREATE, established a new CHILD_SA.
 *
 * This task may be included in the IKE_AUTH message or in a separate 
 * CREATE_CHILD_SA exchange.
 *
 * @b Constructors:
 *  - child_create_create()
 * 
 * @ingroup tasks
 */
struct child_create_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
	
	/**
	 * @brief Use a specific reqid for the CHILD_SA.
	 *
	 * When this task is used for rekeying, the same reqid is used
	 * for the new CHILD_SA. 
	 *
	 * @param this		calling object
	 * @param reqid		reqid to use
	 */
	void (*use_reqid) (child_create_t *this, u_int32_t reqid);
	
	/**
	 * @brief Get the lower of the two nonces, used for rekey collisions.
	 *
	 * @param this		calling object
	 * @return			lower nonce
	 */
	chunk_t (*get_lower_nonce) (child_create_t *this);
	
	/**
	 * @brief Get the CHILD_SA established by this task.
	 *
	 * This call returns a child only when it has been established successfully.
	 *
	 * @param this		calling object
	 * @return			child_sa
	 */
	child_sa_t* (*get_child) (child_create_t *this);
};

/**
 * @brief Create a new child_create task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param policy		policy if task initiator, NULL if responder
 * @return			 	child_create task to handle by the task_manager
 */
child_create_t *child_create_create(ike_sa_t *ike_sa, policy_t *policy);

#endif /* CHILD_CREATE_H_ */
