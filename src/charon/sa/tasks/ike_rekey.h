/**
 * @file ike_rekey.h
 * 
 * @brief Interface ike_rekey_t.
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

#ifndef IKE_REKEY_H_
#define IKE_REKEY_H_

typedef struct ike_rekey_t ike_rekey_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * @brief Task of type IKE_REKEY, rekey an established IKE_SA.
 *
 * @b Constructors:
 *  - ike_rekey_create()
 * 
 * @ingroup tasks
 */
struct ike_rekey_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * @brief Create a new IKE_REKEY task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE for initiator, FALSE for responder
 * @return			  	IKE_REKEY task to handle by the task_manager
 */
ike_rekey_t *ike_rekey_create(ike_sa_t *ike_sa, bool initiator);

#endif /* IKE_REKEY_H_ */
