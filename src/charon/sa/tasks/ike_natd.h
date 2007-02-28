/**
 * @file ike_natd.h
 * 
 * @brief Interface ike_natd_t.
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

#ifndef IKE_NATD_H_
#define IKE_NATD_H_

typedef struct ike_natd_t ike_natd_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * @brief Task of type ike_natd, detects NAT situation in IKE_SA_INIT exchange.
 *
 * @b Constructors:
 *  - ike_natd_create()
 * 
 * @ingroup tasks
 */
struct ike_natd_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * @brief Create a new ike_natd task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if thask is the original initator
 * @return			  ike_natd task to handle by the task_manager
 */
ike_natd_t *ike_natd_create(ike_sa_t *ike_sa, bool initiator);

#endif /* IKE_NATD_H_ */
