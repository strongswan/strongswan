/*
 * Copyright (C) 2011 Tobias Brunner
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

/**
 * @defgroup ike_natd_v1 ike_natd_v1
 * @{ @ingroup tasks
 */

#ifndef IKE_NATD_V1_H_
#define IKE_NATD_V1_H_

typedef struct ike_natd_v1_t ike_natd_v1_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * Task of type ike_natd_v1, detects NAT situation in IKEv1 Phase 1.
 */
struct ike_natd_v1_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * Create a new ike_natd_v1 task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if task is the original initiator
 * @return				ike_natd_v1 task to handle by the task_manager
 */
ike_natd_v1_t *ike_natd_v1_create(ike_sa_t *ike_sa, bool initiator);

#endif /** IKE_NATD_V1_H_ @}*/
