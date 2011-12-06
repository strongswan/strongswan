/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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
 * @defgroup ike_cert_post_v1 ike_cert_post_v1
 * @{ @ingroup tasks
 */

#ifndef IKE_CERT_POST_V1_H_
#define IKE_CERT_POST_V1_H_

typedef struct ike_cert_post_v1_t ike_cert_post_v1_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * IKE_CERT_POST_V1, IKEv1 certificate processing after authentication.
 */
struct ike_cert_post_v1_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * Create a new ike_cert_post_v1 task.
 *
 * The initiator parameter means the original initiator, not the initiator
 * of the certificate request.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if task is the original initiator
 * @return				ike_cert_post_v1 task to handle by the task_manager
 */
ike_cert_post_v1_t *ike_cert_post_v1_create(ike_sa_t *ike_sa, bool initiator);

#endif /** IKE_CERT_POST_V1_H_ @}*/
