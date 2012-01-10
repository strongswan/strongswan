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
 * @defgroup informational informational
 * @{ @ingroup tasks
 */

#ifndef INFORMATIONAL_H_
#define informational_H_

typedef struct informational_t informational_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/task.h>
#include <encoding/payloads/notify_payload.h>

/**
 * IKEv1 informational exchange, negotiates errors.
 */
struct informational_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * Create a new informational task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param notify		notify to send as initiator, NULL if responder
 * @param dpd_seqnr	DPD sequence number, incoming or outgoing
 * @return				task to handle by the task_manager
 */
informational_t *informational_create(ike_sa_t *ike_sa, notify_payload_t *notify, u_int32_t dpd_seqnr);

#endif /** INFORMATIONAL_H_ @}*/
