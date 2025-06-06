/*
 * Copyright (C) 2018-2025 Tobias Brunner
 * Copyright (C) 2007 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup child_create child_create
 * @{ @ingroup tasks_v2
 */

#ifndef CHILD_CREATE_H_
#define CHILD_CREATE_H_

typedef struct child_create_t child_create_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/task.h>
#include <config/child_cfg.h>

/**
 * Task of type TASK_CHILD_CREATE, established a new CHILD_SA.
 *
 * This task may be included in the IKE_AUTH message or in a separate
 * CREATE_CHILD_SA exchange.
 */
struct child_create_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;

	/**
	 * Use a specific reqid for the CHILD_SA.
	 *
	 * When this task is used for rekeying, the same reqid is used
	 * for the new CHILD_SA.
	 *
	 * This must only be called with dynamically allocated reqids (i.e. from
	 * kernel_interface_t::alloc_reqid()), the method takes a reference that's
	 * maintained for the lifetime of the task.
	 *
	 * @param reqid		reqid to use
	 */
	void (*use_reqid) (child_create_t *this, uint32_t reqid);

	/**
	 * Use specific mark values to override configuration.
	 *
	 * @param in		inbound mark value
	 * @param out		outbound mark value
	 */
	void (*use_marks)(child_create_t *this, uint32_t in, uint32_t out);

	/**
	 * Use specific interface IDs, overriding configuration.
	 *
	 * @param in			inbound interface ID
	 * @param out			outbound interface ID
	 */
	void (*use_if_ids)(child_create_t *this, uint32_t in, uint32_t out);

	/**
	 * Use specific security label, overriding configuration.
	 *
	 * @param label			security label
	 */
	void (*use_label)(child_create_t *this, sec_label_t *label);

	/**
	 * Enable per-CPU feature, optionally with a specific CPU ID for the
	 * negotiated CHILD_SA.
	 *
	 * @param per_cpu	TRUE to enable per-CPU feature (automatically set if
	 *					cpu is not CPU_ID_MAX)
	 * @param cpu		CPU ID
	 */
	void (*use_per_cpu)(child_create_t *this, bool per_cpu, uint32_t cpu);

	/**
	 * Use data from the given old SA (e.g. KE method and traffic selectors)
	 * when rekeying/recreating it.
	 *
	 * @param old			old CHILD_SA that is getting rekeyed/recreated
	 */
	void (*recreate_sa)(child_create_t *this, child_sa_t *old);

	/**
	 * Get the lower of the two nonces, used for rekey collisions.
	 *
	 * @return			lower nonce
	 */
	chunk_t (*get_lower_nonce) (child_create_t *this);

	/**
	 * Get the CHILD_SA established/establishing by this task.
	 *
	 * @return			child_sa
	 */
	child_sa_t* (*get_child) (child_create_t *this);

	/**
	 * Get the SPI of the other peer's selected proposal, if available.
	 *
	 * @return			other's SPI, 0 if unknown
	 */
	uint32_t (*get_other_spi)(child_create_t *this);

	/**
	 * Enforce a specific CHILD_SA config as responder.
	 *
	 * @param cfg		configuration to enforce, reference gets owned
	 */
	void (*set_config)(child_create_t *this, child_cfg_t *cfg);

	/**
	 * Get the child config of this task as initiator.
	 *
	 * @return				config for the CHILD_SA, NULL as responder
	 */
	child_cfg_t *(*get_config)(child_create_t *this);

	/**
	 * Mark this active task as being aborted, i.e. cause a deletion of the
	 * created CHILD_SA immediately after its creation (any failures to create
	 * the SA are ignored).
	 */
	void (*abort)(child_create_t *this);
};

/**
 * Create a new child_create task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param config		child_cfg if task initiator, NULL if responder
 * @param rekey			whether we do a rekey or not
 * @param tsi			source of triggering packet, or NULL
 * @param tsr			destination of triggering packet, or NULL
 * @param seq			optional sequence number of triggering acquire, or 0
 * @return				child_create task to handle by the task_manager
 */
child_create_t *child_create_create(ike_sa_t *ike_sa,
									child_cfg_t *config, bool rekey,
									traffic_selector_t *tsi,
									traffic_selector_t *tsr, uint32_t seq);

#endif /** CHILD_CREATE_H_ @}*/
