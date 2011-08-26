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

/**
 * @defgroup controller_i controller
 * @{ @ingroup control
 */

#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <bus/bus.h>

/**
 * callback to log things triggered by controller.
 *
 * @param param			echoed parameter supplied when function invoked
 * @param group			debugging group
 * @param level			verbosity level if log
 * @param ike_sa		associated IKE_SA, if any
 * @param format		printf like format string
 * @param args			list of arguments to use for format
 * @return				FALSE to return from invoked function
 */
typedef bool(*controller_cb_t)(void* param, debug_t group, level_t level,
							   ike_sa_t* ike_sa, char* format, va_list args);

/**
 * Empty callback function for controller_t functions.
 *
 * If you want to do a synchronous call, but don't need a callback, pass
 * this function to the controllers methods.
 */
bool controller_cb_empty(void *param, debug_t group, level_t level,
						 ike_sa_t *ike_sa, char *format, va_list args);

typedef struct controller_t controller_t;

/**
 * The controller provides a simple interface to run actions.
 *
 * The controller starts actions by creating jobs. It then tries to
 * evaluate the result of the operation by listening on the bus.
 *
 * Passing NULL as callback to the managers function calls them asynchronously.
 * If a callback is specified, they are called synchronously. There is a default
 * callback "controller_cb_empty" if you want to call a function
 * synchronously, but don't need a callback.
 */
struct controller_t {

	/**
	 * Create an enumerator for all IKE_SAs.
	 *
	 * The enumerator blocks the IKE_SA manager until it gets destroyed. Do
	 * not call another interface/manager method while the enumerator is alive.
	 *
	 * @param wait			TRUE to wait for checked out SAs, FALSE to skip
	 * @return				enumerator, locks IKE_SA manager until destroyed
	 */
	enumerator_t* (*create_ike_sa_enumerator)(controller_t *this, bool wait);

	/**
	 * Initiate a CHILD_SA, and if required, an IKE_SA.
	 *
	 * The initiate() function is synchronous and thus blocks until the
	 * IKE_SA is established or failed. Because of this, the initiate() function
	 * contains a thread cancellation point.
	 *
	 * @param peer_cfg		peer_cfg to use for IKE_SA setup
	 * @param child_cfg		child_cfg to set up CHILD_SA from
	 * @param cb			logging callback
	 * @param param			parameter to include in each call of cb
	 * @param timeout		timeout in ms to wait for callbacks, 0 to disable
	 * @return
	 *						- SUCCESS, if CHILD_SA established
	 *						- FAILED, if setup failed
	 *						- NEED_MORE, if callback returned FALSE
	 *						- OUT_OF_RES if timed out
	 */
	status_t (*initiate)(controller_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 controller_cb_t callback, void *param, u_int timeout);

	/**
	 * Terminate an IKE_SA and all of its CHILD_SAs.
	 *
	 * The terminate() function is synchronous and thus blocks until the
	 * IKE_SA is properly deleted, or the delete timed out.
	 * The terminate() function contains a thread cancellation point.
	 *
	 * @param unique_id		unique id of the IKE_SA to terminate.
	 * @param cb			logging callback
	 * @param param			parameter to include in each call of cb
	 * @param timeout		timeout in ms to wait for callbacks, 0 to disable
	 * @return
	 *						- SUCCESS, if CHILD_SA terminated
	 *						- NOT_FOUND, if no such CHILD_SA found
	 *						- NEED_MORE, if callback returned FALSE
	 *						- OUT_OF_RES if timed out
	 */
	status_t (*terminate_ike)(controller_t *this, u_int32_t unique_id,
							  controller_cb_t callback, void *param,
							  u_int timeout);

	/**
	 * Terminate a CHILD_SA.
	 *
	 * @param reqid			reqid of the CHILD_SA to terminate
	 * @param cb			logging callback
	 * @param param			parameter to include in each call of cb
	 * @param timeout		timeout in ms to wait for callbacks, 0 to disable
	 * @return
	 *						- SUCCESS, if CHILD_SA terminated
	 *						- NOT_FOUND, if no such CHILD_SA found
	 *						- NEED_MORE, if callback returned FALSE
	 *						- OUT_OF_RES if timed out
	 */
	status_t (*terminate_child)(controller_t *this, u_int32_t reqid,
								controller_cb_t callback, void *param,
								u_int timeout);

	/**
	 * Destroy a controller_t instance.
	 */
	void (*destroy) (controller_t *this);
};


/**
 * Creates a controller instance.
 *
 * @return 			controller_t object
 */
controller_t *controller_create(void);

#endif /** CONTROLLER_H_ @}*/
