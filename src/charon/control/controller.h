/**
 * @file controller.h
 *
 * @brief Interface of controller_t.
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

#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <bus/bus.h>

/**
 * callback to log things triggered by controller
 *
 * @param param			echoed parameter supplied when function invoked
 * @param signal		type of signal
 * @param level			verbosity level if log
 * @param ike_sa		associated IKE_SA, if any
 * @param format		printf like format string
 * @param args			list of arguments to use for format
 * @return				FALSE to return from invoked function
 * @ingroup control
 */
typedef bool(*controller_cb_t)(void* param, signal_t signal, level_t level,
							   ike_sa_t* ike_sa, char* format, va_list args);

typedef struct controller_t controller_t;

/**
 * @brief The controller controls the daemon.
 *
 * The controller starts actions by creating jobs. It then tries to
 * evaluate the result of the operation by listening on the bus.
 * 
 * @b Constructors:
 * - controller_create()
 * 
 * @ingroup control
 */
struct controller_t {

	/**
	 * @brief Initiate a CHILD_SA, and if required, an IKE_SA.
	 *
	 * @param this			calling object
	 * @param peer_cfg		peer_cfg to use for IKE_SA setup
	 * @param child_cfg		child_cfg to set up CHILD_SA from
	 * @param cb			logging callback
	 * @param param			parameter to include in each call of cb
	 * @return
	 *						- SUCCESS, if CHILD_SA established
	 *						- FAILED, if setup failed
	 *						- NEED_MORE, if callback returned FALSE
	 */
	status_t (*initiate)(controller_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 controller_cb_t callback, void *param);
	
	/**
	 * @brief Destroy a controller_t instance.
	 * 
	 * @param this		controller_t objec to destroy
	 */
	void (*destroy) (controller_t *this);
};


/**
 * @brief Create a controller instance.
 * 
 * @return 			controller_t object
 * 
 * @ingroup control
 */
controller_t *controller_create();

#endif /* CONTROLLER_H_ */
