/**
 * @file dispatcher.h
 * 
 * @brief Interface of dispatcher_t.
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

#ifndef DISPATCHER_H_
#define DISPATCHER_H_

#include "controller.h"

typedef struct dispatcher_t dispatcher_t;

/**
 * @brief Dispatcher, accepts connections using multiple threads.
 *
 * The dispatcher creates a session for each client (using SID cookies). In
 * each session, a session context is created using the context constructor.
 * Each controller is instanciated in the session using the controller
 * constructor added with add_controller.
 */
struct dispatcher_t {
	
	/**
	 * @brief Register a controller to the dispatcher.
	 *
	 * The first controller added serves as default controller. Client's
	 * get redirected to it if no other controller matches.
	 *
	 * @param constructor	constructor function to the conntroller
	 * @param param			param to pass to constructor
	 */
	void (*add_controller)(dispatcher_t *this,
						   controller_constructor_t constructor, void *param);
	
	/**
	 * @brief Start with dispatching.
	 *
	 * It may be necessary to call per-thread initialization functions. 
	 * If init is not NULL, the handler is called right after thread
	 * creation (by the created thread) and the deinit function is called
	 * before the thread gets destroyed (again by the thread itself).
	 *
	 * @param thread		number of dispatching threads
	 * @param init			thread specific initialization function, or NULL
	 * @param init_param	param to pass to init function
	 * @param deinit		thread dpecific deinitialization function, or NULL
	 * @param deinit_param	param to pass to deinit function
	 */
	void (*run)(dispatcher_t *this, int threads,
				void(*init)(void *param), void *init_param,
				void(*deinit)(void *param), void *deinit_param);
	
	/**
	 * @brief Wait for a relevant signal action.
	 */
	void (*waitsignal)(dispatcher_t *this);
	
	/**
	 * @brief Destroy the dispatcher_t.
	 */
	void (*destroy) (dispatcher_t *this);
};

/**
 * @brief Create a dispatcher.
 *
 * The context constructor is invoked to create a session context for
 * each session.
 *
 * @param socket		FastCGI socket path, NULL for dynamic
 * @param timeout		session timeout
 * @param constructor	construction function for session context
 * @param param			parameter to supply to context constructor
 */
dispatcher_t *dispatcher_create(char *socket, int timeout,
								context_constructor_t constructor, void *param);

#endif /* DISPATCHER_H_ */
