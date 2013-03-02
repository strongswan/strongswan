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
 * @defgroup controller controller
 * @{ @ingroup libfast
 */

#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include "request.h"
#include "context.h"

typedef struct controller_t controller_t;

/**
 * Constructor function for a controller.
 *
 * @param context		session specific context, implements context_t
 * @param param			user supplied param, as registered to the dispatcher
 */
typedef controller_t *(*controller_constructor_t)(context_t* context, void *param);

/**
 * Controller interface, to be implemented by users controllers.
 *
 * Controller instances get created per session, so each session has an
 * associated set of private controller instances.
 * The controller handle function is called for each incoming request.
 */
struct controller_t {

	/**
	 * Get the name of the controller.
	 *
	 * @return				name of the controller
	 */
	char* (*get_name)(controller_t *this);

	/**
	 * Handle a HTTP request for that controller.
	 *
	 * Request URLs are parsed in the form
	 * controller_name/p1/p2/p3/p4/p5 with a maximum of 5 parameters. Each
	 * parameter not found in the request URL is set to NULL.
	 *
	 * @param request		HTTP request
	 * @param p1			first parameter
	 * @param p2			second parameter
	 * @param p3			third parameter
	 * @param p4			forth parameter
	 * @param p5			fifth parameter
	 * @return
	 */
	void (*handle)(controller_t *this, request_t *request,
				   char *p1, char *p2, char *p3, char *p4, char *p5);

	/**
	 * Destroy the controller instance.
	 */
	void (*destroy) (controller_t *this);
};

#endif /** CONTROLLER_H_ @}*/
