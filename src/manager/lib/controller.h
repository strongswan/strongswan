/**
 * @file controller.h
 * 
 * @brief Interface controller_t.
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

#include "request.h"
#include "response.h"
#include "context.h"

typedef struct controller_t controller_t;

/**
 * @brief Controller action handle function
 *
 * @param request		http request
 * @param response		http response
 */
typedef void *(*controller_handler_t)(controller_t *this, request_t *request, response_t *response);

/**
 * @brief Constructor function for a controller
 *
 * @param context		session specific context
 * @param param			user supplied param
 */
typedef controller_t *(*controller_constructor_t)(context_t* context, void *param);

/**
 * @brief Controller interface, to be implemented by users controllers.
 *
 */
struct controller_t {
	
	/**
	 * @brief Get the name of the controller.
	 *
	 * @return				name of the controller
	 */
	char* (*get_name)(controller_t *this);
	
	/**
	 * @brief Get the controllers handler function for an action name.
	 *
	 * @param name			name of the action 
	 * @return				controllers handler
	 */
	controller_handler_t (*get_handler)(controller_t *this, char *name);
	
	/**
	 * @brief Destroy the controller instance.
	 */
	void (*destroy) (controller_t *this);
};

#endif /* CONTROLLER_H_ */
