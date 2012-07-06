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
 * @defgroup session session
 * @{ @ingroup libfast
 */

#ifndef SESSION_H_
#define SESSION_H_

#include "request.h"
#include "controller.h"
#include "filter.h"

typedef struct session_t session_t;

/**
 * Session handling class, instanciated for each user session.
 */
struct session_t {

	/**
	 * Get the session ID of the session.
	 *
	 * @return				session ID
	 */
	char* (*get_sid)(session_t *this);

	/**
	 * Add a controller instance to the session.
	 *
	 * @param controller	controller to add
	 */
	void (*add_controller)(session_t *this, controller_t *controller);

	/**
	 * Add a filter instance to the session.
	 *
	 * @param filter		filter to add
	 */
	void (*add_filter)(session_t *this, filter_t *filter);

	/**
	 * Process a request in this session.
	 *
	 * @param request		request to process
	 */
	void (*process)(session_t *this, request_t *request);

	/**
	 * Destroy the session_t.
	 */
	void (*destroy) (session_t *this);
};

/**
 * Create a session new session.
 *
 * @param context		user defined session context instance
 * @return				client session, NULL on error
 */
session_t *session_create(context_t *context);

#endif /** SESSION_H_ @}*/
