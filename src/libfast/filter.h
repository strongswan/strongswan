/*
 * Copyright (C) 2008 Martin Willi
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

/*
 * @defgroup filter filter
 * @{ @ingroup libfast
 */

#ifndef FILTER_H_
#define FILTER_H_

#include "request.h"
#include "context.h"
#include "controller.h"

typedef struct filter_t filter_t;

/**
 * Constructor function for a filter
 *
 * @param context		session specific context
 * @param param			user supplied param
 */
typedef filter_t *(*filter_constructor_t)(context_t* context, void *param);

/**
 * Filter interface, to be implemented by users filters.
 */
struct filter_t {

	/**
	 * Called before the controller handles the request.
	 *
	 * @param request		HTTP request
	 * @param p1			first parameter
	 * @param p2			second parameter
	 * @param p3			third parameter
	 * @param p4			forth parameter
	 * @param p5			fifth parameter
	 * @return				TRUE to continue request handling
	 */
	bool (*run)(filter_t *this, request_t *request,
				char *p0, char *p1, char *p2, char *p3, char *p4, char *p5);

	/**
	 * Destroy the filter instance.
	 */
	void (*destroy) (filter_t *this);
};

#endif /* FILTER_H_ @} */
