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
 * @defgroup context context
 * @{ @ingroup libfast
 */

#ifndef CONTEXT_H_
#define CONTEXT_H_

typedef struct context_t context_t;

/**
 * Constructor function for a user specific context.
 */
typedef context_t *(*context_constructor_t)(void *param);

/**
 * User specific session context, to extend.
 */
struct context_t {

	/**
	 * Destroy the context_t.
	 */
	void (*destroy) (context_t *this);
};

#endif /** CONTEXT_H_ @}*/
