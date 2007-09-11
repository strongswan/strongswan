/**
 * @file context.h
 * 
 * @brief Interface of context_t.
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

#ifndef CONTEXT_H_
#define CONTEXT_H_

typedef struct context_t context_t;

/**
 * @brief Constructor function for a context
 */
typedef context_t *(*context_constructor_t)(void *param);

/**
 * @brief Custom session context
 *
 */
struct context_t {
	
	/**
	 * @brief Destroy the context_t.
	 *
	 * @param this 			calling object
	 */
	void (*destroy) (context_t *this);
};

#endif /* CONTEXT_H_ */
