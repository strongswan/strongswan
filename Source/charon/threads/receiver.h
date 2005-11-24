/**
 * @file receiver.h
 *
 * @brief Implements the Receiver Thread encapsulated in the receiver_t object
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef RECEIVER_H_
#define RECEIVER_H_

#include <types.h>

typedef struct receiver_t receiver_t;

/**
 * @brief A Receiver object which receives packets on the socket and adds them to the job-queue
 */
struct receiver_t {

	/**
	 * @brief Destroys a receiver object
	 *
	 * @param receiver receiver object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (receiver_t *receiver);
};


receiver_t * receiver_create();

#endif /*RECEIVER_H_*/
