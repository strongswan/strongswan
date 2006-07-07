/**
 * @file sender.h
 *
 * @brief Interface of sender_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef SENDER_H_
#define SENDER_H_

#include <types.h>

typedef struct sender_t sender_t;

/**
 * @brief Thread responsible for sending packets over the socket.
 * 
 * @b Constructors:
 *  - sender_create()
 * 
 * @ingroup threads
 */
struct sender_t {

	/**
	 * @brief Destroys a sender object.
	 *
	 * @param sender 	calling object
	 */
	void (*destroy) (sender_t *sender);
};


/**
 * @brief Create the sender thread.
 * 
 * The thread will start to work, getting packets
 * from the send queue and sends them out.
 * 
 * @return
 * 					- sender_t object
 * 					- NULL of thread could not be started
 * 
 * @ingroup threads
 */
sender_t * sender_create(void);

#endif /*SENDER_H_*/
