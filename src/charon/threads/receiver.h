/**
 * @file receiver.h
 *
 * @brief Interface of receiver_t.
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

#ifndef RECEIVER_H_
#define RECEIVER_H_

#include <types.h>


typedef struct receiver_t receiver_t;

/**
 * @brief Receives packets from the socket and adds them to the job queue.
 * 
 * The receiver starts a thread, wich reads on the blocking socket. If 
 * data is available, a packet_t object is created , wrapped
 * in an incoming_packet_job_t and added to the job queue.
 * 
 * @b Constructors:
 *  - receiver_create()
 * 
 * @ingroup threads
 */
struct receiver_t {

	/**
	 * @brief Destroys a receiver_t object.
	 *
	 * @param receiver 	receiver object
	 */
	void (*destroy) (receiver_t *receiver);
};

/**
 * @brief Create a receiver_t object.
 * 
 * The receiver thread will start working, get data
 * from the socket and add those packets to the job queue.
 * 
 * @return
 * 					- receiver_t object
 * 					- NULL of thread could not be started
 * 
 * @ingroup threads
 */
receiver_t * receiver_create(void);

#endif /*RECEIVER_H_*/
