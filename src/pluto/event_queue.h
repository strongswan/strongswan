/*
 * Copyright (C) 2010 Tobias Brunner
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
 * @defgroup event_queue event_queue
 * @{ @ingroup pluto
 */

#ifndef EVENT_QUEUE_H_
#define EVENT_QUEUE_H_

typedef struct event_queue_t event_queue_t;

/**
 * The event queue facility can be used to synchronize thread-pool threads
 * with the pluto main thread.  That is, all queued callbacks are executed
 * asynchronously by the pluto main thread.
 */
struct event_queue_t {

	/**
	 * Returns the file descriptor used to notify the main thread.
	 *
	 * @return				fd to use in the main thread
	 */
	int (*get_event_fd) (event_queue_t *this);

	/**
	 * Handle all queued events.
	 */
	void (*handle) (event_queue_t *this);

	/**
	 * Add an event to the queue.
	 *
	 * @param callback		callback function to add to the queue
	 * @param data			data supplied to the callback function
	 * @param cleanup		optional cleanup function
	 */
	void (*queue) (event_queue_t *this, void (*callback)(void *data),
				   void *data, void (*cleanup)(void *data));

	/**
	 * Destroy this instance.
	 */
	void (*destroy) (event_queue_t *this);

};

/**
 * Create the event queue.
 *
 * @return					created object
 */
event_queue_t *event_queue_create();

#endif /** EVENT_QUEUE_H_ @}*/
