/**
 * @file scheduler.h
 * 
 * @brief Interface of scheduler_t.
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

#ifndef SCHEDULER_H_
#define SCHEDULER_H_

#include <types.h>

typedef struct scheduler_t scheduler_t;

/**
 * @brief The scheduler thread is responsible for timed events.
 * 
 * The scheduler thread takes out jobs from the event-queue and adds them
 * to the job-queue.
 * 
 * Starts a thread which does the work, since event-queue is blocking.
 * 
 * @b Constructors:
 *  - scheduler_create()
 * 
 * @ingroup threads
 */
struct scheduler_t { 	

	/**
	 * @brief Destroys a scheduler object.
	 * 
	 * @param scheduler 	calling object
	 */
	void (*destroy) (scheduler_t *scheduler);
};

/**
 * @brief Create a scheduler with its associated thread.
 * 
 * The thread will start to get jobs form the event queue 
 * and adds them to the job queue.
 * 
 * @return 
 * 				- scheduler_t object
 * 				- NULL if thread could not be started
 * 
 * @ingroup threads
 */
scheduler_t * scheduler_create(void);

#endif /*SCHEDULER_H_*/
