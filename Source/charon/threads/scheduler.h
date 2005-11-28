/**
 * @file scheduler.h
 * 
 * @brief Interface of scheduler_t.
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

#ifndef SCHEDULER_H_
#define SCHEDULER_H_

#include <types.h>

typedef struct scheduler_t scheduler_t;

/**
 * @brief The scheduler, looks for timed events in event-queue and adds them
 * to the job-queue.
 * 
 * Starts a thread which does the work, since event-queue is blocking.
 * 
 * @ingroup threads
 */
struct scheduler_t { 	

	/**
	 * @brief Destroys a scheduler object.
	 * 
	 * @param scheduler 	scheduler object
	 */
	void (*destroy) (scheduler_t *scheduler);
};

/**
 * @brief Create a scheduler with its thread.
 * 
 * The thread will start to get jobs form the event queue 
 * and adds them to the job queue.
 * 
 * @return 
 * 				- the created scheduler_t instance, or
 * 				- NULL if thread could not be started
 * 
 * @ingroup threads
 */
scheduler_t * scheduler_create();

#endif /*SCHEDULER_H_*/
