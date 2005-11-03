/**
 * @file worker.h
 * 
 * @brief worker thread, gets jobs form job_queue
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

#ifndef THREAD_POOL_H_
#define THREAD_POOL_H_

#include <stdlib.h>

#include "types.h"

/**
 * A thread_pool contains a pool of threads processing the job queue
 */
typedef struct thread_pool_s thread_pool_t;

struct thread_pool_s {
	/**
	 * Stops process after processing current job
	 * 
	 * @param thread_pool	thread_pool_t object
	 * @param size [out]	size of pool				
	 * @return				SUCCESS		Thread flagged for termination
	 */
	status_t (*get_pool_size) (thread_pool_t *thread_pool, size_t *pool_size);
	/**
	 * Destroy pool, blocks until threads cleanly terminated
	 * 
	 * @param thread_pool	thread_pool_t object
	 * @return				SUCCESS
	 */
	status_t (*destroy) (thread_pool_t *thread_pool);
};

/**
 * @brief Create the thread pool using using pool_size of threads
 * 
 * @param			pool_size	desired pool size
 * @return 			NULL		when no thread could be created
 * 					thread_pool	when one ore more threads could be created
 */
thread_pool_t *thread_pool_create(size_t pool_size);


#endif /*THREAD_POOL_H_*/
