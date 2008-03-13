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

/**
 * @defgroup fetcher_manager fetcher_manager
 * @{ @ingroup fetcher
 */

#ifndef FETCHER_MANAGER_H_
#define FETCHER_MANAGER_H_

typedef struct fetcher_manager_t fetcher_manager_t;

#include <fetcher/fetcher.h>

/**
 * Fetches from URIs using registerd fetcher_t instances.
 */
struct fetcher_manager_t {

	/**
	 * Fetch data from URI into chunk.
	 *
	 * The variable argument list contains fetcher_option_t's, followed
	 * by a option specific data argument.
	 *
	 * @param uri			URI to fetch from
	 * @param result		chunk which receives allocated data
	 * @param options		FETCH_END terminated fetcher_option_t arguments
	 * @return				status indicating result of fetch
	 */
	status_t (*fetch)(fetcher_manager_t *this, char *url, chunk_t *response, ...);

	/**
	 * Register a fetcher implementation.
	 *
	 * @param constructor	fetcher constructor function
	 * @param url			URL type this fetcher fetches, e.g. "http://"
	 */
	void (*add_fetcher)(fetcher_manager_t *this,
						fetcher_constructor_t constructor, char *url);
	
	/**
	 * Unregister a previously registered fetcher implementation.
	 *
	 * @param constructor	fetcher constructor function to unregister
	 */
	void (*remove_fetcher)(fetcher_manager_t *this, 
						   fetcher_constructor_t constructor);
	
	/**
     * Destroy a fetcher_manager instance.
     */
    void (*destroy)(fetcher_manager_t *this);
};

/**
 * Create a fetcher_manager instance.
 */
fetcher_manager_t *fetcher_manager_create();

#endif /* FETCHER_MANAGER_H_ @}*/
