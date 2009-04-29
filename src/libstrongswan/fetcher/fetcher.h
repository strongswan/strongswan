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
 * @defgroup fetcheri fetcher
 * @{ @ingroup fetcher
 */

#ifndef FETCHER_H_
#define FETCHER_H_

typedef struct fetcher_t fetcher_t;
typedef enum fetcher_option_t fetcher_option_t;

#include <stdarg.h>

#include <library.h>

/**
 * Fetching options to use for fetcher_t.fetch() call.
 */
enum fetcher_option_t {

	/** 
	 * Data to include in fetch request, e.g. on a HTTP post.
	 * Additional argument is a chunk_t
	 */
	FETCH_REQUEST_DATA,
	
	/** 
	 * Mime-Type of data included in FETCH_REQUEST_DATA.
	 * Additional argument is a char*.
	 */
	FETCH_REQUEST_TYPE,
	
	/** 
	 * HTTP header to be sent with with the fetch request.
	 * Additional argument is a char*.
	 */
	FETCH_REQUEST_HEADER,

	/** 
	 * Use HTTP Version 1.0 instead of 1.1.
	 * No additional argument is needed.
	 */
	FETCH_HTTP_VERSION_1_0,

	/** 
	 * Timeout to use for fetch, in seconds.
	 * Additional argument is u_int
	 */
	FETCH_TIMEOUT,
	
	/**
	 * end of fetching options
	 */
	FETCH_END,
};

/**
 * Constructor function which creates fetcher instances.
 *
 * @return			fetcher instance
 */
typedef fetcher_t* (*fetcher_constructor_t)();

/**
 * Fetcher interface, an implementation fetches data from an URL.
 */
struct fetcher_t {

	/**
	 * Fetch data from URI into chunk.
	 *
	 * The fetcher returns NOT_SUPPORTED to indicate that it is uncappable
	 * to handle such URLs. Other return values indicate a failure, and
	 * fetching of that URL gets cancelled.
	 *
	 * @param uri		URI to fetch from
	 * @param result	chunk which receives allocated data
	 * @return
	 *					- SUCCESS if fetch was successful
	 * 					- NOT_SUPPORTED if fetcher does not support such URLs
	 *					- FAILED, NOT_FOUND, PARSE_ERROR on failure
	 */
	status_t (*fetch)(fetcher_t *this, char *uri, chunk_t *result);
	
	/**
	 * Set a fetcher option, as defined in fetcher_option_t.
	 *
	 * Arguments passed to options must stay in memory until fetch() returns.
	 *
	 * @param option	option to set
	 * @param ...		variable argument(s) to option
	 * @return			TRUE if option supported, FALSE otherwise
	 */
	bool (*set_option)(fetcher_t *this, fetcher_option_t option, ...);
	
	/**
	 * Destroy the fetcher instance.
	 */
	void (*destroy)(fetcher_t *this);	
};

#endif /** FETCHER_H_ @}*/
