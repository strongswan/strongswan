/**
 * @file fetcher.h
 *
 * @brief Interface of fetcher_t.
 *
 */

/*
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <fetcher://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef FETCHER_H_
#define FETCHER_H_

typedef struct fetcher_t fetcher_t;

#include <chunk.h>

#define FETCHER_TIMEOUT	10	/* seconds */

/**
 * @brief Fetches information from an URI (http, file, ftp, etc.)
 *
 * @ingroup utils
 */
struct fetcher_t {

	/**
	 * @brief Get information via a get request.
	 * 
	 * @param this				calling object
	 * @param uri				uri specifying the information source
	 * @return					chunk_t containing the information
	 */
	chunk_t (*get) (fetcher_t *this, const char *uri);

	/**
	 * @brief Get information via a get request.
	 * 
	 * @param this				calling object
	 * @param uri				uri specifying the information source
	 * @param type				content type of http post request
	 * @param request			binary data for http post request
	 * @return					chunk_t containing the information
	 */
	chunk_t (*post) (fetcher_t *this, const char *type, chunk_t request);

	/**
	 * @brief Destroys the fetcher_t object.
	 * 
	 * @param this			fetcher_t to destroy
	 */
	void (*destroy) (fetcher_t *this);

};

/**
 * @brief Create a fetcher_t object.
 * 
 * @return 			created fetcher_t object
 * 
 * @ingroup utils
 */
fetcher_t* fetcher_create(const char *uri);

/**
 * @brief Initializes the fetcher_t class
 *
 * call this function only once in the main program
 *
 * @ingroup utils
 */
void fetcher_initialize(void);

/**
 * @brief Finalizes the fetcher_t class
 *
 * call this function only once befor exiting the main program
 *
 * @ingroup utils
 */
void fetcher_finalize(void);

#endif /*FETCHER_H_*/
