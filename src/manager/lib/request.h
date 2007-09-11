/**
 * @file request.h
 * 
 * @brief Interface of request_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef REQUEST_H_
#define REQUEST_H_


#include <fcgiapp.h>

typedef struct request_t request_t;

/**
 * @brief A HTTP request, encapsulates FCGX_Request.
 *
 */
struct request_t {
	
	/**
	 * @brief Get a cookie the client sent in the request.
	 *
	 * @param name		name of the cookie
	 * @return			cookie value, NULL if no such cookie found
	 */
	char* (*get_cookie)(request_t *this, char *name);
	
	/**
	 * @brief Get the request path relative to the application.
	 *
	 * @return			path
	 */
	char* (*get_path)(request_t *this);
	
	/**
	 * @brief Get a post variable included in the request.
	 *
	 * @param name		name of the POST variable
	 * @return			value, NULL if not found
	 */
	char* (*get_post_data)(request_t *this, char *name);
	
	/**
	 * @brief Destroy the request_t.
	 */
	void (*destroy) (request_t *this);
};

/**
 * @brief Create a request from the fastcgi struct.
 *
 * @param request		the FCGI request
 */
request_t *request_create(FCGX_Request *request);

#endif /* REQUEST_H_ */
