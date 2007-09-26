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
#include <library.h>

typedef struct request_t request_t;

/**
 * @brief A HTTP request, encapsulates FCGX_Request.
 *
 */
struct request_t {
	
	/**
	 * @brief Add a cookie to the reply (Set-Cookie header).
	 *
	 * @param name			name of the cookie to set
	 * @param value			value of the cookie
	 */
	void (*add_cookie)(request_t *this, char *name, char *value);
	
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
	 * @brief Get the base path of the application.
	 *
	 * @return			base path
	 */
	char* (*get_base)(request_t *this);
	
	/**
	 * @brief Get a post/get variable included in the request.
	 *
	 * @param name		name of the POST/GET variable
	 * @return			value, NULL if not found
	 */
	char* (*get_query_data)(request_t *this, char *name);
	
	/**
	 * @brief Redirect the client to another location.
	 *
	 * @param location		location to redirect to
	 */
	void (*redirect)(request_t *this, char *location);
	
	/**
	 * @brief Set a template value.
	 *
	 * @param key		key to set
	 * @param value		value to set key to
	 */
	void (*set)(request_t *this, char *key, char *value);
	
	/**
	 * @brief Set a template value using format strings.
	 *
	 * Format string is in the form "key=value", where printf like format
	 * substitution occurs over the whole string.
	 *
	 * @param format	printf like format string
	 * @param ...		variable argument list
	 */
	void (*setf)(request_t *this, char *format, ...);
	
	/**
	 * @brief Render a template.
	 *
	 * The render() function additionally sets a HDF variable "base"
	 * which points to the root of the web application and allows to point to
	 * other targets without to worry about path location.
	 *
	 * @param template	clearsilver template file location
	 * @return			rendered template string
	 */
	void (*render)(request_t *this, char *template);
	
	/**
	 * @brief Destroy the request_t.
	 */
	void (*destroy) (request_t *this);
};

/**
 * @brief Create a request from the fastcgi struct.
 *
 * @param request		the FCGI request
 * @param debug			no stripping, no compression, timing information
 */
request_t *request_create(FCGX_Request *request, bool debug);

#endif /* REQUEST_H_ */
