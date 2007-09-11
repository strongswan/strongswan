/**
 * @file response.h
 * 
 * @brief Interface of response_t.
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

#ifndef RESPONSE_H_
#define RESPONSE_H_


#include <fcgiapp.h>

typedef struct response_t response_t;

/**
 * @brief A HTTP response, wraps response functionality around FCGX_Request.
 *
 */
struct response_t {
	
	/**
	 * @brief Write a string to the client.
	 *
	 * @param str			string to write
	 */
	void (*print)(response_t *this, char *str);
	
	/**
	 * @brief Write a printf like format string to client.
	 *
	 * @param format		printf like format string
	 * @param ...			variable argument list
	 */
	void (*printf)(response_t *this, char *format, ...);
	
	/**
	 * @brief Add a custom header to the response.
	 *
	 * @param name			name of the header
	 * @param value			value of the header
	 */
	void (*add_header)(response_t *this, char *name, char *value);
	
	/**
	 * @brief Set the content type (Content-Type header).
	 *
	 * @param type			content type (e.g. text/html)
	 */
	void (*set_content_type)(response_t *this, char *type);
	
	/**
	 * @brief Add a cookie to the response (Set-Cookie header).
	 *
	 * @param name			name of the cookie to set
	 * @param value			value of the cookie
	 */
	void (*add_cookie)(response_t *this, char *name, char *value);
	
	/**
	 * @brief Redirect the client to another location.
	 *
	 * @param location		location to redirect to
	 */
	void (*redirect)(response_t *this, char *location);
		
	/**
	 * @brief Destroy a response_t.
	 */
	void (*destroy) (response_t *this);
};

/**
 * @brief Create a response.
 *
 * @param request		the FCGI request structure
 */
response_t *response_create(FCGX_Request *request);

#endif /* RESPONSE_H_ */
