/**
 * @file template.h
 * 
 * @brief Interface of template_t.
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

#ifndef TEMPLATE_H_
#define TEMPLATE_H_

#include "response.h"

typedef struct template_t template_t;

/**
 * @brief Template engine based on ClearSilver.
 *
 */
struct template_t {
	
	/**
	 * @brief Set a template value.
	 *
	 * @param key		key to set
	 * @param value		value to set key to
	 */
	void (*set)(template_t *this, char *key, char *value);
	
	/**
	 * @brief Set a template value using format strings.
	 *
	 * Format string is in the form "key=value", where printf like format
	 * substitution occurs over the whole string.
	 *
	 * @param format	printf like format string
	 * @param ...		variable argument list
	 */
	void (*setf)(template_t *this, char *format, ...);
	
	/**
	 * @brief Render a template to a response object.
	 *
	 * The render() function additionally sets a clearsilver variable "base"
	 * which points to the root of the web application and allows to point to
	 * other targets without to worry about path location.
	 *
	 * @param response	response to render to
	 * @return			rendered template string
	 */
	void (*render)(template_t *this, response_t *response);
	
	/**
	 * @brief Destroy the template_t.
	 */
	void (*destroy) (template_t *this);
};

/**
 * @brief Create a template from a file.
 *
 * @param file			template file
 */
template_t *template_create(char *file);

#endif /* TEMPLATE_H_ */
