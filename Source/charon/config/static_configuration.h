/**
 * @file static_configuration_t.h
 * 
 * @brief Interface of static_configuration_t.
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

#ifndef STATIC_CONFIGURATION_H_
#define STATIC_CONFIGURATION_H_

#include <config/configuration.h>


typedef struct static_configuration_t static_configuration_t;

/**
 * @brief A static hardcoded config for testing purposes.
 * 
 * @b Constructors:
 * - static_configuration_create()
 * 
 * @ingroup config
 */
struct static_configuration_t { 

	/**
	 * Implements configuration_t interface
	 */
	configuration_t configuration_interface;
};

/**
 * @brief Creates an static configuration
 * 
 * @return static_configuration_t object
 * 
 * @ingroup config
 */
static_configuration_t *static_configuration_create();

#endif /*STATIC_CONFIGURATION_H_*/
