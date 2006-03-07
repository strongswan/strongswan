/**
 * @file starter_configuration_t.h
 *
 * @brief Interface of starter_configuration_t.
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

#ifndef STARTER_CONFIGURATION_H_
#define STARTER_CONFIGURATION_H_

#include <config/configuration.h>


typedef struct starter_configuration_t starter_configuration_t;

/**
 * @brief A config backend which uses the ipsec starter
 * from pluto, wich parses config files.
 * 
 * This configuration implementation opens a Whack-Socket
 * and waits for input from ipsec starter.
 * 
 * @b Constructors:
 * - starter_configuration_create()
 * 
 * @ingroup config
 */
struct starter_configuration_t { 

	/**
	 * Implements configuration_t interface
	 */
	configuration_t configuration_interface;
};

/**
 * @brief Creates an configuration using ipsec starter as input.
 * 
 * @return starter_configuration_t object
 * 
 * @ingroup config
 */
starter_configuration_t *starter_configuration_create();

#endif /*STARTER_CONFIGURATION_H_*/
