/**
 * @file configuration.h
 * 
 * @brief Class configuration_t. 
 * Object of this type represents a configuration for an IKE_SA
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

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include "types.h"

/**
 * @brief This class is used to represent an IKE_SA-configuration.
 * 
 */
typedef struct configuration_s configuration_t;

struct configuration_s { 	

	/**
	 * @brief Destroys a configuration_t object
	 * 
	 * @param this configuration_t object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (configuration_t *this);
};

/**
 * Creates an configuration_t-object
 * 
 * @return created configuration_t object
 */
configuration_t * configuration_create();

#endif /*CONFIGURATION_H_*/
