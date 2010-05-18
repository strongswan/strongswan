/*
 * Copyright (C) 2010 Andreas Steffen
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
 * @defgroup pluto pluto
 *
 * @defgroup xauth xauth
 * @ingroup pluto
 *
 * @defgroup pplugins plugins
 * @ingroup pluto
 *
 * @addtogroup pluto
 * @{
 */

#ifndef PLUTO_H_
#define PLUTO_H_

typedef struct pluto_t pluto_t;

#include <xauth/xauth_manager.h>

#include <library.h>

/**
 * Pluto daemon support object.
 */
struct pluto_t {

	/**
	 * manager for payload attributes
	 */
	xauth_manager_t *xauth;
};

/**
 * The single instance of pluto_t.
 *
 * Set between calls to pluto_init() and pluto_deinit() calls.
 */
extern pluto_t *pluto;

/**
 * Initialize pluto.
 *
 * @return				FALSE if integrity check failed
 */
bool pluto_init(char *file);

/**
 * Deinitialize pluto.
 */
void pluto_deinit(void);

#endif /** PLUTO_H_ @}*/

