/*
 * Copyright (C) 2010 Tobias Brunner
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
 * @defgroup libhydra libhydra
 *
 * @defgroup attributes attributes
 * @ingroup libhydra
 *
 * @defgroup hplugins plugins
 * @ingroup libhydra
 *
 * @addtogroup libhydra
 * @{
 */

#ifndef HYDRA_H_
#define HYDRA_H_

typedef struct hydra_t hydra_t;

#include <attributes/attribute_manager.h>

#include <library.h>

/**
 * IKE Daemon support object.
 */
struct hydra_t {

	/**
	 * manager for payload attributes
	 */
	attribute_manager_t *attributes;

	/**
	 * name of the daemon that initialized the library
	 */
	const char *daemon;
};

/**
 * The single instance of hydra_t.
 *
 * Set between calls to libhydra_init() and libhydra_deinit() calls.
 */
extern hydra_t *hydra;

/**
 * Initialize libhydra.
 *
 * The daemon's name is used to load daemon-specific settings.
 *
 * @param daemon		name of the daemon that initializes the library
 * @return				FALSE if integrity check failed
 */
bool libhydra_init(const char *daemon);

/**
 * Deinitialize libhydra.
 */
void libhydra_deinit();

#endif /** HYDRA_H_ @}*/
