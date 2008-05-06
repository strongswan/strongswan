/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup med_db_config_i med_db_config
 * @{ @ingroup med_db
 */

#ifndef MED_DB_CONFIG_H_
#define MED_DB_CONFIG_H_

#include <config/backend.h>
#include <database/database.h>

typedef struct med_db_config_t med_db_config_t;

/**
 * Mediation server configuration backend.
 */
struct med_db_config_t {

	/**
	 * Implements backend_t interface
	 */
	backend_t backend;
	
	/**
	 * Destroy the backend.
	 */
	void (*destroy)(med_db_config_t *this);	
};

/**
 * Create a med_db_config backend instance.
 *
 * @param db		underlying database
 * @return			backend instance
 */
med_db_config_t *med_db_config_create(database_t *db);

#endif /* MED_DB_CONFIG_H_ @}*/
