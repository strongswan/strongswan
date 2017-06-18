/*
 * Copyright (C) 2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup sw_collector_db_t sw_collector_db
 * @{ @ingroup imc_swima
 */

#ifndef SW_COLLECTOR_DB_H_
#define SW_COLLECTOR_DB_H_

#include <library.h>

typedef struct sw_collector_db_t sw_collector_db_t;

/**
 * Software collector database object
 */
struct sw_collector_db_t {

	/**
	 * Add event to database
	 *
	 * @param timestamp		Timestamp in 20 octet RFC 3339 format
	 * @return				Primary key pointing to event ID or 0 if failed
	 */
	uint32_t (*add_event)(sw_collector_db_t *this, char *timestamp);

	/**
	 * Get last event, zero EID if none exists
	 *
	 * @param eid			Primary key pointing to last event
	 * @param epoch			Epoch
	 * @param last_time		Timestamp in 20 octet RFC 3339 format of last event
	 * @return				
	 */
	bool (*get_last_event)(sw_collector_db_t *this, uint32_t *eid,
							   uint32_t *epoch, char **last_time);

	/**
	 * Add software identifier event to database
	 *
	 * @param eid			Foreign key pointing to an event ID
	 * @param sw_id			Foreign key pointing to a software identifier
	 * @param action		1 for CREATION, 2 for deletion
	 * @return				TRUE if successful
	 */
	bool (*add_sw_event)(sw_collector_db_t *this, uint32_t eid, uint32_t sw_id,
						 uint8_t action);

	/**
	 * Get software_identifier, creating one if it doesn't exist yet
	 *
	 * @param package		Software package
	 * @param version		Version of software package
	 * @param name			Software identifier
	 * @param source		Source ID of the software collector
	 * @param installed		Installation status to be set, TRUE if installed
	 * @param check			Check if SW ID is already installed
	 * @return				Primary key pointing to SW ID or 0 if failed
	 */
	uint32_t (*get_sw_id)(sw_collector_db_t *this, char *package, char *version,
						  char *name, uint8_t source, bool installed, bool check);

	/**
	 * Get number of installed or deleted software identifiers
	 *
	 * @param installed_only	Count installed SW IDs if TRUE
	 * @return					Count
	 */
	uint32_t (*get_sw_id_count)(sw_collector_db_t *this, bool installed_only);

	/**
	 * Enumerate over all collected [installed] software identities
	 *
	 * @param installed_only	Return only installed software identities
	 * @return					Enumerator
	 */
	enumerator_t* (*create_sw_enumerator)(sw_collector_db_t *this,
										  bool installed_only);

	/**
	 * Destroy sw_collector_db_t object
	 */
	void (*destroy)(sw_collector_db_t *this);

};

/**
 * Create an sw_collector_db_t instance
 *
 * @param uri				database URI
 */
sw_collector_db_t* sw_collector_db_create(char *uri);

#endif /** SW_COLLECTOR_DB_H_ @}*/
