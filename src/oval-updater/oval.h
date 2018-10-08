/*
 * Copyright (C) 2018 Andreas Steffen
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
 * @defgroup oval oval
 * @{ @ingroup tnccs_11
 */

#ifndef OVAL_H_
#define OVAL_H_

typedef struct oval_t oval_t;

#include <library.h>

/**
 * OVAL vulnerability object
 */
struct oval_t {

	/**
	 * Add an OVAL logical criterion
	 *
	 @param tst				reference to OVAL test
	 @param ste             reference to OVAL status
	 @param obj				reference to OVAL object
	 @param obj_name		OVAL object name
	 @param obj_id			primary key of object in packages table
	 @param op				package version comparison operation
	 @param version			package version
	 */
	void (*add_criterion)(oval_t *this, char *tst, char* ste, char *obj,
						  char *obj_name, int obj_id, char *op, char *version);

	/**
	 * Enumerate over the complete criteria
	 *
	 @return				criterion enumerator
	 */
	enumerator_t* (*create_criterion_enumerator)(oval_t *this);

	/**
	 * Does OVAL vulnerability object contain at least one complete criterion?
	 *
	 @return				TRUE if there is at least one complete criterion
	 */
	bool (*is_complete)(oval_t *this);

	/**
	 * Print an oval_t object.
	 */
	void (*print)(oval_t *this);

	/**
	 * Destroys a oval_t object.
	 */
	void (*destroy)(oval_t *this);
};

/**
 * Create an OVAL vulnerability object
 *
 * @param cve				CVE number
 * @param description		vulnerability description
 */
oval_t* oval_create(char *cve, char* description);

#endif /** OVAL_H_ @}*/
