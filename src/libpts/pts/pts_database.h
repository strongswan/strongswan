/*
 * Copyright (C) 2011 Andreas Steffen
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
 * @defgroup pts_database pts_database
 * @{ @ingroup pts
 */

#ifndef PTS_DATABASE_H_
#define PTS_DATABASE_H_

typedef struct pts_database_t pts_database_t;

#include "pts_meas_algo.h"
#include <library.h>

/**
 * Class implementing the PTS File Measurement database
 *
 */
struct pts_database_t {

	/**
	* Get files/directories to be measured by PTS
	*
	* @param product		software product (os, vpn client, etc.)
	* @return				enumerator over all matching files/directories
	*/
	enumerator_t* (*create_file_enumerator)(pts_database_t *this, char *product);

	/**
	* Get files/directories to request metadata of
	*
	* @param product		software product (os, vpn client, etc.)
	* @return				enumerator over all matching files/directories
	*/
	enumerator_t* (*create_file_meta_enumerator)(pts_database_t *this, char *product);

	/**
	* Get stored measurement hash for single file or directory entries
	*
	* @param product		software product (os, vpn client, etc.)
	* @param algo			hash algorithm used for measurement
	* @param id				primary key of measured file/directory
	* @param is_dir			TRUE if directory was measured
	* @return				enumerator over all matching measurement hashes
	*/
	enumerator_t* (*create_hash_enumerator)(pts_database_t *this, char *product,
											pts_meas_algorithms_t algo,
											int id, bool is_dir);

	/**
	* Destroys a pts_database_t object.
	*/
	void (*destroy)(pts_database_t *this);

};

/**
 * Creates an pts_database_t object
 *
 * @param uri				database uri
 */
pts_database_t* pts_database_create(char *uri);

#endif /** PTS_DATABASE_H_ @}*/
