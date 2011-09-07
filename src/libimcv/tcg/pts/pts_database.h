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
	* Get files to be measured by PTS
	*
	* @product				software product (os, vpn client, etc.)
	* @return				enumerator over all files matching a given release
	*/
	enumerator_t* (*create_file_enumerator)(pts_database_t *this, char *product);

	/**
	* Get Enumerator over files in a given directory with measurements
	*
	* @id					primary key in files table, directory column in file_hashes table
	* @return				enumerator over all measurements matching a given release
	*/
	enumerator_t* (*create_files_in_dir_enumerator)(pts_database_t *this, int id);

	/**
	* Get Hash measurement of a file in a folder with given id and hashing algorithm type
	*
	* @received_hash		measurement of a file to match with database entry
	* @product				software product (os, vpn client, etc.)
	* @id					primary key in files table
	* @file_name			path in files table, obligatory for the files in directory
	* @algorithm			measurement algorithm type
	* @is_dir				TRUE if file is requested as content in a directory
	* @return				enumerator over all measurements matching a given release
	*/
	bool (*check_measurement)(pts_database_t *this, chunk_t received_hash,
					char *product, int id, char *file_name, pts_meas_algorithms_t algorithm, bool is_dir);


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
