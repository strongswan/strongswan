/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include "pts_database.h"

#include <debug.h>
#include <crypto/hashers/hasher.h>


typedef struct private_pts_database_t private_pts_database_t;

/**
 * Private data of a pts_database_t object.
 *
 */
struct private_pts_database_t {

	/**
	 * Public pts_database_t interface.
	 */
	pts_database_t public;

	/**
	 * database instance
	 */
	database_t *db;

};

METHOD(pts_database_t, create_file_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product)
{
	enumerator_t *e;

	/* look for all entries belonging to a product in the files table */
	e = this->db->query(this->db,
				"SELECT f.id, f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.name = ?",
				DB_TEXT, product, DB_INT, DB_INT, DB_TEXT);
	return e;
}

METHOD(pts_database_t, is_directory, bool,
	private_pts_database_t *this, int id, bool *is_directory)
{
	enumerator_t *e;
	int is_dir;

	/* look for a entry in files table with matching id */
	e = this->db->query(this->db,
				"SELECT f.type FROM files AS f "
				"WHERE f.id = ?",
				DB_INT, id, DB_INT);

	if (!e)
	{
		DBG1(DBG_TNC, "database enumerator failed", id);
		return FALSE;
	}
	if (!e->enumerate(e, &is_dir))
	{
		e->destroy(e);
		DBG1(DBG_TNC, "file entry with given id:%d not found", id);
		return FALSE;
	}

	*is_directory = (is_dir == 1) ? TRUE : FALSE;
	return TRUE;
}


METHOD(pts_database_t, create_files_in_dir_enumerator, enumerator_t*,
	private_pts_database_t *this, int id)
{
	enumerator_t *e;

	/* look for all entries in file_hashes belonging to a same directory*/
	e = this->db->query(this->db,
				"SELECT DISTINCT f.path FROM files AS f "
				"JOIN file_hashes AS fh ON f.id = fh.file "
				"WHERE fh.directory = ?",
				DB_INT, id, DB_TEXT);
	return e;
}

METHOD(pts_database_t, create_file_meas_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product, int id, pts_meas_algorithms_t algorithm)
{
	enumerator_t *e;
	
	/* look for all entries belonging to a product and file in file_hashes table */
	e = this->db->query(this->db,
				"SELECT fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE p.name = ? AND f.id = ? AND fh.algo = ?",
				DB_TEXT, product, DB_INT, id, DB_INT, algorithm, DB_BLOB);
	return e;
}

METHOD(pts_database_t, create_dir_meas_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product, int id, char *file_name, pts_meas_algorithms_t algorithm)
{
	enumerator_t *e;

	/* look for all entries belonging to a product, file and directory in file_hashes table */
	e = this->db->query(this->db,
				"SELECT fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE f.path = ? AND p.name = ? AND fh.directory = ? AND fh.algo = ?",
				DB_TEXT, file_name, DB_TEXT, product, DB_INT, id, DB_INT, algorithm, DB_BLOB);
	return e;
}

METHOD(pts_database_t, destroy, void,
	private_pts_database_t *this)
{
	this->db->destroy(this->db);
	free(this);
}

/**
 * See header
 */
pts_database_t *pts_database_create(char *uri)
{
	private_pts_database_t *this;

	INIT(this,
		.public = {
			.create_file_enumerator = _create_file_enumerator,
			.is_directory = _is_directory,
			.create_files_in_dir_enumerator = _create_files_in_dir_enumerator,
			.create_file_meas_enumerator = _create_file_meas_enumerator,
			.create_dir_meas_enumerator = _create_dir_meas_enumerator,
			.destroy = _destroy,
		},
		.db = lib->db->create(lib->db, uri),
	);

	if (!this->db)
	{
		DBG1(DBG_TNC, "failed to connect to PTS file measurement database '%s'",
			 uri);
		free(this);
		return NULL;
	}

	return &this->public;
}

