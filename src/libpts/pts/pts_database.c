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

METHOD(pts_database_t, create_file_meas_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product)
{
	enumerator_t *e;

	/* look for all entries belonging to a product in the files table */
	e = this->db->query(this->db,
				"SELECT f.id, f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.name = ? AND f.measurement = 1",
				DB_TEXT, product, DB_INT, DB_INT, DB_TEXT);
	return e;
}

METHOD(pts_database_t, create_file_meta_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product)
{
	enumerator_t *e;

	/* look for all entries belonging to a product in the files table */
	e = this->db->query(this->db,
				"SELECT f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.name = ? AND f.metadata = 1",
				DB_TEXT, product, DB_INT, DB_TEXT);
	return e;
}

METHOD(pts_database_t, create_comp_evid_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product)
{
	enumerator_t *e;

	/* look for all entries belonging to a product in the files table */
	e = this->db->query(this->db,
				"SELECT f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.name = ? AND f.component = 1",
				DB_TEXT, product, DB_INT, DB_TEXT);
	return e;
}


METHOD(pts_database_t, create_hash_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product, pts_meas_algorithms_t algo,
	int id, bool is_dir)
{
	enumerator_t *e;

	if (is_dir)
	{
		e = this->db->query(this->db,
				"SELECT f.path, fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE p.name = ? AND fh.directory = ? AND fh.algo = ? "
				"ORDER BY f.path",
				DB_TEXT, product, DB_INT, id, DB_INT, algo, DB_TEXT, DB_BLOB);
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT f.path, fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE p.name = ? AND fh.file = ? AND fh.algo = ?",
				DB_TEXT, product, DB_INT, id, DB_INT, algo, DB_TEXT, DB_BLOB);
	}
	return e;
}

METHOD(pts_database_t, create_comp_hash_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product,
	pts_meas_algorithms_t algo, char *comp_name)
{
	enumerator_t *e;
	
	e = this->db->query(this->db,
				"SELECT fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE p.name = ? AND f.path = ? AND fh.algo = ? ",
				DB_TEXT, product, DB_TEXT, comp_name, DB_INT, algo, DB_BLOB);

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
			.create_file_meas_enumerator = _create_file_meas_enumerator,
			.create_file_meta_enumerator = _create_file_meta_enumerator,
			.create_comp_evid_enumerator = _create_comp_evid_enumerator,
			.create_hash_enumerator = _create_hash_enumerator,
			.create_comp_hash_enumerator = _create_comp_hash_enumerator,
			.destroy = _destroy,
		},
		.db = lib->db->create(lib->db, uri),
	);

	if (!this->db)
	{
		DBG1(DBG_PTS,
			 "failed to connect to PTS file measurement database '%s'", uri);
		free(this);
		return NULL;
	}

	return &this->public;
}

