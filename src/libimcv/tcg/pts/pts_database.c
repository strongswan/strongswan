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

METHOD(pts_database_t, create_meas_enumerator, enumerator_t*,
	private_pts_database_t *this, char *product, int id, pts_meas_algorithms_t algorithm)
{
	enumerator_t *e;
	int algo = 0;
	
	switch(algorithm)
	{
		case PTS_MEAS_ALGO_SHA1:
			algo = 32768;
			break;
		case PTS_MEAS_ALGO_SHA256:
			algo = 16384;
			break;
		case PTS_MEAS_ALGO_SHA384:
			algo = 8192;
			break;
	}
	
	/* look for all entries belonging to a product and file in file_hashes table */
	e = this->db->query(this->db,
				"SELECT fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON fh.file = f.id "
				"JOIN products AS p ON fh.product = p.id "
				"WHERE p.name = ? AND f.id = ? AND fh.algo = ?",
				DB_TEXT, product, DB_INT, id, DB_INT, algo, DB_BLOB);
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
			.create_meas_enumerator = _create_meas_enumerator,
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

