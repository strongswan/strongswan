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

#include "attest_db.h"

typedef struct private_attest_db_t private_attest_db_t;

/**
 * Private data of an attest_db_t object.
 */
struct private_attest_db_t {

	/**
	 * Public members of attest_db_state_t
	 */
	attest_db_t public;

	/**
	 * Software product to be queried
	 */
	char *product;

	/**
	 * Primary key of software product to be queried
	 */
	int pid;

	/**
	 * TRUE if product has been set
	 */
	bool product_set;

	/**
	 * Measurement file to be queried
	 */
	char *file;

	/**
	 * Primary key of measurement file to be queried
	 */
	int fid;

	/**
	 * TRUE if file has been set
	 */
	bool file_set;

	/**
	 * Directory containing the Measurement file to be queried
	 */
	char *dir;

	/**
	 * Primary key of the directory to be queried
	 */
	int did;

	/**
	 * TRUE if directory has been set
	 */
	bool dir_set;

	/**
	 * File measurement hash algorithm
	 */
	pts_meas_algorithms_t algo;

	/**
	 * Attestation database
	 */
	database_t *db;

};

METHOD(attest_db_t, set_product, bool,
	private_attest_db_t *this, char *product)
{
	enumerator_t *e;

	if (this->product_set)
	{
		printf("product has already been set\n");
		return FALSE;
	}
	this->product = strdup(product);

	e = this->db->query(this->db, "SELECT id FROM products WHERE name = ?",
						DB_TEXT, product, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->pid))
		{
			this->product_set = TRUE;
		}
		else
		{
			printf("product '%s' not found in database\n", product);
		}
		e->destroy(e);
	}
	return this->product_set;
}

METHOD(attest_db_t, set_pid, bool,
	private_attest_db_t *this, int pid)
{
	enumerator_t *e;
	char *product;

	if (this->product_set)
	{
		printf("product has already been set\n");
		return FALSE;
	}
	this->pid = pid;

	e = this->db->query(this->db, "SELECT name FROM products WHERE id = ?",
						DB_INT, pid, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &product))
		{
			this->product = strdup(product);
			this->product_set = TRUE;
		}
		else
		{
			printf("no product found with pid %d in database\n", pid);
		}
		e->destroy(e);
	}
	return this->product_set;
}

METHOD(attest_db_t, set_file, bool,
	private_attest_db_t *this, char *file)
{
	enumerator_t *e;

	if (this->file_set)
	{
		printf("file has already been set\n");
		return FALSE;
	}
	this->file = strdup(file);

	e = this->db->query(this->db, "SELECT id FROM files WHERE path = ?",
						DB_TEXT, file, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->fid))
		{
			this->file_set = TRUE;
		}
		else
		{
			printf("file '%s' not found in database\n", file);
		}
		e->destroy(e);
	}
	return this->file_set;
}

METHOD(attest_db_t, set_fid, bool,
	private_attest_db_t *this, int fid)
{
	enumerator_t *e;
	char *file;

	if (this->file_set)
	{
		printf("file has already been set\n");
		return FALSE;
	}
	this->fid = fid;

	e = this->db->query(this->db, "SELECT path FROM files WHERE id = ?",
						DB_INT, fid, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &file))
		{
			this->file = strdup(file);
			this->file_set = TRUE;
		}
		else
		{
			printf("no file found with fid %d\n", fid);
		}
		e->destroy(e);
	}
	return this->file_set;
}

METHOD(attest_db_t, set_directory, bool,
	private_attest_db_t *this, char *dir)
{
	enumerator_t *e;

	if (this->dir_set)
	{
		printf("directory has already been set\n");
		return FALSE;
	}
	free(this->dir);
	this->dir = strdup(dir);

	e = this->db->query(this->db, "SELECT id FROM files WHERE path = ?",
						DB_TEXT, dir, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->did))
		{
			this->dir_set = TRUE;
		}
		else
		{
			printf("directory '%s' not found in database\n", dir);
		}
		e->destroy(e);
	}
	return this->dir_set;
}

METHOD(attest_db_t, set_did, bool,
	private_attest_db_t *this, int did)
{
	enumerator_t *e;
	char *dir;

	if (this->dir_set)
	{
		printf("directory has already been set\n");
		return FALSE;
	}
	this->did = did;

	e = this->db->query(this->db, "SELECT path FROM files WHERE id = ?",
						DB_INT, did, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &dir))
		{
			free(this->dir);
			this->dir = strdup(dir);
			this->dir_set = TRUE;
		}
		else
		{
			printf("no directory found with did %d\n", did);
		}
		e->destroy(e);
	}
	return this->dir_set;
}

METHOD(attest_db_t, set_algo, void,
	private_attest_db_t *this, pts_meas_algorithms_t algo)
{
	this->algo = algo;
}

METHOD(attest_db_t, list_files, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	char *file;
	int fid, is_dir, count = 0;

	if (this->pid)
	{
		e = this->db->query(this->db,
				"SELECT f.id, f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"WHERE pf.product = ? ORDER BY f.path",
				DB_INT, this->pid, DB_INT, DB_INT, DB_TEXT);
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT id, type, path FROM files "
				"ORDER BY path",
				DB_INT, DB_INT, DB_TEXT);
	}
	if (e)
	{
		while (e->enumerate(e, &fid, &is_dir, &file))
		{
			printf("%3d: %s %s\n", fid, is_dir ? "d":" ", file);
			count++;
		}
		e->destroy(e);

		printf("%d file%s found", count, (count == 1) ? "" : "s");
		if (this->product)
		{
			printf(" for product '%s'", this->product);
		}
		printf("\n");
	}
}

METHOD(attest_db_t, list_products, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	char *product;
	int pid, count = 0;

	if (this->fid)
	{
		e = this->db->query(this->db,
				"SELECT p.id, p.name FROM products AS p "
				"JOIN product_file AS pf ON p.id = pf.product "
				"WHERE pf.file = ? ORDER BY p.name",
				DB_INT, this->fid, DB_INT, DB_TEXT);
	}
	else
	{
		e = this->db->query(this->db, "SELECT id, name FROM products "
				"ORDER BY name",
				DB_INT, DB_TEXT);
	}
	if (e)
	{
		while (e->enumerate(e, &pid, &product))
		{
			printf("%3d:  %s\n", pid, product);
			count++;
		}
		e->destroy(e);

		printf("%d product%s found", count, (count == 1) ? "" : "s");
		if (this->file)
		{
			printf(" for file '%s'", this->file);
		}
		printf("\n");
	}
}

/**
 * get the directory if there is one from the files tables
 */
static void get_directory(private_attest_db_t *this, int did, char **directory)
{
	enumerator_t *e;
	char *dir;

	free(*directory);
	*directory = strdup("");

	if (did)
	{
		e = this->db->query(this->db,
				"SELECT path from files WHERE id = ?",
				DB_INT, did, DB_TEXT);
		if (e)
		{
			if (e->enumerate(e, &dir))
			{
				free(*directory);
				*directory = strdup(dir);
			}
			e->destroy(e);
		}
	}
}

static bool slash(char *directory, char *file)
{
	return *file != '/' && directory[max(0, strlen(directory)-1)] != '/';
}

METHOD(attest_db_t, list_hashes, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	chunk_t hash;
	char *file, *dir, *product;
	int fid, fid_old = 0, did, did_old = 0, count = 0;

	dir = strdup("");

	if (this->pid && this->fid)
	{
		e = this->db->query(this->db,
				"SELECT hash FROM file_hashes "
				"WHERE algo = ? AND file = ? AND directory = ? AND product = ?",
				DB_INT, this->algo, DB_INT, this->fid, DB_INT, this->did,
				DB_INT, this->pid, DB_BLOB);
		if (e)
		{
			while (e->enumerate(e, &hash))
			{
				if (this->fid != fid_old)
				{
					printf("%3d: %s%s%s\n", this->fid, this->dir,
						   slash(this->dir, this->file) ? "/" : "", this->file);
					fid_old = this->fid;
				}
				printf("     %#B\n", &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for product '%s'\n", count,
				   hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", this->product);
		}
	}
	else if (this->pid)
	{
		e = this->db->query(this->db,
				"SELECT f.id, f. f.path, fh.hash, fh.directory "
				"FROM file_hashes AS fh "
				"JOIN files AS f ON f.id = fh.file "
				"WHERE fh.algo = ? AND fh.product = ? "
				"ORDER BY fh.directory, f.path",
				DB_INT, this->algo, DB_INT, this->pid,
				DB_INT, DB_TEXT, DB_BLOB, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &fid,  &file, &hash, &did))
			{
				if (fid != fid_old || did != did_old)
				{
					if (did != did_old)
					{
						get_directory(this, did, &dir);
					}
					printf("%3d: %s%s%s\n", fid,
						   dir, slash(dir, file) ? "/" : "", file);
					fid_old = fid;
					did_old = did;
				}
				printf("     %#B\n", &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for product '%s'\n", count,
				   hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", this->product);
		}
	}
	else if (this->fid)
	{
		e = this->db->query(this->db,
				"SELECT p.name, fh.hash, fh.directory "
				"FROM file_hashes AS fh "
				"JOIN products AS p ON p.id = fh.product "
				"WHERE fh.algo = ? AND fh.file = ? AND fh.directory = ?"
				"ORDER BY p.name",
				DB_INT, this->algo, DB_INT, this->fid, DB_INT, this->did,
				DB_TEXT, DB_BLOB, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &product, &hash, &did))
			{
				printf("%#B '%s'\n", &hash, product);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for file '%s%s%s'\n",
				   count, hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", this->dir,
				   slash(this->dir, this->file) ? "/" : "", this->file);
		}
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT f.id, f.path, p.name, fh.hash, fh.directory "
				"FROM file_hashes AS fh "
				"JOIN files AS f ON f.id = fh.file "
				"JOIN products AS p ON p.id = fh.product "
				"WHERE fh.algo = ? "
				"ORDER BY fh.directory, f.path, p.name",
				DB_INT, this->algo,
				DB_INT, DB_TEXT, DB_TEXT, DB_BLOB, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &fid, &file, &product, &hash, &did))
			{
				if (fid != fid_old || did != did_old)
				{
					if (did != did_old)
					{
						get_directory(this, did, &dir);
						did_old = did;
					}
					printf("%3d: %s%s%s\n", fid,
						   dir, slash(dir, file) ? "/" : "", file);
					fid_old = fid;
				}
				printf("     %#B '%s'\n", &hash, product);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found\n", count, hash_algorithm_names,
				   pts_meas_algo_to_hash(this->algo), (count == 1) ? "" : "s");
		}
	}
	free(dir);
}

METHOD(attest_db_t, destroy, void,
	private_attest_db_t *this)
{
	DESTROY_IF(this->db);
	free(this->product);
	free(this->file);
	free(this->dir);
	free(this);
}

/**
 * Described in header.
 */
attest_db_t *attest_db_create(char *uri)
{
	private_attest_db_t *this;

	INIT(this,
		.public = {
			.set_product = _set_product,
			.set_pid = _set_pid,
			.set_file = _set_file,
			.set_fid = _set_fid,
			.set_directory = _set_directory,
			.set_did = _set_did,
			.set_algo = _set_algo,
			.list_products = _list_products,
			.list_files = _list_files,
			.list_hashes = _list_hashes,
			.destroy = _destroy,
		},
		.dir = strdup(""),
		.algo = PTS_MEAS_ALGO_SHA256,
		.db = lib->db->create(lib->db, uri),
	);

	if (!this->db)
	{
		fprintf(stderr, "opening database failed.\n");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
