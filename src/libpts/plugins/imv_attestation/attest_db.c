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

#include "libpts.h"
#include "pts/components/pts_comp_func_name.h"

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
	 * Component Functional Name to be queried
	 */
	pts_comp_func_name_t *cfn;

	/**
	 * Primary key of the Component Functional Name to be queried
	 */
	int cid;

	/**
	 * TRUE if Component Functional Name has been set
	 */
	bool comp_set;

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
	 *  AIK to be queried
	 */
	chunk_t key;

	/**
	 * Primary key of the AIK to be queried
	 */
	int kid;

	/**
	 * TRUE if AIK has been set
	 */
	bool key_set;

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
	 * File measurement hash algorithm
	 */
	pts_meas_algorithms_t algo;

	/**
	 * Optional owner (user/host name)
	 */
	char *owner;

	/**
	 * Attestation database
	 */
	database_t *db;

};

char* print_cfn(pts_comp_func_name_t *cfn)
{
	static char buf[BUF_LEN];
	char flags[8];
	int type, vid, name, qualifier, n;
	enum_name_t *names, *types;

	vid = cfn->get_vendor_id(cfn),
	name = cfn->get_name(cfn);
	qualifier = cfn->get_qualifier(cfn);
	n = snprintf(buf, BUF_LEN, "0x%06x/0x%08x-0x%02x", vid, name, qualifier);

	names = pts_components->get_comp_func_names(pts_components, vid);
	types = pts_components->get_qualifier_type_names(pts_components, vid);
	type =  pts_components->get_qualifier(pts_components, cfn, flags);
	if (names && types)
	{
		n = snprintf(buf + n, BUF_LEN - n, " %N/%N [%s] %N",
					 pen_names, vid, names, name, flags, types, type);
	}
	return buf;
}

METHOD(attest_db_t, set_component, bool,
	private_attest_db_t *this, char *comp, bool create)
{
	enumerator_t *e;
	char *pos1, *pos2;
	int vid, name, qualifier;
	pts_comp_func_name_t *cfn;

	if (this->comp_set)
	{
		printf("component has already been set\n");
		return FALSE;
	}

	/* parse component string */
	pos1 = strchr(comp, '/');
	pos2 = strchr(comp, '-');
	if (!pos1 || !pos2)
	{
		printf("component string must have the form \"vendor_id/name-qualifier\"\n");
		return FALSE;
	}
	vid       = atoi(comp);
	name      = atoi(pos1 + 1);
	qualifier = atoi(pos2 + 1);
	cfn = pts_comp_func_name_create(vid, name, qualifier);

	e = this->db->query(this->db,
					   "SELECT id FROM components "
					   "WHERE vendor_id = ? AND name = ? AND qualifier = ?",
						DB_INT, vid, DB_INT, name, DB_INT, qualifier, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->cid))
		{
			this->comp_set = TRUE;
			this->cfn = cfn;
		}
		e->destroy(e);
	}
	if (this->comp_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("component '%s' not found in database\n", print_cfn(cfn));
		cfn->destroy(cfn);
		return FALSE;
	}

	/* Add a new database entry */
	this->comp_set = this->db->execute(this->db, &this->cid,
						"INSERT INTO components (vendor_id, name, qualifier) "
						"VALUES (?, ?, ?)",
						DB_INT, vid, DB_INT, name, DB_INT, qualifier) == 1;

	printf("component '%s' %sinserted into database\n", print_cfn(cfn),
		   this->comp_set ? "" : "could not be ");
	if (this->comp_set)
	{
		this->cfn = cfn;
	}
	else
	{
		cfn->destroy(cfn);
	}
	return this->comp_set;
}

METHOD(attest_db_t, set_cid, bool,
	private_attest_db_t *this, int cid)
{
	enumerator_t *e;
	int vid, name, qualifier;

	if (this->comp_set)
	{
		printf("component has already been set\n");
		return FALSE;
	}
	this->cid = cid;

	e = this->db->query(this->db, "SELECT vendor_id, name, qualifier "
								  "FROM components WHERE id = ?",
						DB_INT, cid, DB_INT, DB_INT, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &vid, &name, &qualifier))
		{
			this->cfn = pts_comp_func_name_create(vid, name, qualifier);
			this->comp_set = TRUE;
		}
		else
		{
			printf("no component found with cid %d\n", cid);
		}
		e->destroy(e);
	}
	return this->comp_set;
}

METHOD(attest_db_t, set_directory, bool,
	private_attest_db_t *this, char *dir, bool create)
{
	enumerator_t *e;

	if (this->dir_set)
	{
		printf("directory has already been set\n");
		return FALSE;
	}
	free(this->dir);
	this->dir = strdup(dir);

	e = this->db->query(this->db,
						"SELECT id FROM files WHERE type = 1 AND path = ?",
						DB_TEXT, dir, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->did))
		{
			this->dir_set = TRUE;
		}
		e->destroy(e);
	}
	if (this->dir_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("directory '%s' not found in database\n", dir);
		return FALSE;
	}

	/* Add a new database entry */
	this->dir_set = this->db->execute(this->db, &this->did,
								"INSERT INTO files (type, path) VALUES (1, ?)",
								DB_TEXT, dir) == 1;

	printf("directory '%s' %sinserted into database\n", dir,
		   this->dir_set ? "" : "could not be ");

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

METHOD(attest_db_t, set_file, bool,
	private_attest_db_t *this, char *file, bool create)
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
		e->destroy(e);
	}
	if (this->file_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("file '%s' not found in database\n", file);
		return FALSE;
	}

	/* Add a new database entry */
	this->file_set = this->db->execute(this->db, &this->fid,
								"INSERT INTO files (type, path) VALUES (0, ?)",
								DB_TEXT, file) == 1;

	printf("file '%s' %sinserted into database\n", file,
		   this->file_set ? "" : "could not be ");

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

METHOD(attest_db_t, set_key, bool,
	private_attest_db_t *this, chunk_t key, bool create)
{
	enumerator_t *e;
	char *owner;

	if (this->key_set)
	{
		printf("key has already been set\n");
		return FALSE;
	}
	this->key = key;

	e = this->db->query(this->db, "SELECT id, owner FROM keys WHERE keyid= ?",
						DB_BLOB, this->key, DB_INT, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &this->kid, &owner))
		{
			free(this->owner);
			this->owner = strdup(owner);
			this->key_set = TRUE;
		}
		e->destroy(e);
	}
	if (this->key_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("key '%#B' not found in database\n", &this->key);
		return FALSE;
	}

	/* Add a new database entry */
	if (!this->owner)
	{
		this->owner = strdup("");
	}
	this->key_set = this->db->execute(this->db, &this->kid,
								"INSERT INTO keys (keyid, owner) VALUES (?, ?)",
								DB_BLOB, this->key, DB_TEXT, this->owner) == 1;

	printf("key '%#B' %sinserted into database\n", &this->key,
		   this->key_set ? "" : "could not be ");

	return this->key_set;

};

METHOD(attest_db_t, set_kid, bool,
	private_attest_db_t *this, int kid)
{
	enumerator_t *e;
	chunk_t key;
	char *owner;

	if (this->key_set)
	{
		printf("key has already been set\n");
		return FALSE;
	}
	this->kid = kid;

	e = this->db->query(this->db, "SELECT keyid, owner FROM keys WHERE id = ?",
						DB_INT, kid, DB_BLOB, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &key, &owner))
		{
			this->owner = strdup(owner);
			this->key = chunk_clone(key);
			this->key_set = TRUE;
		}
		else
		{
			printf("no key found with kid %d\n", kid);
		}
		e->destroy(e);
	}
	return this->key_set;

};

METHOD(attest_db_t, set_product, bool,
	private_attest_db_t *this, char *product, bool create)
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
		e->destroy(e);
	}
	if (this->product_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("product '%s' not found in database\n", product);
		return FALSE;
	}

	/* Add a new database entry */
	this->product_set = this->db->execute(this->db, &this->pid,
									"INSERT INTO products (name) VALUES (?)",
									DB_TEXT, product) == 1;

	printf("product '%s' %sinserted into database\n", product,
		   this->product_set ? "" : "could not be ");

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

METHOD(attest_db_t, set_algo, void,
	private_attest_db_t *this, pts_meas_algorithms_t algo)
{
	this->algo = algo;
}

METHOD(attest_db_t, set_owner, void,
	private_attest_db_t *this, char *owner)
{
	free(this->owner);
	this->owner = strdup(owner);
}

METHOD(attest_db_t, list_components, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	pts_comp_func_name_t *cfn;
	int cid, vid, name, qualifier, count = 0;

	if (this->kid)
	{
		e = this->db->query(this->db,
				"SELECT c.id, c.vendor_id, c.name, c.qualifier "
				"FROM components AS c "
				"JOIN key_component AS kc ON c.id = kc.component "
				"WHERE kc.key = ? ORDER BY c.vendor_id, c.name, c.qualifier",
				DB_INT, this->kid, DB_INT, DB_INT, DB_INT, DB_INT);
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT id, vendor_id, name, qualifier FROM components "
				"ORDER BY vendor_id, name, qualifier",
				DB_INT, DB_INT, DB_INT, DB_INT);
	}
	if (e)
	{
		while (e->enumerate(e, &cid, &vid, &name, &qualifier))
		{
			cfn   = pts_comp_func_name_create(vid, name, qualifier);
			printf("%3d: %s\n", cid, print_cfn(cfn));
			cfn->destroy(cfn);
			count++;
		}
		e->destroy(e);

		printf("%d component%s found", count, (count == 1) ? "" : "s");
		if (this->key_set)
		{
			printf(" for key %#B", &this->key);
		}
		printf("\n");
	}
}

METHOD(attest_db_t, list_keys, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	chunk_t keyid;
	char *owner;
	int kid, count = 0;

	if (this->cid)
	{
		e = this->db->query(this->db,
				"SELECT k.id, k.keyid, k.owner FROM keys AS k "
				"JOIN key_component AS kc ON k.id = kc.key "
				"WHERE kc.component = ? ORDER BY k.keyid",
				DB_INT, this->cid, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &kid, &keyid, &owner))
			{
				printf("%3d: %#B '%s'\n", kid, &keyid, owner);
				count++;
			}
			e->destroy(e);
		}
	}
	else
	{
		e = this->db->query(this->db, "SELECT id, keyid, owner FROM keys "
				"ORDER BY keyid",
				DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &kid, &keyid, &owner))
			{
				printf("%3d: %#B '%s'\n", kid, &keyid, owner);
				count++;
			}
			e->destroy(e);
		}
	}

	printf("%d key%s found", count, (count == 1) ? "" : "s");
	if (this->comp_set)
	{
		printf(" for component '%s'", print_cfn(this->cfn));
	}
	printf("\n");
}

METHOD(attest_db_t, list_files, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	char *file, *file_type[] = { " ", "d", "r" };
	int fid, type, meas, meta, count = 0;

	if (this->pid)
	{
		e = this->db->query(this->db,
				"SELECT f.id, f.type, f.path, pf.measurement, pf.metadata "
				"FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"WHERE pf.product = ? ORDER BY f.path",
				DB_INT, this->pid, DB_INT, DB_INT, DB_TEXT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &fid, &type, &file, &meas, &meta))
			{
				type = (type < 0 || type > 2) ? 0 : type;
				printf("%3d: |%s%s| %s %s\n", fid, meas ? "M":" ", meta ? "T":" ",
											  file_type[type], file);
				count++;
			}
			e->destroy(e);
		}
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT id, type, path FROM files "
				"ORDER BY path",
				DB_INT, DB_INT, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &fid, &type, &file))
			{
				type = (type < 0 || type > 2) ? 0 : type;
				printf("%3d: %s %s\n", fid, file_type[type], file);
				count++;
			}
			e->destroy(e);
		}
	}

	printf("%d file%s found", count, (count == 1) ? "" : "s");
	if (this->product_set)
	{
		printf(" for product '%s'", this->product);
	}
	printf("\n");
}

METHOD(attest_db_t, list_products, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	char *product;
	int pid, meas, meta, count = 0;

	if (this->fid)
	{
		e = this->db->query(this->db,
				"SELECT p.id, p.name, pf.measurement, pf.metadata "
				"FROM products AS p "
				"JOIN product_file AS pf ON p.id = pf.product "
				"WHERE pf.file = ? ORDER BY p.name",
				DB_INT, this->fid, DB_INT, DB_TEXT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &pid, &product, &meas, &meta))
			{
				printf("%3d: |%s%s| %s\n", pid, meas ? "M":" ", meta ? "T":" ",
										   product);
				count++;
			}
			e->destroy(e);
		}
	}
	else
	{
		e = this->db->query(this->db, "SELECT id, name FROM products "
				"ORDER BY name",
				DB_INT, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &pid, &product))
			{
				printf("%3d: %s\n", pid, product);
				count++;
			}
			e->destroy(e);
		}
	}

	printf("%d product%s found", count, (count == 1) ? "" : "s");
	if (this->file_set)
	{
		printf(" for file '%s'", this->file);
	}
	printf("\n");
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

METHOD(attest_db_t, list_measurements, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	chunk_t hash, keyid;
	pts_comp_func_name_t *cfn;
	char *owner;
	int seq_no, pcr, vid, name, qualifier;
	int cid, cid_old = 0, kid, kid_old = 0, count = 0;

	if (this->kid && this->cid)
	{
		e = this->db->query(this->db,
				"SELECT ch.seq_no, ch.pcr, ch.hash, k.owner "
				"FROM component_hashes AS ch "
				"JOIN keys AS k ON k.id = ch.key "
				"WHERE ch.algo = ? AND ch.key = ? AND ch.component = ? "
				"ORDER BY seq_no",
				DB_INT, this->algo, DB_INT, this->kid, DB_INT, this->cid,
				DB_INT, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &owner))
			{
				if (this->kid != kid_old)
				{
					printf("%3d: %#B '%s'\n", this->kid, &this->key, owner);
					kid_old = this->kid;
				}
				printf("%5d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for component '%s'\n", count,
				   hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", print_cfn(this->cfn));
		}
	}
	else if (this->cid)
	{
		e = this->db->query(this->db,
				"SELECT ch.seq_no, ch.pcr, ch.hash, k.id, k.keyid, k.owner "
				"FROM component_hashes AS ch "
				"JOIN keys AS k ON k.id = ch.key "
				"WHERE ch.algo = ? AND ch.component = ? "
				"ORDER BY keyid, seq_no",
				DB_INT, this->algo, DB_INT, this->cid,
				DB_INT, DB_INT, DB_BLOB, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &kid, &keyid, &owner))
			{
				if (kid != kid_old)
				{
					printf("%3d: %#B '%s'\n", kid, &keyid, owner);
					kid_old = kid;
				}
				printf("%5d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for component '%s'\n", count,
				   hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", print_cfn(this->cfn));
		}

	}
	else if (this->kid)
	{
		e = this->db->query(this->db,
				"SELECT ch.seq_no, ch.pcr, ch.hash, "
				"c.id, c.vendor_id, c.name, c.qualifier "
				"FROM component_hashes AS ch "
				"JOIN components AS c ON c.id = ch.component "
				"WHERE ch.algo = ? AND ch.key = ? "
				"ORDER BY vendor_id, name, qualifier, seq_no",
				DB_INT, this->algo, DB_INT, this->kid, DB_INT, DB_INT, DB_BLOB,
				DB_INT, DB_INT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &cid, &vid, &name,
								   &qualifier))
			{
				if (cid != cid_old)
				{
					cfn = pts_comp_func_name_create(vid, name, qualifier);
					printf("%3d: %s\n", cid, print_cfn(cfn));
					cfn->destroy(cfn);
					cid_old = cid;
				}
				printf("%5d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for key %#B '%s'\n", count,
				   hash_algorithm_names, pts_meas_algo_to_hash(this->algo),
				   (count == 1) ? "" : "s", &this->key, this->owner);
		}
	}
}

METHOD(attest_db_t, add, bool,
	private_attest_db_t *this)
{
	bool success = FALSE;

	if (this->kid && this->cid)
	{
		success = this->db->execute(this->db, NULL,
					"INSERT INTO key_component (key, component) VALUES (?, ?)",
					DB_UINT, this->kid, DB_UINT, this->cid) == 1;

		printf("key/component pair (%d/%d) %sinserted into database\n",
				this->kid, this->cid, success ? "" : "could not be ");
	}
	return success;
}

METHOD(attest_db_t, delete, bool,
	private_attest_db_t *this)
{
	bool success;

	if (this->pid && (this->fid || this->did))
	{
		printf("deletion of product/file entries not supported yet\n");
		return FALSE;
	}

	if (this->kid && this->cid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM key_component "
								"WHERE key = ? AND component = ?",
								DB_UINT, this->kid, DB_UINT, this->cid) > 0;

		printf("key/component pair (%d/%d) %sdeleted from database\n",
				this->kid, this->cid, success ? "" : "could not be ");
		return success;
	}

	if (this->cid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM components WHERE id = ?",
								DB_UINT, this->cid) > 0;

		printf("component '%s' %sdeleted from database\n", print_cfn(this->cfn),
			   success ? "" : "could not be ");
		return success;
	}

	if (this->did)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM files WHERE type = 1 AND id = ?",
								DB_UINT, this->did) > 0;

		printf("directory '%s' %sdeleted from database\n", this->dir,
			   success ? "" : "could not be ");
		return success;
	}

	if (this->fid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM files WHERE id = ?",
								DB_UINT, this->fid) > 0;

		printf("file '%s' %sdeleted from database\n", this->file,
			   success ? "" : "could not be ");
		return success;
	}

	if (this->kid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM keys WHERE id = ?",
								DB_UINT, this->kid) > 0;

		printf("key %#B %sdeleted from database\n", &this->key,
			   success ? "" : "could not be ");
		return success;
	}
	if (this->pid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM products WHERE id = ?",
								DB_UINT, this->pid) > 0;

		printf("product '%s' %sdeleted from database\n", this->product,
			   success ? "" : "could not be ");
		return success;
	}

	printf("empty delete command\n");
	return FALSE;
}

METHOD(attest_db_t, destroy, void,
	private_attest_db_t *this)
{
	DESTROY_IF(this->db);
	DESTROY_IF(this->cfn);
	free(this->product);
	free(this->file);
	free(this->dir);
	free(this->owner);
	free(this->key.ptr);
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
			.set_component = _set_component,
			.set_cid = _set_cid,
			.set_directory = _set_directory,
			.set_did = _set_did,
			.set_file = _set_file,
			.set_fid = _set_fid,
			.set_key = _set_key,
			.set_kid = _set_kid,
			.set_product = _set_product,
			.set_pid = _set_pid,
			.set_algo = _set_algo,
			.set_owner = _set_owner,
			.list_products = _list_products,
			.list_files = _list_files,
			.list_components = _list_components,
			.list_keys = _list_keys,
			.list_hashes = _list_hashes,
			.list_measurements = _list_measurements,
			.add = _add,
			.delete = _delete,
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
