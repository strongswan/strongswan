/*
 * Copyright (C) 2011-2012 Andreas Steffen
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
#include "pts/pts_meas_algo.h"
#include "pts/pts_file_meas.h"
#include "pts/components/pts_comp_func_name.h"

#include <libgen.h>
#include <time.h>

#define IMA_MAX_NAME_LEN	255

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
	 * Software package to be queried
	 */
	char *package;

	/**
	 * Primary key of software package to be queried
	 */
	int gid;

	/**
	 * TRUE if package has been set
	 */
	bool package_set;

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
	 * Software package version to be queried
	 */
	char *version;

	/**
	 * TRUE if version has been set
	 */
	bool version_set;

	/**
	 * TRUE if relative filenames are to be used
	 */
	bool relative;

	/**
	 * TRUE if dates are to be displayed in UTC
	 */
	bool utc;

	/**
	 * Package security state
	 */
	os_package_state_t security;

	/**
	 * Sequence number for ordering entries
	 */
	int seq_no;

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
						DB_UINT, vid, DB_INT, name, DB_INT, qualifier, DB_INT);
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
						DB_UINT, cid, DB_INT, DB_INT, DB_INT);
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
	size_t len;

	if (this->dir_set)
	{
		printf("directory has already been set\n");
		return FALSE;
	}
	free(this->dir);

	/* remove trailing '/' character */
	len = strlen(dir);
	if (len && dir[len-1] == '/')
	{
		dir[len-1] = '\0';
	}
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
						DB_UINT, did, DB_TEXT);
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
	char *filename;

	if (this->file_set)
	{
		printf("file has already been set\n");
		return FALSE;
	}
	this->file = strdup(file);
	filename = this->relative ? basename(file) : file;

	e = this->db->query(this->db, "SELECT id FROM files WHERE path = ?",
						DB_TEXT, filename, DB_INT);
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
								DB_TEXT, filename) == 1;

	printf("file '%s' %sinserted into database\n", filename,
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
						DB_UINT, fid, DB_TEXT);
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
						DB_UINT, kid, DB_BLOB, DB_TEXT);
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
						DB_UINT, pid, DB_TEXT);
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

METHOD(attest_db_t, set_package, bool,
	private_attest_db_t *this, char *package, bool create)
{
	enumerator_t *e;

	if (this->package_set)
	{
		printf("package has already been set\n");
		return FALSE;
	}
	this->package = strdup(package);

	e = this->db->query(this->db, "SELECT id FROM packages WHERE name = ?",
						DB_TEXT, package, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &this->gid))
		{
			this->package_set = TRUE;
		}
		e->destroy(e);
	}
	if (this->package_set)
	{
		return TRUE;
	}

	if (!create)
	{
		printf("package '%s' not found in database\n", package);
		return FALSE;
	}

	/* Add a new database entry */
	this->package_set = this->db->execute(this->db, &this->gid,
									"INSERT INTO packages (name) VALUES (?)",
									DB_TEXT, package) == 1;

	printf("package '%s' %sinserted into database\n", package,
		   this->package_set ? "" : "could not be ");

	return this->package_set;
}

METHOD(attest_db_t, set_gid, bool,
	private_attest_db_t *this, int gid)
{
	enumerator_t *e;
	char *package;

	if (this->package_set)
	{
		printf("package has already been set\n");
		return FALSE;
	}
	this->gid = gid;

	e = this->db->query(this->db, "SELECT name FROM packages WHERE id = ?",
						DB_UINT, gid, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &package))
		{
			this->package = strdup(package);
			this->package_set = TRUE;
		}
		else
		{
			printf("no package found with gid %d in database\n", gid);
		}
		e->destroy(e);
	}
	return this->package_set;
}

METHOD(attest_db_t, set_version, bool,
	private_attest_db_t *this, char *version)
{
	if (this->version_set)
	{
		printf("version has already been set\n");
		return FALSE;
	}
	this->version = strdup(version);
	this->version_set = TRUE;

	return TRUE;
}


METHOD(attest_db_t, set_algo, void,
	private_attest_db_t *this, pts_meas_algorithms_t algo)
{
	this->algo = algo;
}

METHOD(attest_db_t, set_relative, void,
	private_attest_db_t *this)
{
	this->relative = TRUE;
}

METHOD(attest_db_t, set_security, void,
	private_attest_db_t *this, os_package_state_t security)
{
	this->security = security;
}

METHOD(attest_db_t, set_sequence, void,
	private_attest_db_t *this, int seq_no)
{
	this->seq_no = seq_no;
}

METHOD(attest_db_t, set_owner, void,
	private_attest_db_t *this, char *owner)
{
	free(this->owner);
	this->owner = strdup(owner);
}

METHOD(attest_db_t, set_utc, void,
	private_attest_db_t *this)
{
	this->utc = TRUE;
}

METHOD(attest_db_t, list_components, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	pts_comp_func_name_t *cfn;
	int seq_no, cid, vid, name, qualifier, count = 0;

	if (this->kid)
	{
		e = this->db->query(this->db,
				"SELECT kc.seq_no, c.id, c.vendor_id, c.name, c.qualifier "
				"FROM components AS c "
				"JOIN key_component AS kc ON c.id = kc.component "
				"WHERE kc.key = ? ORDER BY kc.seq_no",
				DB_UINT, this->kid, DB_INT, DB_INT, DB_INT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e,  &cid, &seq_no, &vid, &name, &qualifier))
			{
				cfn   = pts_comp_func_name_create(vid, name, qualifier);
				printf("%4d: #%-2d %s\n", seq_no, cid, print_cfn(cfn));
				cfn->destroy(cfn);
				count++;
			}
			e->destroy(e);
			printf("%d component%s found for key %#B\n", count,
				  (count == 1) ? "" : "s", &this->key);
		}
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT id, vendor_id, name, qualifier FROM components "
				"ORDER BY vendor_id, name, qualifier",
				DB_INT, DB_INT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e,  &cid, &vid, &name, &qualifier))
			{
				cfn   = pts_comp_func_name_create(vid, name, qualifier);
				printf("%4d: %s\n", cid, print_cfn(cfn));
				cfn->destroy(cfn);
				count++;
			}
			e->destroy(e);
			printf("%d component%s found\n", count, (count == 1) ? "" : "s");
		}
	}
}

METHOD(attest_db_t, list_devices, void,
	private_attest_db_t *this)
{
	enumerator_t *e, *e_ar;
	chunk_t value, ar_id_value = chunk_empty;
	char *product;
	time_t timestamp;
	int id, last_id = 0, ar_id = 0, last_ar_id = 0, device_count = 0;
	int count, count_update, count_blacklist;
	u_int32_t ar_id_type;
	u_int tstamp, flags = 0;

	e = this->db->query(this->db,
			"SELECT d.id, d.value, i.time, i.count, i.count_update, "
			"i.count_blacklist, i.flags, i.ar_id, p.name FROM devices AS d "
			"JOIN device_infos AS i ON d.id = i.device "
			"JOIN products AS p ON p.id = i.product "
			"ORDER BY d.value, i.time DESC",
			 DB_INT, DB_BLOB, DB_UINT, DB_INT, DB_INT, DB_INT, DB_UINT,
			 DB_INT, DB_TEXT);

	if (e)
	{
		while (e->enumerate(e, &id, &value, &tstamp, &count, &count_update,
							   &count_blacklist, &flags, &ar_id, &product))
		{
			if (id != last_id)
			{
				printf("%4d: %.*s\n", id, (int)value.len, value.ptr);
				device_count++;
				last_id = id;
			}
			timestamp = tstamp;
			printf("      %T, %4d, %3d, %3d, %1u, '%s'", &timestamp, this->utc,
				   count, count_update, count_blacklist, flags, product);
			if (ar_id)
			{
				if (ar_id != last_ar_id)
				{
					chunk_free(&ar_id_value);
					e_ar = this->db->query(this->db,
								"SELECT type, data FROM identities "
								"WHERE id = ?", DB_INT, ar_id, DB_INT, DB_BLOB);
					if (e_ar)
					{
						e_ar->enumerate(e_ar, &ar_id_type, &ar_id_value);
						ar_id_value = chunk_clone(ar_id_value);
						e_ar->destroy(e_ar);
					}
				}
				if (ar_id_value.len)
				{
					printf(" %.*s", (int)ar_id_value.len, ar_id_value.ptr);
				}
				last_ar_id = ar_id;
			}
			printf("\n");
		}
		e->destroy(e);
		free(ar_id_value.ptr);

		printf("%d device%s found\n", device_count,
									 (device_count == 1) ? "" : "s");
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
				DB_UINT, this->cid, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &kid, &keyid, &owner))
			{
				printf("%4d: %#B '%s'\n", kid, &keyid, owner);
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
				printf("%4d: %#B '%s'\n", kid, &keyid, owner);
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
				DB_UINT, this->pid, DB_INT, DB_INT, DB_TEXT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &fid, &type, &file, &meas, &meta))
			{
				type = (type < 0 || type > 2) ? 0 : type;
				printf("%4d: |%s%s| %s %s\n", fid, meas ? "M":" ", meta ? "T":" ",
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
				printf("%4d: %s %s\n", fid, file_type[type], file);
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

METHOD(attest_db_t, list_packages, void,
	private_attest_db_t *this)
{
	enumerator_t *e;
	char *package, *version;
	os_package_state_t security;
	int gid, gid_old = 0, spaces, count = 0, t;
	time_t timestamp;

	if (this->pid)
	{
		e = this->db->query(this->db,
				"SELECT p.id, p.name, v.release, v.security, v.time "
				"FROM packages AS p JOIN versions AS v ON v.package = p.id "
				"WHERE v.product = ? ORDER BY p.name, v.release",
				DB_INT, this->pid, DB_INT, DB_TEXT, DB_TEXT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &gid, &package, &version, &security, &t))
			{
				if (gid != gid_old)
				{
					printf("%5d: %s,", gid, package);
					gid_old = gid;
				}
				else
				{
					spaces = 8 + strlen(package);
					while (spaces--)
					{
						printf(" ");
					}
				}
				timestamp = t;
				printf(" %T (%s)%N\n", &timestamp, this->utc, version,
					 os_package_state_names, security);
				count++;
			}
			e->destroy(e);
		}
	}
	else
	{
		e = this->db->query(this->db, "SELECT id, name FROM packages "
				"ORDER BY name",
				DB_INT, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &gid, &package))
			{
				printf("%4d: %s\n", gid, package);
				count++;
			}
			e->destroy(e);
		}
	}

	printf("%d package%s found", count, (count == 1) ? "" : "s");
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
				DB_UINT, this->fid, DB_INT, DB_TEXT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &pid, &product, &meas, &meta))
			{
				printf("%4d: |%s%s| %s\n", pid, meas ? "M":" ", meta ? "T":" ",
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
				printf("%4d: %s\n", pid, product);
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
				DB_UINT, did, DB_TEXT);
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

	if (this->pid && this->fid & this->did)
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
					printf("%4d: %s%s%s\n", this->fid, this->dir,
						   slash(this->dir, this->file) ? "/" : "", this->file);
					fid_old = this->fid;
				}
				printf("      %#B\n", &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for product '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
				   (count == 1) ? "" : "s", this->product);
		}
	}
	else if (this->pid && this->fid)
	{
		e = this->db->query(this->db,
				"SELECT f.path, fh.hash FROM file_hashes AS fh "
				"JOIN files AS f ON f.id = fh.file "
				"WHERE algo = ? AND file = ? AND product = ?",
				DB_INT, this->algo, DB_INT, this->fid, DB_INT, this->pid,
				DB_TEXT, DB_BLOB);
		if (e)
		{
			free(dir);
			while (e->enumerate(e, &dir, &hash))
			{
				printf("%4d: %s%s%s\n", this->fid, dir,
						   slash(dir, this->file) ? "/" : "", this->file);
				printf("      %#B\n", &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for product '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
				   (count == 1) ? "" : "s", this->product);
			dir = NULL;
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
				DB_INT, this->algo, DB_UINT, this->pid,
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
					printf("%4d: %s%s%s\n", fid,
						   dir, slash(dir, file) ? "/" : "", file);
					fid_old = fid;
					did_old = did;
				}
				printf("      %#B\n", &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for product '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
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
				DB_INT, this->algo, DB_UINT, this->fid, DB_UINT, this->did,
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
				   count, pts_meas_algorithm_names, this->algo,
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
					printf("%4d: %s%s%s\n", fid,
						   dir, slash(dir, file) ? "/" : "", file);
					fid_old = fid;
				}
				printf("      %#B '%s'\n", &hash, product);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found\n", count, pts_meas_algorithm_names,
				   this->algo, (count == 1) ? "" : "s");
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
				DB_INT, this->algo, DB_UINT, this->kid, DB_UINT, this->cid,
				DB_INT, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &owner))
			{
				if (this->kid != kid_old)
				{
					printf("%4d: %#B '%s'\n", this->kid, &this->key, owner);
					kid_old = this->kid;
				}
				printf("%7d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for component '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
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
				DB_INT, this->algo, DB_UINT, this->cid,
				DB_INT, DB_INT, DB_BLOB, DB_INT, DB_BLOB, DB_TEXT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &kid, &keyid, &owner))
			{
				if (kid != kid_old)
				{
					printf("%4d: %#B '%s'\n", kid, &keyid, owner);
					kid_old = kid;
				}
				printf("%7d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for component '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
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
				DB_INT, this->algo, DB_UINT, this->kid, DB_INT, DB_INT, DB_BLOB,
				DB_INT, DB_INT, DB_INT, DB_INT);
		if (e)
		{
			while (e->enumerate(e, &seq_no, &pcr, &hash, &cid, &vid, &name,
								   &qualifier))
			{
				if (cid != cid_old)
				{
					cfn = pts_comp_func_name_create(vid, name, qualifier);
					printf("%4d: %s\n", cid, print_cfn(cfn));
					cfn->destroy(cfn);
					cid_old = cid;
				}
				printf("%5d %02d %#B\n", seq_no, pcr, &hash);
				count++;
			}
			e->destroy(e);

			printf("%d %N value%s found for key %#B '%s'\n", count,
				   pts_meas_algorithm_names, this->algo,
				   (count == 1) ? "" : "s", &this->key, this->owner);
		}
	}
}

bool insert_file_hash(private_attest_db_t *this, pts_meas_algorithms_t algo,
					  chunk_t measurement, int fid, int did, bool ima,
					  int *hashes_added, int *hashes_updated)
{
	enumerator_t *e;
	chunk_t hash;
	char *label;

	label = "could not be created";

	e = this->db->query(this->db,
		"SELECT hash FROM file_hashes WHERE algo = ? "
		"AND file = ? AND directory = ? AND product = ? and key = 0",
		DB_INT, algo, DB_UINT, fid, DB_UINT, did, DB_UINT, this->pid, DB_BLOB);
	if (!e)
	{
		printf("file_hashes query failed\n");
		return FALSE;
	}
	if (e->enumerate(e, &hash))
	{
		if (chunk_equals(measurement, hash))
		{
			label = "exists and equals";
		}
		else
		{
			if (this->db->execute(this->db, NULL,
				"UPDATE file_hashes SET hash = ? WHERE algo = ? "
				"AND file = ? AND directory = ? AND product = ? and key = 0",
				DB_BLOB, measurement, DB_INT, algo, DB_UINT, fid, DB_UINT, did,
				DB_UINT, this->pid) == 1)
			{
				label = "updated";
				(*hashes_updated)++;
			}
		}
	}
	else
	{
		if (this->db->execute(this->db, NULL,
			"INSERT INTO file_hashes "
			"(file, directory, product, key, algo, hash) "
			"VALUES (?, ?, ?, 0, ?, ?)",
			DB_UINT, fid, DB_UINT, did, DB_UINT, this->pid,
			DB_INT, algo, DB_BLOB, measurement) == 1)
		{
			label = "created";
			(*hashes_added)++;
		}
	}
	e->destroy(e);

	printf("     %#B - %s%s\n", &measurement, ima ? "ima - " : "", label);
	return TRUE;
}

METHOD(attest_db_t, add, bool,
	private_attest_db_t *this)
{
	bool success = FALSE;

	/* add key/component pair */
	if (this->kid && this->cid)
	{
		success = this->db->execute(this->db, NULL,
					"INSERT INTO key_component (key, component, seq_no) "
					"VALUES (?, ?, ?)",
					DB_UINT, this->kid, DB_UINT, this->cid,
					DB_UINT, this->seq_no) == 1;

		printf("key/component pair (%d/%d) %sinserted into database at "
			   "position %d\n", this->kid, this->cid,
			    success ? "" : "could not be ", this->seq_no);

		return success;
	}

	/* add directory or file measurement for a given product */
	if ((this->did || this->fid) && this->pid)
	{
		char *pathname, *filename, *label;
		char ima_buffer[IMA_MAX_NAME_LEN + 1];
		chunk_t measurement, ima_template;
		pts_file_meas_t *measurements;
		hasher_t *hasher = NULL;
		bool ima = FALSE;
		int fid, did;
		int files_added = 0, hashes_added = 0, hashes_updated = 0;
		int ima_hashes_added = 0, ima_hashes_updated = 0;
		enumerator_t *enumerator, *e;

		if (this->algo == PTS_MEAS_ALGO_SHA1_IMA)
		{
			ima = TRUE;
			this->algo = PTS_MEAS_ALGO_SHA1;
			hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
			if (!hasher)
			{
				printf("could not create hasher\n");
				return FALSE;
			}
		}

		pathname = this->did ? this->dir : this->file;
		measurements = pts_file_meas_create_from_path(0, pathname, this->did,
												this->relative, this->algo);
		if (!measurements)
		{
			printf("file measurement failed\n");
			DESTROY_IF(hasher);
			return FALSE;
		}
		if (this->fid && this->relative)
		{
			set_directory(this, dirname(pathname), TRUE);
		}
		did = this->relative ? this->did : 0;

		enumerator = measurements->create_enumerator(measurements);
		while (enumerator->enumerate(enumerator, &filename, &measurement))
		{
			/* retrieve or create filename */
			label = "could not be created";

			e = this->db->query(this->db,
				"SELECT id FROM files WHERE path = ?",
				DB_TEXT, filename, DB_INT);
			if (!e)
			{
				printf("files query failed\n");
				break;
			}
			if (e->enumerate(e, &fid))
			{
				label = "exists";
			}
			else
			{
				if (this->db->execute(this->db, &fid,
					"INSERT INTO files (type, path) VALUES (0, ?)",
					DB_TEXT, filename) == 1)
				{
					label = "created";
					files_added++;
				}
			}
			e->destroy(e);

			printf("%4d: %s - %s\n", fid, filename, label);

			/* compute file measurement hash */
			if (!insert_file_hash(this, this->algo, measurement,
								  fid, did, FALSE,
								  &hashes_added, &hashes_updated))
			{
				break;
			}

			if (!ima)
			{
				continue;
			}

			/* compute IMA template hash */
			strncpy(ima_buffer, filename, IMA_MAX_NAME_LEN);
			ima_buffer[IMA_MAX_NAME_LEN] = '\0';
			ima_template = chunk_create(ima_buffer, sizeof(ima_buffer));
			if (!hasher->get_hash(hasher, measurement, NULL) ||
				!hasher->get_hash(hasher, ima_template, measurement.ptr))
			{
				printf("could not compute IMA template hash\n");
				break;
			}
			if (!insert_file_hash(this, PTS_MEAS_ALGO_SHA1_IMA, measurement,
								  fid, did, TRUE,
								  &ima_hashes_added, &ima_hashes_updated))
			{
				break;
			}
		}
		enumerator->destroy(enumerator);

		printf("%d measurements, added %d new files, %d file hashes",
			    measurements->get_file_count(measurements), files_added,
				hashes_added);
		if (ima)
		{
			printf(", %d ima hashes", ima_hashes_added);
			hasher->destroy(hasher);
		}
		printf(", updated %d file hashes", hashes_updated);
		if (ima)
		{
			printf(", %d ima hashes", ima_hashes_updated);
		}
		printf("\n");
		measurements->destroy(measurements);
		success = TRUE;
	}

	/* insert package version */
	if (this->version_set && this->gid && this->pid)
	{
		time_t t = time(NULL);

		success = this->db->execute(this->db, NULL,
					"INSERT INTO versions "
					"(package, product, release, security, time) "
					"VALUES (?, ?, ?, ?, ?)",
					DB_UINT, this->gid, DB_UINT, this->pid, DB_TEXT,
					this->version, DB_UINT, this->security, DB_INT, t) == 1;

		printf("'%s' package %s (%s)%N %sinserted into database\n",
				this->product, this->package, this->version,
				os_package_state_names, this->security,
				success ? "" : "could not be ");
	}
	return success;
}

METHOD(attest_db_t, delete, bool,
	private_attest_db_t *this)
{
	bool success;

	/* delete a file measurement hash for a given product */
	if (this->algo && this->pid && this->fid)
	{
		success = this->db->execute(this->db, NULL,
								"DELETE FROM file_hashes "
								"WHERE algo = ? AND product = ? "
								"AND file = ? AND directory = ?",
								DB_UINT, this->algo, DB_UINT, this->pid,
								DB_UINT, this->fid, DB_UINT, this->did) > 0;

		printf("%4d: %s%s%s\n", this->fid, this->dir, this->did ? "/":"",
								this->file);
		printf("%N value for product '%s' %sdeleted from database\n",
				pts_meas_algorithm_names, this->algo, this->product,
				success ? "" : "could not be ");

		return success;
	}

	/* delete product/file entries */
	if (this->pid && (this->fid || this->did))
	{
		success = this->db->execute(this->db, NULL,
							"DELETE FROM product_file "
							"WHERE product = ? AND file = ?",
							DB_UINT, this->pid,
							DB_UINT, this->fid ? this->fid : this->did) > 0;

		printf("product/file pair (%d/%d) %sdeleted from database\n",
				this->pid, this->fid ? this->fid : this->did,
				success ? "" : "could not be ");

		return success;
	}

	/* delete key/component pair */
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
	free(this->package);
	free(this->product);
	free(this->version);
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
			.set_package = _set_package,
			.set_gid = _set_gid,
			.set_product = _set_product,
			.set_pid = _set_pid,
			.set_version = _set_version,
			.set_algo = _set_algo,
			.set_relative = _set_relative,
			.set_security = _set_security,
			.set_sequence = _set_sequence,
			.set_owner = _set_owner,
			.set_utc = _set_utc,
			.list_packages = _list_packages,
			.list_products = _list_products,
			.list_files = _list_files,
			.list_components = _list_components,
			.list_devices = _list_devices,
			.list_keys = _list_keys,
			.list_hashes = _list_hashes,
			.list_measurements = _list_measurements,
			.add = _add,
			.delete = _delete,
			.destroy = _destroy,
		},
		.dir = strdup(""),
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
