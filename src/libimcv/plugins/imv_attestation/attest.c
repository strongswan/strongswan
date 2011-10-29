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

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <debug.h>
#include <library.h>

#include <pts/pts_meas_algo.h>

#include "attest_usage.h"

/**
 * global database handle
 */
database_t *db;

/**
 * forward declarations
 */
static void do_args(int argc, char *argv[]);

/**
 * ipsec attest --files - show files
 */
static void list_files(char *product, int pid)
{
	enumerator_t *e;
	char *file;
	bool select = TRUE;
	int fid, is_dir, count = 0;

	if (pid)
	{
		e = db->query(db,
				"SELECT f.id, f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.id = ? ORDER BY f.path",
				DB_INT, pid, DB_INT, DB_INT, DB_TEXT);
	}
	else if (!product || *product == '\0')
	{
		select = FALSE;
		e = db->query(db,
				"SELECT id, type, path FROM files "
				"ORDER BY path",
				DB_INT, DB_INT, DB_TEXT);
	}
	else
	{
		e = db->query(db,
				"SELECT f.id, f.type, f.path FROM files AS f "
				"JOIN product_file AS pf ON f.id = pf.file "
				"JOIN products AS p ON p.id = pf.product "
				"WHERE p.name = ? ORDER BY f.path",
				DB_TEXT, product, DB_INT, DB_INT, DB_TEXT);
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
		if (select)
		{
			printf(" for product '%s'", product);
		}
		printf("\n");
	}
}

/**
 * ipsec attest --products - show products
 */
static void list_products(char *file, int fid)
{
	enumerator_t *e;
	char *product;
	bool select = TRUE;
	int pid, count = 0;

	if (fid)
	{
		e = db->query(db,
				"SELECT p.id, p.name FROM products AS p "
				"JOIN product_file AS pf ON p.id = pf.product "
				"JOIN files AS f ON f.id = pf.file "
				"WHERE f.id = ? ORDER BY p.name",
				DB_INT, fid, DB_INT, DB_TEXT);
	}
	else if (!file || *file == '\0')
	{
		select = FALSE;
		e = db->query(db, "SELECT id, name FROM products "
					  "ORDER BY name",
					  DB_INT, DB_TEXT);
	}
	else
	{
		e = db->query(db,
				"SELECT p.id, p.name FROM products AS p "
				"JOIN product_file AS pf ON p.id = pf.product "
				"JOIN files AS f ON f.id = pf.file "
				"WHERE f.path = ? ORDER BY p.name",
				DB_TEXT, file, DB_INT, DB_TEXT);
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
		if (select)
		{
			printf(" for file '%s'", file);
		}
		printf("\n");
	}
}

/**
 * get the directory if there is one from the files tables
 */
static void get_directory(int did, char **directory)
{
	enumerator_t *e;
	char *dir;

	free(*directory);
	*directory = strdup("");

	if (did)
	{
		e = db->query(db, "SELECT path from files WHERE id = ?",
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

/**
 * ipsec attest --hashes - show all file measurement hashes
 */
static void list_hashes(pts_meas_algorithms_t algo)
{
	enumerator_t *e;
	chunk_t hash;
	char *file, *dir, *product;
	int fid, fid_old = 0, did, did_old = 0, count = 0;

	dir = strdup("");

	e = db->query(db,
			"SELECT f.id, f.path, p.name, fh.hash, fh.directory "
			"FROM files AS f, products AS p, file_hashes AS fh "
			"WHERE fh.algo = ? AND f.id = fh.file AND p.id = fh.product "
			"ORDER BY fh.directory, f.path, p.name",
			DB_INT, algo, DB_INT, DB_TEXT, DB_TEXT, DB_BLOB, DB_INT);
	if (e)
	{
		while (e->enumerate(e, &fid, &file, &product, &hash, &did))
		{
			if (fid != fid_old || did != did_old)
			{
				if (did != did_old)
				{
					get_directory(did, &dir);
				}
				printf("%3d: %s%s%s\n", fid,
					   dir, slash(dir, file) ? "/" : "", file);
				fid_old = fid;
				did_old = did;
			}
			printf("     %#B '%s'\n", &hash, product);
			count++;
		}
		e->destroy(e);

		printf("%d %N value%s found\n", count, hash_algorithm_names,
			   pts_meas_algo_to_hash(algo), (count == 1) ? "" : "s");
		free(dir);
	}
}

/**
 * ipsec attest --hashes - show file measurement hashes for a given file
 */
static void list_hashes_for_file(pts_meas_algorithms_t algo, char *file, int fid)
{
	enumerator_t *e;
	chunk_t hash;
	char *product, *dir;
	int did, count = 0;

	dir = strdup("");

	if (fid)
	{
		e = db->query(db,
				"SELECT p.name, fh.hash, fh.directory "
				"FROM products AS p, file_hashes AS fh "
				"JOIN files AS f ON f.id = fh.file "
				"WHERE fh.algo = ? AND f.id = ? AND p.id = fh.product "
				"ORDER BY p.name",
				DB_INT, algo, DB_INT, fid, DB_TEXT, DB_BLOB, DB_INT);
	}
	else
	{
		e = db->query(db,
				"SELECT p.name, fh.hash, fh.directory "
				"FROM products AS p, file_hashes AS fh "
				"JOIN files AS f ON f.id = fh.file "
				"WHERE fh.algo = ? AND f.path = ? AND p.id = fh.product "
				"ORDER BY p.name",
				DB_INT, algo, DB_TEXT, file, DB_TEXT, DB_BLOB, DB_INT);
	}
	if (e)
	{
		while (e->enumerate(e, &product, &hash, &did))
		{
			printf("%#B '%s'\n", &hash, product);
			count++;
		}
		e->destroy(e);

		get_directory(did, &dir);
		printf("%d %N value%s found for file '%s%s%s'\n",
			   count, hash_algorithm_names, pts_meas_algo_to_hash(algo),
			   (count == 1) ? "" : "s",
			   dir, slash(dir, file) ? "/" : "", file);
		free(dir);
	}
}

/**
 * ipsec attest --hashes - show file measurement hashes for a given product
 */
static void list_hashes_for_product(pts_meas_algorithms_t algo,
									char *product, int pid)
{
	enumerator_t *e;
	chunk_t hash;
	char *file, *dir;
	int fid, fid_old = 0, did, did_old = 0, count = 0;

	dir = strdup("");

	if (pid)
	{
		e = db->query(db,
				"SELECT f.id, f. f.path, fh.hash, fh.directory "
				"FROM files AS f, file_hashes AS fh "
				"JOIN products AS p ON p.id = fh.product "
				"WHERE fh.algo = ? AND p.id = ? AND f.id = fh.file "
				"ORDER BY fh.directory, f.path",
				DB_INT, algo, DB_INT, pid, DB_INT, DB_TEXT, DB_BLOB, DB_INT);
	}
	else
	{
		e = db->query(db,
				"SELECT f.id, f.path, fh.hash, fh.directory "
				"FROM files AS f, file_hashes AS fh "
				"JOIN products AS p ON p.id = fh.product "
				"WHERE fh.algo = ? AND p.name = ? AND f.id = fh.file "
				"ORDER BY fh.directory, f.path",
				DB_INT, algo, DB_TEXT, product, DB_INT, DB_TEXT, DB_BLOB, DB_INT);
	}
	if (e)
	{
		while (e->enumerate(e, &fid,  &file, &hash, &did))
		{
			if (fid != fid_old || did != did_old)
			{
				if (did != did_old)
				{
					get_directory(did, &dir);
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

		printf("%d %N value%s found for product '%s'\n",
			   count, hash_algorithm_names, pts_meas_algo_to_hash(algo),
			   (count == 1) ? "" : "s", product);
		free(dir);
	}
}

/**
 * find file corresponding to primary key fid
 */
static bool fid_to_file(int fid, char **file)
{
	enumerator_t *e;
	bool found = FALSE;
	char *f;

	e = db->query(db, "SELECT path FROM files WHERE id = ?",
				  DB_INT, fid, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &f))
		{
			found = TRUE;
			*file = strdup(f);
		}
		else
		{
			printf("no file found with fid %d\n", fid);
		}
		e->destroy(e);
	}
	return found;
}

/**
 * find product corresponding to primary key pid
 */
static bool pid_to_product(int pid, char **product)
{
	enumerator_t *e;
	bool found = FALSE;
	char *p;

	e = db->query(db, "SELECT name FROM products WHERE id = ?",
				  DB_INT, pid, DB_TEXT);
	if (e)
	{
		if (e->enumerate(e, &p))
		{
			found = TRUE;
			*product = strdup(p);
		}
		else
		{
			printf("no product found with pid %d\n", pid);
		}
		e->destroy(e);
	}
	return found;
}

/**
 * atexit handler to close db on shutdown
 */
static void cleanup(void)
{
	db->destroy(db);
}

static void do_args(int argc, char *argv[])
{
	char *product = NULL, *file = NULL;
	int fid = 0, pid = 0;
	pts_meas_algorithms_t algo = PTS_MEAS_ALGO_SHA256;

	enum {
		OP_UNDEF,
		OP_USAGE,
		OP_FILES,
		OP_PRODUCTS,
		OP_HASHES,
	} operation = OP_UNDEF;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "files", no_argument, NULL, 'f' },
			{ "products", no_argument, NULL, 'p' },
			{ "hashes", no_argument, NULL, 'H' },
			{ "file", required_argument, NULL, 'F' },
			{ "product", required_argument, NULL, 'P' },
			{ "sha1", no_argument, NULL, '1' },
			{ "sha256", no_argument, NULL, '2' },
			{ "sha384", no_argument, NULL, '3' },
			{ "fid", required_argument, NULL, '4' },
			{ "pid", required_argument, NULL, '5' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				operation = OP_USAGE;
				break;
			case 'f':
				operation = OP_FILES;
				continue;
			case 'p':
				operation = OP_PRODUCTS;
				continue;
			case 'H':
				operation = OP_HASHES;
				continue;
			case 'F':
				file = optarg;
				continue;
			case 'P':
				product = optarg;
				continue;
			case '1':
				algo = PTS_MEAS_ALGO_SHA1;
				continue;
			case '2':
				algo = PTS_MEAS_ALGO_SHA256;
				continue;
			case '3':
				algo = PTS_MEAS_ALGO_SHA384;
				continue;
			case '4':
				fid = atoi(optarg);
				if (!fid_to_file(fid, &file))
				{
					exit(EXIT_FAILURE);
				}
				continue;
			case '5':
				pid = atoi(optarg);
				if (!pid_to_product(pid, &product))
				{
					exit(EXIT_FAILURE);
				}
				continue;
		}
		break;
	}

	switch (operation)
	{
		case OP_USAGE:
			usage();
			break;
		case OP_PRODUCTS:
			list_products(file, fid);
			break;
		case OP_FILES:
			list_files(product, pid);
			break;
		case OP_HASHES:
			if ((!product || *product == '\0') && (!file || *file == '\0'))
			{
				list_hashes(algo);
			}
			else if (product)
			{
				list_hashes_for_product(algo, product, pid);
			}
			else
			{
				list_hashes_for_file(algo, file, fid);
			}
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
	}

	if (fid)
	{
		free(file);
	}
	if (pid)
	{
		free(product);
	}

}

int main(int argc, char *argv[])
{
	char *uri;

	atexit(library_deinit);

	/* initialize library */
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "attest.load", "sqlite")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	uri = lib->settings->get_str(lib->settings, "attest.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "database URI attest.database not set.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "opening database failed.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	atexit(cleanup);

	do_args(argc, argv);

	exit(EXIT_SUCCESS);
}

