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
				"SELECT name FROM products WHERE id = ?",
				DB_INT, pid, DB_TEXT);
		if (e)
		{
			if (e->enumerate(e, &product))
			{
				product = strdup(product);
				e->destroy(e);
			}
			else
			{
				printf("no product found with pid %d\n", pid);
				e->destroy(e);
				return;
			}
		}
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
			printf("%3d: %s %s\n", fid, is_dir ? "d":"f", file);
			count++;
		}
		e->destroy(e);

		printf("%d file%s found", count, (count == 1) ? "" : "s");
		if (select)
		{
			printf(" for product '%s'", product);
		}
		printf("\n");
		if (pid)
		{
			free(product);
		}
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
				"SELECT path FROM files WHERE id = ?",
				DB_INT, fid, DB_TEXT);
		if (e)
		{
			if (e->enumerate(e, &file))
			{
				file = strdup(file);
				e->destroy(e);
			}
			else
			{
				printf("no file found with fid %d\n", fid);
				e->destroy(e);
				return;
			}
		}
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
		if (fid)
		{
			free(file);
		}
	}
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

	enum {
		OP_UNDEF,
		OP_USAGE,
		OP_PRODUCTS,
		OP_FILES,
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
			{ "file", required_argument, NULL, 'F' },
			{ "product", required_argument, NULL, 'P' },
			{ "fid", required_argument, NULL, '1' },
			{ "pid", required_argument, NULL, '2' },
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
			case 'F':
				file = optarg;
				continue;
			case 'P':
				product = optarg;
				continue;
			case '1':
				fid = atoi(optarg);
				continue;
			case '2':
				pid = atoi(optarg);
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
		default:
			usage();
			exit(EXIT_FAILURE);
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

