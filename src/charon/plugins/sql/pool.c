/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * 
 * $Id$
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>

#include <debug.h>
#include <library.h>
#include <utils/host.h>

/**
 * global database handle
 */
database_t *db;

/**
 * create a host from a blob
 */
static host_t *host_create_from_blob(chunk_t blob)
{
	return host_create_from_chunk(blob.len == 4 ? AF_INET : AF_INET6, blob, 0);
}

/**
 * print usage info
 */
static void usage()
{
	printf("\
Usage:\n\
  ipsec pool --status|--add|--del|--resize [options]\n\
  \n\
  ipsec pool --status\n\
    Show a list of installed pools with statistics.\n\
  \n\
  ipsec pool --add <name> --start <start> --end <end> --timeout <timeout>\n\
    Add a new pool to the database.\n\
      name:	   Name of the pool, as used in ipsec.conf rightsourceip=%%name\n\
      start:   Start address of the pool\n\
      end:     End address of the pool\n\
      timeout: Lease time in hours, 0 for static leases\n\
  \n\
  ipsec pool --del <name>\n\
    Delete a pool from the database.\n\
      name:   Name of the pool to delete\n\
  \n\
  ipsec pool --resize <name> --end <end>\n\
    Grow or shrink an existing pool.\n\
      name:   Name of the pool to resize\n\
      end:    New end address for the pool\n\
  \n\
  ipsec pool --leases <name> --filter <filter>\n\
    Show lease information using filters:\n\
      name:   Name of the pool to show leases from\n\
      filter: Filter stiring:\n\
  \n");
	exit(0);
}

/**
 * ipsec pool --status - show pool overview
 */
static void status()
{
	enumerator_t *pool, *lease;
	bool found = FALSE;
	
	pool = db->query(db, "SELECT id, name, start, end, timeout FROM pools",
					 DB_INT, DB_TEXT, DB_BLOB, DB_BLOB, DB_UINT);
	if (pool)
	{
		char *name;
		chunk_t start_chunk, end_chunk;
		host_t *start, *end;
		u_int id, timeout, online = 0;
	
		while (pool->enumerate(pool, &id, &name,
							   &start_chunk, &end_chunk, &timeout))
		{
			if (!found)
			{
				printf("%8s %15s %15s %8s %6s\n",
					   "name", "start", "end", "lease", "online");
				found = TRUE;
			}
			
			start = host_create_from_blob(start_chunk);
			end = host_create_from_blob(end_chunk);
			
			lease = db->query(db, "SELECT COUNT(*) FROM leases "
							  "WHERE pool = ? AND release = NULL",
							  DB_UINT, id, DB_INT);
			if (lease)
			{
				lease->enumerate(lease, &online);
				lease->destroy(lease);
			}

			printf("%8s %15H %15H ", name, start, end);
			if (timeout)
			{
				printf("%7dh ", timeout/3600);
			}
			else
			{
				printf("%8s ", "static");
			}
			printf("%6d\n", online);
			
			DESTROY_IF(start);
			DESTROY_IF(end);
		}
		pool->destroy(pool);
	}
	if (!found)
	{
		printf("no pools found.\n");
	}
	exit(0);
}

/**
 * ipsec pool --add - add a new pool
 */
static void add(char *name, host_t *start, host_t *end, int timeout)
{
	if (db->execute(db, NULL,
			"INSERT INTO pools (name, start, end, next, timeout) "
			"VALUES (?, ?, ?, ?, ?)",
			DB_TEXT, name, DB_BLOB, start->get_address(start),
			DB_BLOB, end->get_address(end), DB_BLOB, start->get_address(start),
			DB_INT, timeout*3600) != 1)
	{
		fprintf(stderr, "creating pool failed.\n");
		exit(-1);
	}
	exit(0);
}

/**
 * ipsec pool --del - delete a pool
 */
static void del(char *name)
{
	enumerator_t *query;
	u_int id;
	bool found = FALSE;
	
	query = db->query(db, "SELECT id FROM pools WHERE name = ?",
					  DB_TEXT, name, DB_UINT);
	if (!query)
	{
		fprintf(stderr, "deleting pool failed.\n");
		exit(-1);
	}
	while (query->enumerate(query, &id))
	{
		found = TRUE;
		if (db->execute(db, NULL,
				"DELETE FROM pools WHERE id = ?", DB_UINT, id) != 1 ||
			db->execute(db, NULL,
				"DELETE FROM leases WHERE pool = ?", DB_UINT, id) < 0)
		{
			fprintf(stderr, "deleting pool failed.\n");
			query->destroy(query);
			exit(-1);
		}
	}
	query->destroy(query);
	if (!found)
	{
		fprintf(stderr, "pool '%s' not found.\n", name);
		exit(-1);
	}
	exit(0);
}

/**
 * ipsec pool --resize - resize a pool
 */
static void resize(char *name, host_t *end)
{
	/* TODO: check for active leases if we are decreasing pool size */
	if (db->execute(db, NULL,
			"UPDATE pools SET end = ? WHERE name = ?",
			DB_BLOB, end->get_address(end), DB_TEXT, name) <= 0)
	{
		fprintf(stderr, "pool '%s' not found.\n", name);
		exit(-1);
	}
	exit(0);
}

/**
 * ipsec pool --leases - show lease information of a pool
 */
static void leases(char *name, char *filter)
{
	enumerator_t *query;
	chunk_t address_chunk, identity_chunk;
	int identity_type;
	u_int acquire, release;
	host_t *address;
	identification_t *identity;
	bool found = FALSE;
	
	query = db->query(db, "SELECT name, address, identities.type, "
					  "identities.data, acquire, release "
					  "FROM leases JOIN pools ON leases.pool = pools.id "
					  "JOIN identities ON leases.identity = identities.id "
					  "WHERE (? or name = ?)",
					  DB_INT, name == NULL, DB_TEXT, name,
					  DB_TEXT, DB_BLOB, DB_INT, DB_BLOB, DB_UINT, DB_UINT);
	if (!query)
	{
		fprintf(stderr, "querying leases failed.\n");
		exit(-1);
	}
	while (query->enumerate(query, &name, &address_chunk,
							&identity_type, &identity_chunk, &acquire, &release))
	{
		if (!found)
		{
			found = TRUE;
			printf("%8s %15s %20s %16s %16s %7s\n",
				   "name", "address", "identity", "start", "end", "status");
		}
		address = host_create_from_blob(address_chunk);
		identity = identification_create_from_encoding(identity_type, identity_chunk);
		
		printf("%8s %15H %20D %16d %16d, %7s\n",
			   name, address, identity, acquire, release, "hum");
		DESTROY_IF(address);
		identity->destroy(identity);
	}
	query->destroy(query);
	if (!found)
	{
		fprintf(stderr, "no matching leases found.\n");
		exit(-1);
	}
	exit(0);
}

/**
 * atexit handler to close db on shutdown
 */
static void close_database(void)
{
	db->destroy(db);
}

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(int level, char *fmt, ...)
{
	va_list args;
	
	if (level <= 1)
	{
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

int main(int argc, char *argv[])
{
	char *uri, *name = "", *filter = "";
	int timeout = 0;
	host_t *start = NULL, *end = NULL;
	enum {
		OP_USAGE,
		OP_STATUS,
		OP_ADD,
		OP_DEL,
		OP_RESIZE,
		OP_LEASES,
	} operation = OP_USAGE;

	dbg = dbg_stderr;
	library_init(STRONGSWAN_CONF);
	atexit(library_deinit);
	
	lib->plugins->load(lib->plugins, IPSEC_PLUGINDIR, "libstrongswan-sqlite");
	
	uri = lib->settings->get_str(lib->settings, "charon.plugins.sql.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "database URI charon.plugins.sql.database not set.\n");
		exit(-1);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "opening database failed.\n");
		exit(-1);
	}
	atexit(close_database);
	
	while (TRUE)
	{
		int c;
		
		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			
			{ "status", no_argument, NULL, 'w' },
			{ "add", required_argument, NULL, 'a' },
			{ "del", required_argument, NULL, 'd' },
			{ "resize", required_argument, NULL, 'r' },
			{ "leases", optional_argument, NULL, 'l' },
			
			{ "start", required_argument, NULL, 's' },
			{ "end", required_argument, NULL, 'e' },
			{ "timeout", required_argument, NULL, 't' },
			{ "filter", required_argument, NULL, 'f' },
			{ 0,0,0,0 }
		};
		
		c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
	    		break;
			case 'h':
				break;
			case 'w':
				operation = OP_STATUS;
				break;
			case 'a':
				operation = OP_ADD;
				name = optarg;
				continue;
			case 'd':
				operation = OP_DEL;
				name = optarg;
				continue;
			case 'r':
				operation = OP_RESIZE;
				name = optarg;
				continue;
			case 'l':
				operation = OP_LEASES;
				name = optarg;
				continue;
			case 's':
				start = host_create_from_string(optarg, 0);
				if (start == NULL)
				{
					fprintf(stderr, "invalid start address: '%s'.\n", optarg);
					operation = OP_USAGE;
					break;
				}
				continue;
			case 'e':
				end = host_create_from_string(optarg, 0);
				if (end == NULL)
				{
					fprintf(stderr, "invalid end address: '%s'.\n", optarg);
					operation = OP_USAGE;
					break;
				}
				continue;
			case 't':
				timeout = atoi(optarg);
				if (timeout == 0 && strcmp(optarg, "0") != 0)
				{
					fprintf(stderr, "invalid timeout '%s'.\n", optarg);
					operation = OP_USAGE;
					break;
				}
				continue;
			case 'f':
				filter = optarg;
				continue;
			default:
				operation = OP_USAGE;
				break;
		}
		break;
	}
	
	switch (operation)
	{
		case OP_USAGE:
			usage();
			break;
		case OP_STATUS:
			status();
			break;
		case OP_ADD:
			if (start == NULL || end == NULL)
			{
				fprintf(stderr, "missing arguments.\n");
				usage();
			}
			add(name, start, end, timeout);
			break;
		case OP_DEL:
			del(name);
			break;
		case OP_RESIZE:
			if (end == NULL)
			{
				fprintf(stderr, "missing arguments.\n");
				usage();
			}
			resize(name, end);
			break;
		case OP_LEASES:
			leases(name, filter);
			break;
	}
	exit(0);
}

