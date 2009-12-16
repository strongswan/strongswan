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
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include <debug.h>
#include <library.h>
#include <utils/host.h>
#include <utils/identification.h>
#include <attributes/attributes.h>

/**
 * global database handle
 */
database_t *db;

/**
 * --start/--end/--server addresses of various subcommands
 */
host_t *start = NULL, *end = NULL, *server = NULL;

/**
 * instead of a pool handle a DNS or NBNS attribute
 */
static bool is_attribute(char *name)
{
	return strcaseeq(name, "dns") || strcaseeq(name, "nbns") ||
		   strcaseeq(name, "wins");
}

/**
 * determine configuration attribute type
 */
static configuration_attribute_type_t get_attribute_type(char *name, host_t* addr)
{
	if (strcaseeq(name, "dns"))
	{
		return (addr->get_family(addr) == AF_INET) ? INTERNAL_IP4_DNS :
													 INTERNAL_IP6_DNS;
	}
	else
	{
		return (addr->get_family(addr) == AF_INET) ? INTERNAL_IP4_NBNS :
													 INTERNAL_IP6_NBNS;
	}
}

/**
 * calculate the size of a pool using start and end address chunk
 */
static u_int get_pool_size(chunk_t start, chunk_t end)
{
	u_int *start_ptr, *end_ptr;

	if (start.len < sizeof(u_int) || end.len < sizeof(u_int))
	{
		return 0;
	}
	start_ptr = (u_int*)(start.ptr + start.len - sizeof(u_int));
	end_ptr = (u_int*)(end.ptr + end.len - sizeof(u_int));
	return ntohl(*end_ptr) -  ntohl(*start_ptr) + 1;
}

/**
 * print usage info
 */
static void usage(void)
{
	printf("\
Usage:\n\
  ipsec pool --status|--add|--del|--resize|--purge [options]\n\
  \n\
  ipsec pool --status\n\
    Show a list of installed pools with statistics.\n\
  \n\
  ipsec pool --add <name> --start <start> --end <end> [--timeout <timeout>]\n\
    Add a new pool to the database.\n\
      name:    Name of the pool, as used in ipsec.conf rightsourceip=%%name\n\
      start:   Start address of the pool\n\
      end:     End address of the pool\n\
      timeout: Lease time in hours, 0 for static leases\n\
  \n\
  ipsec pool --add dns|nbns|wins --server <server>\n\
    Add a new DNS or NBNS server to the database.\n\
      server:  IP address of the name server\n\
  \n\
  ipsec pool --del <name>\n\
    Delete a pool from the database.\n\
      name:    Name of the pool to delete\n\
  \n\
  ipsec pool --del dns|nbns|wins [--server <server>]\n\
    Delete a specific or all DNS or NBNS servers from the database.\n\
      server:  IP address of the name server to delete\n\
  \n\
  ipsec pool --resize <name> --end <end>\n\
    Grow or shrink an existing pool.\n\
      name:    Name of the pool to resize\n\
      end:     New end address for the pool\n\
  \n\
  ipsec pool --leases [--filter <filter>] [--utc]\n\
    Show lease information using filters:\n\
      filter:  Filter string containing comma separated key=value filters,\n\
               e.g. id=alice@strongswan.org,addr=1.1.1.1\n\
                  pool:   name of the pool\n\
                  id:     assigned identity of the lease\n\
                  addr:   lease IP address\n\
                  tstamp: UNIX timestamp when lease was valid, as integer\n\
                  status: status of the lease: online|valid|expired\n\
      utc:    Show times in UTC instead of local time\n\
  \n\
  ipsec pool --purge <name>\n\
    Delete lease history of a pool:\n\
      name:    Name of the pool to purge\n\
  \n");
	exit(0);
}

/**
 * ipsec pool --status - show pool overview
 */
static void status(void)
{
	enumerator_t *ns, *pool, *lease;
	host_t *server;
	chunk_t value;
	bool found = FALSE;

	/* enumerate IPv4 DNS servers */
	ns = db->query(db, "SELECT value FROM attributes WHERE type = ?",
				   DB_INT, INTERNAL_IP4_DNS, DB_BLOB);
	if (ns)
	{
		while (ns->enumerate(ns, &value))
		{
			if (!found)
			{
				printf("dns servers:");
				found = TRUE;
			}
			server = host_create_from_chunk(AF_INET, value, 0);
			if (server)
			{
				printf(" %H", server);
				server->destroy(server);
			}
		}
		ns->destroy(ns);
	}

	/* enumerate IPv6 DNS servers */
	ns = db->query(db, "SELECT value FROM attributes WHERE type = ?",
				   DB_INT, INTERNAL_IP6_DNS, DB_BLOB);
	if (ns)
	{
		while (ns->enumerate(ns, &value))
		{
			if (!found)
			{
				printf("dns servers:");
				found = TRUE;
			}
			server = host_create_from_chunk(AF_INET6, value, 0);
			if (server)
			{
				printf(" %H", server);
				server->destroy(server);
			}
		}
		ns->destroy(ns);
	}
	if (found)
	{
		printf("\n");
	}
	else
	{
		printf("no dns servers found.\n");
	}
	found = FALSE;

	/* enumerate IPv4 NBNS servers */
	ns = db->query(db, "SELECT value FROM attributes WHERE type = ?",
				   DB_INT, INTERNAL_IP4_NBNS, DB_BLOB);
	if (ns)
	{
		while (ns->enumerate(ns, &value))
		{
			if (!found)
			{
				printf("nbns servers:");
				found = TRUE;
			}
			server = host_create_from_chunk(AF_INET, value, 0);
			if (server)
			{
				printf(" %H", server);
				server->destroy(server);
			}
		}
		ns->destroy(ns);
	}

	/* enumerate IPv6 NBNS servers */
	ns = db->query(db, "SELECT value FROM attributes WHERE type = ?",
				   DB_INT, INTERNAL_IP6_NBNS, DB_BLOB);
	if (ns)
	{
		while (ns->enumerate(ns, &value))
		{
			if (!found)
			{
				printf("nbns servers:");
				found = TRUE;
			}
			server = host_create_from_chunk(AF_INET6, value, 0);
			if (server)
			{
				printf(" %H", server);
				server->destroy(server);
			}
		}
		ns->destroy(ns);
	}
	if (found)
	{
		printf("\n");
	}
	else
	{
		printf("no nbns servers found.\n");
	}
	found = FALSE;

	pool = db->query(db, "SELECT id, name, start, end, timeout FROM pools",
					 DB_INT, DB_TEXT, DB_BLOB, DB_BLOB, DB_UINT);
	if (pool)
	{
		char *name;
		chunk_t start_chunk, end_chunk;
		host_t *start, *end;
		u_int id, timeout, online = 0, used = 0, size = 0;

		while (pool->enumerate(pool, &id, &name,
							   &start_chunk, &end_chunk, &timeout))
		{
			if (!found)
			{
				printf("%8s %15s %15s %8s %6s %11s %11s\n", "name", "start",
					   "end", "timeout", "size", "online", "usage");
				found = TRUE;
			}

			start = host_create_from_chunk(AF_UNSPEC, start_chunk, 0);
			end = host_create_from_chunk(AF_UNSPEC, end_chunk, 0);
			size = get_pool_size(start_chunk, end_chunk);
			printf("%8s %15H %15H ", name, start, end);
			if (timeout)
			{
				printf("%7dh ", timeout/3600);
			}
			else
			{
				printf("%8s ", "static");
			}
			printf("%6d ", size);
			/* get number of online hosts */
			lease = db->query(db, "SELECT COUNT(*) FROM addresses "
							  "WHERE pool = ? AND released = 0",
							  DB_UINT, id, DB_INT);
			if (lease)
			{
				lease->enumerate(lease, &online);
				lease->destroy(lease);
			}
			printf("%5d (%2d%%) ", online, online*100/size);
			/* get number of online or valid lieases */
			lease = db->query(db, "SELECT COUNT(*) FROM addresses "
							  "WHERE addresses.pool = ? "
							  "AND ((? AND acquired != 0) "
							  "     OR released = 0 OR released > ?) ",
							  DB_UINT, id, DB_UINT, !timeout,
							  DB_UINT, time(NULL) - timeout, DB_UINT);
			if (lease)
			{
				lease->enumerate(lease, &used);
				lease->destroy(lease);
			}
			printf("%5d (%2d%%) ", used, used*100/size);

			printf("\n");
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
	chunk_t start_addr, end_addr, cur_addr;
	u_int id, count;

	start_addr = start->get_address(start);
	end_addr = end->get_address(end);
	cur_addr = chunk_clonea(start_addr);
	count = get_pool_size(start_addr, end_addr);

	if (start_addr.len != end_addr.len ||
		memcmp(start_addr.ptr, end_addr.ptr, start_addr.len) > 0)
	{
		fprintf(stderr, "invalid start/end pair specified.\n");
		exit(-1);
	}
	if (db->execute(db, &id,
			"INSERT INTO pools (name, start, end, timeout) "
			"VALUES (?, ?, ?, ?)",
			DB_TEXT, name, DB_BLOB, start_addr,
			DB_BLOB, end_addr, DB_INT, timeout*3600) != 1)
	{
		fprintf(stderr, "creating pool failed.\n");
		exit(-1);
	}
	printf("allocating %d addresses... ", count);
	fflush(stdout);
	if (db->get_driver(db) == DB_SQLITE)
	{	/* run population in a transaction for sqlite */
		db->execute(db, NULL, "BEGIN TRANSACTION");
	}
	while (TRUE)
	{
		db->execute(db, NULL,
			"INSERT INTO addresses (pool, address, identity, acquired, released) "
			"VALUES (?, ?, ?, ?, ?)",
			DB_UINT, id, DB_BLOB, cur_addr,	DB_UINT, 0, DB_UINT, 0, DB_UINT, 1);
		if (chunk_equals(cur_addr, end_addr))
		{
			break;
		}
		chunk_increment(cur_addr);
	}
	if (db->get_driver(db) == DB_SQLITE)
	{
		db->execute(db, NULL, "END TRANSACTION");
	}
	printf("done.\n", count);

	exit(0);
}

/**
 * ipsec pool --add dns|nbns|wins - add a DNS or NBNS server entry
 */
static void add_attr(char *name, host_t *server)
{
	configuration_attribute_type_t type;
	chunk_t value;

	type = get_attribute_type(name, server);
	value = server->get_address(server);
	if (db->execute(db, NULL,
			"INSERT INTO attributes (type, value) VALUES (?, ?)",
			DB_INT, type, DB_BLOB, value) != 1)
	{
		fprintf(stderr, "adding %s server %H failed.\n", name, server);
		exit(-1);
	}
	printf("added %s server %H\n", name, server);
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
				"DELETE FROM leases WHERE address IN ("
				" SELECT id FROM addresses WHERE pool = ?)", DB_UINT, id) < 0 ||
			db->execute(db, NULL,
				"DELETE FROM addresses WHERE pool = ?", DB_UINT, id) < 0 ||
			db->execute(db, NULL,
				"DELETE FROM pools WHERE id = ?", DB_UINT, id) < 0)
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
 * ipsec pool --del dns|nbns|wins - delete a DNS or NBNS server entry
 */
static void del_attr(char *name, host_t *server)
{
	configuration_attribute_type_t type;
	chunk_t value;
	u_int id;
	enumerator_t *query;
	bool found = FALSE;

	if (server)
	{
		type = get_attribute_type(name, server);
		value = server->get_address(server);
		query = db->query(db, 
					"SELECT id, type, value FROM attributes "
					"WHERE type = ? AND value = ?",
					DB_INT, type, DB_BLOB, value,
					DB_UINT, DB_INT, DB_BLOB);
	}
	else
	{
		configuration_attribute_type_t type_ip4, type_ip6;

		if (strcaseeq(name, "dns"))
		{
			type_ip4 = INTERNAL_IP4_DNS;
			type_ip6 = INTERNAL_IP6_DNS;
		}
		else
		{
			type_ip4 = INTERNAL_IP4_NBNS;
			type_ip6 = INTERNAL_IP6_NBNS;
		}
			
		query = db->query(db,
					"SELECT id, type, value FROM attributes "
					"WHERE type = ? OR type = ?",
					DB_INT, type_ip4, DB_INT, type_ip6,
					DB_UINT, DB_INT, DB_BLOB);
	}	
	if (!query)
	{
		fprintf(stderr, "deleting %s servers failed.\n", name);
		exit(-1);
	}

	while (query->enumerate(query, &id, &type, &value))
	{
		int family;
		host_t *host;

		found = TRUE;
		family = (type == INTERNAL_IP4_DNS || type == INTERNAL_IP4_NBNS) ?
				  AF_INET : AF_INET6;
		host = host_create_from_chunk(family, value, 0);
		if (db->execute(db, NULL,
					"DELETE FROM attributes WHERE id = ?",
					 DB_UINT, id) != 1)
		{
			fprintf(stderr, "deleting %s server %H failed\n", name, host);
			query->destroy(query);
			DESTROY_IF(host);
			exit(-1);
		}
		printf("deleted %s server %H\n", name, host);
		DESTROY_IF(host);
	}
	query->destroy(query);

	if (!found)
	{
		printf("no matching %s servers found\n", name);
		exit(-1);		
	}
	exit(0);
}

/**
 * ipsec pool --resize - resize a pool		if (db->execute(db, NULL,
					"DELETE FROM attributes WHERE type = ? AND value = ?",
					 DB_INT, type, DB_BLOB, value) != 1)
		{
			fprintf(stderr, "deleting %s server %H failed\n", name, server);
			exit(-1);
		}
		printf("deleted %s server %H\n", name, server);
		if (db->execute(db, NULL,
					"DELETE FROM attributes WHERE type = ? AND value = ?",
					 DB_INT, type, DB_BLOB, value) != 1)
		{
			fprintf(stderr, "deleting %s server %H failed\n", name, server);
			exit(-1);
		}
		printf("deleted %s server %H\n", name, server);

 */
static void resize(char *name, host_t *end)
{
	enumerator_t *query;
	chunk_t old_addr, new_addr, cur_addr;
	u_int id, count;

	new_addr = end->get_address(end);

	query = db->query(db, "SELECT id, end FROM pools WHERE name = ?",
					  DB_TEXT, name, DB_UINT, DB_BLOB);
	if (!query || !query->enumerate(query, &id, &old_addr))
	{
		DESTROY_IF(query);
		fprintf(stderr, "resizing pool failed.\n");
		exit(-1);
	}
	if (old_addr.len != new_addr.len ||
		memcmp(new_addr.ptr, old_addr.ptr, old_addr.len) < 0)
	{
		fprintf(stderr, "shrinking of pools not supported.\n");
		query->destroy(query);
		exit(-1);
	}
	cur_addr = chunk_clonea(old_addr);
	count = get_pool_size(old_addr, new_addr) - 1;
	query->destroy(query);

	if (db->execute(db, NULL,
			"UPDATE pools SET end = ? WHERE name = ?",
			DB_BLOB, new_addr, DB_TEXT, name) <= 0)
	{
		fprintf(stderr, "pool '%s' not found.\n", name);
		exit(-1);
	}

	printf("allocating %d new addresses... ", count);
	fflush(stdout);
	if (db->get_driver(db) == DB_SQLITE)
	{	/* run population in a transaction for sqlite */
		db->execute(db, NULL, "BEGIN TRANSACTION");
	}
	while (count-- > 0)
	{
		chunk_increment(cur_addr);
		db->execute(db, NULL,
			"INSERT INTO addresses (pool, address, identity, acquired, released) "
			"VALUES (?, ?, ?, ?, ?)",
			DB_UINT, id, DB_BLOB, cur_addr,	DB_UINT, 0, DB_UINT, 0, DB_UINT, 1);
	}
	if (db->get_driver(db) == DB_SQLITE)
	{
		db->execute(db, NULL, "END TRANSACTION");
	}
	printf("done.\n", count);

	exit(0);
}

/**
 * create the lease query using the filter string
 */
static enumerator_t *create_lease_query(char *filter)
{
	enumerator_t *query;
	identification_t *id = NULL;
	host_t *addr = NULL;
	u_int tstamp = 0;
	bool online = FALSE, valid = FALSE, expired = FALSE;
	char *value, *pos, *pool = NULL;
	enum {
		FIL_POOL = 0,
		FIL_ID,
		FIL_ADDR,
		FIL_TSTAMP,
		FIL_STATE,
	};
	char *const token[] = {
		[FIL_POOL] = "pool",
		[FIL_ID] = "id",
		[FIL_ADDR] = "addr",
		[FIL_TSTAMP] = "tstamp",
		[FIL_STATE] = "status",
		NULL
	};

	/* if the filter string contains a distinguished name as a ID, we replace
	 * ", " by "/ " in order to not confuse the getsubopt parser */
	pos = filter;
	while ((pos = strchr(pos, ',')))
	{
		if (pos[1] == ' ')
		{
			pos[0] = '/';
		}
		pos++;
	}

	while (filter && *filter != '\0')
	{
		switch (getsubopt(&filter, token, &value))
		{
			case FIL_POOL:
				if (value)
				{
					pool = value;
				}
				break;
			case FIL_ID:
				if (value)
				{
					id = identification_create_from_string(value);
				}
				break;
			case FIL_ADDR:
				if (value)
				{
					addr = host_create_from_string(value, 0);
				}
				if (!addr)
				{
					fprintf(stderr, "invalid 'addr' in filter string.\n");
					exit(-1);
				}
				break;
			case FIL_TSTAMP:
				if (value)
				{
					tstamp = atoi(value);
				}
				if (tstamp == 0)
				{
					online = TRUE;
				}
				break;
			case FIL_STATE:
				if (value)
				{
					if (streq(value, "online"))
					{
						online = TRUE;
					}
					else if (streq(value, "valid"))
					{
						valid = TRUE;
					}
					else if (streq(value, "expired"))
					{
						expired = TRUE;
					}
					else
					{
						fprintf(stderr, "invalid 'state' in filter string.\n");
						exit(-1);
					}
				}
				break;
			default:
				fprintf(stderr, "invalid filter string.\n");
				exit(-1);
				break;
		}
	}
	query = db->query(db,
				"SELECT name, addresses.address, identities.type, "
				"identities.data, leases.acquired, leases.released, timeout "
				"FROM leases JOIN addresses ON leases.address = addresses.id "
				"JOIN pools ON addresses.pool = pools.id "
				"JOIN identities ON leases.identity = identities.id "
				"WHERE (? OR name = ?) "
				"AND (? OR (identities.type = ? AND identities.data = ?)) "
				"AND (? OR addresses.address = ?) "
				"AND (? OR (? >= leases.acquired AND (? <= leases.released))) "
				"AND (? OR leases.released > ? - timeout) "
				"AND (? OR leases.released < ? - timeout) "
				"AND ? "
				"UNION "
				"SELECT name, address, identities.type, identities.data, "
				"acquired, released, timeout FROM addresses "
				"JOIN pools ON addresses.pool = pools.id "
				"JOIN identities ON addresses.identity = identities.id "
				"WHERE ? AND released = 0 "
				"AND (? OR name = ?) "
				"AND (? OR (identities.type = ? AND identities.data = ?)) "
				"AND (? OR address = ?)",
				DB_INT, pool == NULL, DB_TEXT, pool,
				DB_INT, id == NULL,
					DB_INT, id ? id->get_type(id) : 0,
					DB_BLOB, id ? id->get_encoding(id) : chunk_empty,
				DB_INT, addr == NULL,
					DB_BLOB, addr ? addr->get_address(addr) : chunk_empty,
				DB_INT, tstamp == 0, DB_UINT, tstamp, DB_UINT, tstamp,
				DB_INT, !valid, DB_INT, time(NULL),
				DB_INT, !expired, DB_INT, time(NULL),
				DB_INT, !online,
				/* union */
				DB_INT, !(valid || expired),
				DB_INT, pool == NULL, DB_TEXT, pool,
				DB_INT, id == NULL,
					DB_INT, id ? id->get_type(id) : 0,
					DB_BLOB, id ? id->get_encoding(id) : chunk_empty,
				DB_INT, addr == NULL,
					DB_BLOB, addr ? addr->get_address(addr) : chunk_empty,
				/* res */
				DB_TEXT, DB_BLOB, DB_INT, DB_BLOB, DB_UINT, DB_UINT, DB_UINT);
	/* id and addr leak but we can't destroy them until query is destroyed. */
	return query;
}

/**
 * ipsec pool --leases - show lease information of a pool
 */
static void leases(char *filter, bool utc)
{
	enumerator_t *query;
	chunk_t address_chunk, identity_chunk;
	int identity_type;
	char *name;
	u_int acquired, released, timeout;
	host_t *address;
	identification_t *identity;
	bool found = FALSE;

	query = create_lease_query(filter);
	if (!query)
	{
		fprintf(stderr, "querying leases failed.\n");
		exit(-1);
	}
	while (query->enumerate(query, &name, &address_chunk, &identity_type,
							&identity_chunk, &acquired, &released, &timeout))
	{
		if (!found)
		{
			int len = utc ? 25 : 21;

			found = TRUE;
			printf("%-8s %-15s %-7s  %-*s %-*s %s\n",
				   "name", "address", "status", len, "start", len, "end", "identity");
		}
		address = host_create_from_chunk(AF_UNSPEC, address_chunk, 0);
		identity = identification_create_from_encoding(identity_type, identity_chunk);

		printf("%-8s %-15H ", name, address);
		if (released == 0)
		{
			printf("%-7s ", "online");
		}
		else if (timeout == 0)
		{
			printf("%-7s ", "static");
		}
		else if (released >= time(NULL) - timeout)
		{
			printf("%-7s ", "valid");
		}
		else
		{
			printf("%-7s ", "expired");
		}

		printf(" %T  ", &acquired, utc);
		if (released)
		{
			printf("%T  ", &released, utc);
		}
		else
		{
			printf("                      ");
			if (utc)
			{
				printf("    ");
			}
		}
		printf("%Y\n", identity);
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
 * ipsec pool --purge - delete expired leases
 */
static void purge(char *name)
{
	int purged = 0;

	purged = db->execute(db, NULL,
				"DELETE FROM leases WHERE address IN ("
				" SELECT id FROM addresses WHERE pool IN ("
				"  SELECT id FROM pools WHERE name = ?))",
				DB_TEXT, name);
	if (purged < 0)
	{
		fprintf(stderr, "purging pool '%s' failed.\n", name);
		exit(-1);
	}
	fprintf(stderr, "purged %d leases in pool '%s'.\n", purged, name);
	exit(0);
}

/**
 * atexit handler to close db on shutdown
 */
static void cleanup(void)
{
	db->destroy(db);
	DESTROY_IF(start);
	DESTROY_IF(end);
	DESTROY_IF(server);
}

int main(int argc, char *argv[])
{
	char *uri, *name = "", *filter = "";
	int timeout = 0;
	bool utc = FALSE;
	enum {
		OP_USAGE,
		OP_STATUS,
		OP_ADD,
		OP_ADD_ATTR,
		OP_DEL,
		OP_DEL_ATTR,
		OP_RESIZE,
		OP_LEASES,
		OP_PURGE
	} operation = OP_USAGE;

	atexit(library_deinit);

	/* initialize library */
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pool", argv[0]))
	{
		fprintf(stderr, "integrity check of pool failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "pool.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	uri = lib->settings->get_str(lib->settings, "libstrongswan.plugins.attr-sql.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "database URI libstrongswan.plugins.attr-sql.database not set.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "opening database failed.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	atexit(cleanup);

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },

			{ "utc", no_argument, NULL, 'u' },
			{ "status", no_argument, NULL, 'w' },
			{ "add", required_argument, NULL, 'a' },
			{ "del", required_argument, NULL, 'd' },
			{ "resize", required_argument, NULL, 'r' },
			{ "leases", no_argument, NULL, 'l' },
			{ "purge", required_argument, NULL, 'p' },

			{ "start", required_argument, NULL, 's' },
			{ "end", required_argument, NULL, 'e' },
			{ "timeout", required_argument, NULL, 't' },
			{ "filter", required_argument, NULL, 'f' },
			{ "server", required_argument, NULL, 'v' },
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
			case 'u':
				utc = TRUE;
				continue;
			case 'a':
				name = optarg;
				operation = is_attribute(name) ? OP_ADD_ATTR : OP_ADD;
				continue;
			case 'd':
				name = optarg;
				operation = is_attribute(name) ? OP_DEL_ATTR : OP_DEL;
				continue;
			case 'r':
				name = optarg;
				operation = OP_RESIZE;
				continue;
			case 'l':
				operation = OP_LEASES;
				continue;
			case 'p':
				name = optarg;
				operation = OP_PURGE;
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
			case 'v':
				server = host_create_from_string(optarg, 0);
				if (server == NULL)
				{
					fprintf(stderr, "invalid server address: '%s'.\n", optarg);
					operation = OP_USAGE;
					break;
				}
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
		case OP_ADD_ATTR:
			if (server == NULL)
			{
				fprintf(stderr, "missing arguments.\n");
				usage();
			}
			add_attr(name, server);
			break;
		case OP_DEL:
			del(name);
			break;
		case OP_DEL_ATTR:
			del_attr(name, server);
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
			leases(filter, utc);
			break;
		case OP_PURGE:
			purge(name);
			break;
	}
	exit(0);
}

