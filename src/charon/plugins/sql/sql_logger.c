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
 * $Id: sql_logger.c 3589 2008-03-13 14:14:44Z martin $
 */

#include <string.h>

#include "sql_logger.h"

#include <daemon.h>

typedef struct private_sql_logger_t private_sql_logger_t;

/**
 * Private data of an sql_logger_t object
 */
struct private_sql_logger_t {

	/**
	 * Public part
	 */
	sql_logger_t public;
	
	/**
	 * database connection
	 */
	database_t *db;
	
	/**
	 * logging level
	 */
	int level;
};


/**
 * Implementation of bus_listener_t.signal.
 */
static bool signal_(private_sql_logger_t *this, signal_t signal, level_t level,
					int thread, ike_sa_t* ike_sa, char *format, va_list args)
{
	if (ike_sa && level <= this->level)
	{
		char buffer[8192], local_id[64], remote_id[64], local[40], remote[40];
		char *current = buffer, *next;
		chunk_t local_spi, remote_spi;
		u_int64_t ispi, rspi;
		bool initiator;
		ike_sa_id_t *id;
	
		id = ike_sa->get_id(ike_sa);
		initiator = id->is_initiator(id);
		ispi = id->get_initiator_spi(id);
		rspi = id->get_responder_spi(id);
		if (initiator)
		{
			local_spi.ptr = (char*)&ispi;
			remote_spi.ptr = (char*)&rspi;
		}
		else
		{
			local_spi.ptr = (char*)&rspi;
			remote_spi.ptr = (char*)&ispi;
		}
		local_spi.len = remote_spi.len = sizeof(ispi);
		snprintf(local_id, sizeof(local_id), "%D", ike_sa->get_my_id(ike_sa));
		snprintf(remote_id, sizeof(remote_id), "%D", ike_sa->get_other_id(ike_sa));
		snprintf(local, sizeof(local), "%H", ike_sa->get_my_host(ike_sa));
		snprintf(remote, sizeof(remote), "%H", ike_sa->get_other_host(ike_sa));
		
		/* write in memory buffer first */
		vsnprintf(buffer, sizeof(buffer), format, args);
	
		this->db->execute(this->db, NULL, "REPLACE INTO ike_sas ("
						  "local_spi, remote_spi, id, initiator, "
						  "local_id, remote_id, local, remote) "
						  "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
						  DB_BLOB, local_spi, DB_BLOB, remote_spi,
						  DB_INT, ike_sa->get_unique_id(ike_sa),
						  DB_INT, initiator,
						  DB_TEXT, local_id, DB_TEXT, remote_id, 
						  DB_TEXT, local, DB_TEXT, remote);
		/* do a log with every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			this->db->execute(this->db, NULL,
							  "INSERT INTO logs (local_spi, signal, level, msg) "
							  "VALUES (?, ?, ?, ?)",
							  DB_BLOB, local_spi, DB_INT, signal, DB_INT, level,
							  DB_TEXT, current);
			current = next;
		}
	}
	/* always stay registered */
	return TRUE;
}

/**
 * Implementation of sql_logger_t.destroy.
 */
static void destroy(private_sql_logger_t *this)
{
	free(this);
}

/**
 * Described in header.
 */
sql_logger_t *sql_logger_create(database_t *db)
{
	private_sql_logger_t *this = malloc_thing(private_sql_logger_t);
	
	this->public.listener.signal = (bool(*)(bus_listener_t*,signal_t,level_t,int,ike_sa_t*,char*,va_list))signal_;
	this->public.destroy = (void(*)(sql_logger_t*))destroy;
	
	this->db = db;
	
	this->level = lib->settings->get_int(lib->settings,
										 "charon.plugins.sql.loglevel", 1);
	
	return &this->public;
}

