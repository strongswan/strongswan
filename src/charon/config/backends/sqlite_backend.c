/**
 * @file sqlite_backend.c
 *
 * @brief Implementation of sqlite_backend_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <string.h>
#include <sqlite3.h>

#include "sqlite_backend.h"

#include <daemon.h>


typedef struct private_sqlite_backend_t private_sqlite_backend_t;

/**
 * Private data of an sqlite_backend_t object
 */
struct private_sqlite_backend_t {

	/**
	 * Public part
	 */
	sqlite_backend_t public;
	
	/**
	 * SQLite database handle
	 */
	sqlite3 *db;
};

/**
 * implements backen_t.get_ike_cfg.
 */
static ike_cfg_t *get_ike_cfg(private_sqlite_backend_t *this, 
							  host_t *my_host, host_t *other_host)
{
	return NULL;
}

/**
 * add TS with child "id" to "child_cfg"
 */
static void add_ts(private_sqlite_backend_t *this, child_cfg_t *child_cfg, int id)
{
	sqlite3_stmt *stmt;
	
	if (sqlite3_prepare_v2(this->db,
		"SELECT type, protocol, start_addr, end_addr, start_port, end_port, kind "
		"FROM traffic_selectors, child_config_traffic_selector "
			"ON traffic_selectors.oid = child_config_traffic_selector.traffic_selector "
		"WHERE child_config_traffic_selector.child_cfg = ?;",
		-1, &stmt, NULL) == SQLITE_OK &&
		sqlite3_bind_int(stmt, 1, id) == SQLITE_OK)
	{
		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			traffic_selector_t *ts;
			bool local = FALSE;
			enum {
				TS_LOCAL = 0,
				TS_REMOTE = 1,
				TS_LOCAL_DYNAMIC = 2,
				TS_REMOTE_DYNAMIC = 3,
			} kind;
			
			kind = sqlite3_column_int(stmt, 6);
			switch (kind)
			{
				case TS_LOCAL:
					local = TRUE;
					/* FALL */
				case TS_REMOTE:
					ts = traffic_selector_create_from_string(
						sqlite3_column_int(stmt, 1), 			/* protocol */
						sqlite3_column_int(stmt, 0),			/* type */
						(char*)sqlite3_column_text(stmt, 2),	/* from addr */
						sqlite3_column_int(stmt, 4),			/* from port */
						(char*)sqlite3_column_text(stmt, 3),	/* to addr */
						sqlite3_column_int(stmt, 5));			/* to port */
					break;
				case TS_LOCAL_DYNAMIC:
					local = TRUE;
					/* FALL */
				case TS_REMOTE_DYNAMIC:
					ts = traffic_selector_create_dynamic(
						sqlite3_column_int(stmt, 1), 			/* protocol */
						sqlite3_column_int(stmt, 0),			/* type */
						sqlite3_column_int(stmt, 4),			/* from port */
						sqlite3_column_int(stmt, 5));			/* to port */
					break;
				default:
					continue;
			}
			if (ts)
			{
				child_cfg->add_traffic_selector(child_cfg, local, ts);
			}
		}
	}
	sqlite3_finalize(stmt);
}

/**
 * add childrens belonging to config with "id" to "peer_cfg"
 */
static void add_children(private_sqlite_backend_t *this, peer_cfg_t *peer_cfg, int id)
{
	sqlite3_stmt *stmt;
	child_cfg_t *child_cfg;
	
	if (sqlite3_prepare_v2(this->db,
		"SELECT child_configs.oid, name, updown, hostaccess, mode, "
			   "lifetime, rekeytime, jitter "
		"FROM child_configs, peer_config_child_config "
			"ON child_configs.oid = peer_config_child_config.child_cfg "
		"WHERE peer_config_child_config.peer_cfg = ?;",
		-1, &stmt, NULL) == SQLITE_OK &&
		sqlite3_bind_int(stmt, 1, id) == SQLITE_OK)
	{
		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			child_cfg = child_cfg_create(
					(char*)sqlite3_column_text(stmt, 1), 	/* name */
					sqlite3_column_int(stmt, 5),			/* lifetime */
					sqlite3_column_int(stmt, 6), 			/* rekeytime */
					sqlite3_column_int(stmt, 7),			/* jitter */
					(char*)sqlite3_column_text(stmt, 2), 	/* updown */
					sqlite3_column_int(stmt, 3),			/* hostaccess */
					sqlite3_column_int(stmt, 4));			/* mode */
			add_ts(this, child_cfg, sqlite3_column_int(stmt, 0));
			child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
			peer_cfg->add_child_cfg(peer_cfg, child_cfg);
		}
	}
	sqlite3_finalize(stmt);
}

/**
 * processing function for get_peer_cfg and get_peer_cfg_by_name
 */
static peer_cfg_t *process_peer_cfg_row(private_sqlite_backend_t *this,
										sqlite3_stmt *stmt)
{
	host_t *local_host, *remote_host, *local_vip = NULL, *remote_vip = NULL;
	identification_t *local_id, *remote_id;
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;

	local_host = host_create_from_string((char*)sqlite3_column_text(stmt, 17), IKEV2_UDP_PORT);
	remote_host = host_create_from_string((char*)sqlite3_column_text(stmt, 18), IKEV2_UDP_PORT);
	if (sqlite3_column_text(stmt, 15))
	{
		local_vip = host_create_from_string((char*)sqlite3_column_text(stmt, 15), 0);
	}
	if (sqlite3_column_text(stmt, 16))
	{
		remote_vip = host_create_from_string((char*)sqlite3_column_text(stmt, 16), 0);
	}
	local_id = identification_create_from_string((char*)sqlite3_column_text(stmt, 2));
	remote_id = identification_create_from_string((char*)sqlite3_column_text(stmt, 3));
	if (local_host && remote_host && local_id && remote_id)
	{
		ike_cfg = ike_cfg_create(sqlite3_column_int(stmt, 19),  local_host, remote_host);		
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
		peer_cfg = peer_cfg_create(
			(char*)sqlite3_column_text(stmt, 1),		/* name */
			2, ike_cfg,	local_id, remote_id, NULL, NULL, linked_list_create(),
			sqlite3_column_int(stmt, 4),				/* cert_policy */
			sqlite3_column_int(stmt, 5),				/* auth_method */
			sqlite3_column_int(stmt, 6),				/* eap_type */
			sqlite3_column_int(stmt, 7),				/* keyingtries */
			sqlite3_column_int(stmt, 8),				/* lifetime */
			sqlite3_column_int(stmt, 9),				/* rekeytime */
			sqlite3_column_int(stmt, 10),				/* jitter */
			sqlite3_column_int(stmt, 13),				/* reauth */
			sqlite3_column_int(stmt, 14),				/* mobike */
			sqlite3_column_int(stmt, 11),				/* dpd_delay */
			sqlite3_column_int(stmt, 12),				/* dpd_action */
			local_vip, remote_vip);
		add_children(this, peer_cfg, sqlite3_column_int(stmt, 0));
		return peer_cfg;
	}
	
	DESTROY_IF(local_host);
	DESTROY_IF(remote_host);
	DESTROY_IF(local_id);
	DESTROY_IF(remote_id);
	DESTROY_IF(local_vip);
	DESTROY_IF(remote_vip);
	return NULL;
}

/**
 * implements backend_t.get_peer_cfg.
 */			
static peer_cfg_t *get_peer_cfg(private_sqlite_backend_t *this,
								identification_t *my_id, identification_t *other_id,
								ca_info_t *other_ca_info)
{
	sqlite3_stmt *stmt;
	char local[256], remote[256];
	peer_cfg_t *peer_cfg = NULL;

	snprintf(local, sizeof(local), "%D",  my_id);
	snprintf(remote, sizeof(remote), "%D", other_id);
	
	if (sqlite3_prepare_v2(this->db,
			"SELECT peer_configs.oid, name, local_id, remote_id, cert_policy, "
				   "auth_method, eap_type, keyingtries, lifetime, rekeytime, jitter, "
				   "dpd_delay, dpd_action, reauth, mobike, local_vip, remote_vip, "
				   "local, remote, certreq "
			"FROM peer_configs, ike_configs "
				"ON peer_configs.ike_cfg = ike_configs.oid "
			"WHERE local_id = ? and remote_id = ?;", -1, &stmt, NULL) == SQLITE_OK &&
		sqlite3_bind_text(stmt, 1, local, -1, SQLITE_STATIC) == SQLITE_OK &&
		sqlite3_bind_text(stmt, 2, remote, -1, SQLITE_STATIC) == SQLITE_OK &&
		sqlite3_step(stmt) == SQLITE_ROW)
	{
		peer_cfg = process_peer_cfg_row(this, stmt);
	}
	sqlite3_finalize(stmt);
	return peer_cfg;
}

/**
 * implements backend_t.get_peer_cfg_by_name.
 */			
static peer_cfg_t *get_peer_cfg_by_name(private_sqlite_backend_t *this, char *name)
{
	sqlite3_stmt *stmt;
	peer_cfg_t *peer_cfg = NULL;
	
	if (sqlite3_prepare_v2(this->db,
			"SELECT peer_configs.oid, name, local_id, remote_id, cert_policy, "
				   "auth_method, eap_type, keyingtries, lifetime, rekeytime, jitter, "
				   "dpd_delay, dpd_action, reauth, mobike, local_vip, remote_vip, "
				   "local, remote, certreq "
			"FROM peer_configs, ike_configs "
				"ON peer_configs.ike_cfg = ike_configs.oid "
			"WHERE name = ? ;", -1, &stmt, NULL) == SQLITE_OK &&
		sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
		sqlite3_step(stmt) == SQLITE_ROW)
	{
		peer_cfg = process_peer_cfg_row(this, stmt);
	}
	sqlite3_finalize(stmt);
	return peer_cfg;
}

/**
 * Implementation of backend_t.is_writable.
 */
static bool is_writeable(private_sqlite_backend_t *this)
{
    return FALSE;
}

/**
 * Implementation of backend_t.destroy.
 */
static void destroy(private_sqlite_backend_t *this)
{
	sqlite3_close(this->db);
    free(this);
}

/**
 * Described in header.
 */
backend_t *backend_create(void)
{
	private_sqlite_backend_t *this = malloc_thing(private_sqlite_backend_t);

	this->public.backend.get_ike_cfg = (ike_cfg_t* (*)(backend_t*, host_t*, host_t*))get_ike_cfg;
	this->public.backend.get_peer_cfg = (peer_cfg_t* (*)(backend_t*,identification_t*,identification_t*,ca_info_t*))get_peer_cfg;
	this->public.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	this->public.backend.is_writeable = (bool(*) (backend_t*))is_writeable;
	this->public.backend.destroy = (void (*)(backend_t*))destroy;
	
	if (sqlite3_open(IPSEC_DIR "/sqlite.db", &this->db) != SQLITE_OK)
	{
		DBG1(DBG_CFG, "opening SQLite database '" IPSEC_DIR "/sqlite.db' failed.");
		destroy(this);
		return NULL;
	}
	
	return &this->public.backend;
}

