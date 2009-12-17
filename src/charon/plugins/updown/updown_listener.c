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
#include <stdio.h>

#include "updown_listener.h"

#include <daemon.h>
#include <config/child_cfg.h>

typedef struct private_updown_listener_t private_updown_listener_t;

/**
 * Private data of an updown_listener_t object.
 */
struct private_updown_listener_t {

	/**
	 * Public updown_listener_t interface.
	 */
	updown_listener_t public;

	/**
	 * List of cached interface names
	 */
	linked_list_t *iface_cache;
};

typedef struct cache_entry_t cache_entry_t;

/**
 * Cache line in the interface name cache.
 */
struct cache_entry_t {
	/** requid of the CHILD_SA */
	u_int32_t reqid;
	/** cached interface name */
	char *iface;
};

/**
 * Insert an interface name to the cache
 */
static void cache_iface(private_updown_listener_t *this, u_int32_t reqid,
						char *iface)
{
	cache_entry_t *entry = malloc_thing(cache_entry_t);

	entry->reqid = reqid;
	entry->iface = strdup(iface);

	this->iface_cache->insert_first(this->iface_cache, entry);
}

/**
 * Remove a cached interface name and return it.
 */
static char* uncache_iface(private_updown_listener_t *this, u_int32_t reqid)
{
	enumerator_t *enumerator;
	cache_entry_t *entry;
	char *iface = NULL;

	enumerator = this->iface_cache->create_enumerator(this->iface_cache);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->reqid == reqid)
		{
			this->iface_cache->remove_at(this->iface_cache, enumerator);
			iface = entry->iface;
			free(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return iface;
}

/**
 * Run the up/down script
 */
static void updown(private_updown_listener_t *this, ike_sa_t *ike_sa,
				   child_sa_t *child_sa, bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	child_cfg_t *config;
	host_t *vip, *me, *other;
	char *script;

	config = child_sa->get_config(child_sa);
	vip = ike_sa->get_virtual_ip(ike_sa, TRUE);
	script = config->get_updown(config);
	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	if (script == NULL)
	{
		return;
	}

	enumerator = child_sa->create_policy_enumerator(child_sa);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		char command[1024];
		char *my_client, *other_client, *my_client_mask, *other_client_mask;
		char *pos, *virtual_ip, *iface;
		bool is_host, is_ipv6;
		FILE *shell;

		/* get subnet/bits from string */
		if (asprintf(&my_client, "%R", my_ts) < 0)
		{
			my_client = NULL;
		}
		pos = strchr(my_client, '/');
		*pos = '\0';
		my_client_mask = pos + 1;
		pos = strchr(my_client_mask, '[');
		if (pos)
		{
			*pos = '\0';
		}
		if (asprintf(&other_client, "%R", other_ts) < 0)
		{
			other_client = NULL;
		}
		pos = strchr(other_client, '/');
		*pos = '\0';
		other_client_mask = pos + 1;
		pos = strchr(other_client_mask, '[');
		if (pos)
		{
			*pos = '\0';
		}

		if (vip)
		{
			if (asprintf(&virtual_ip, "PLUTO_MY_SOURCEIP='%H' ", vip) < 0)
			{
				virtual_ip = NULL;
			}
		}
		else
		{
			if (asprintf(&virtual_ip, "") < 0)
			{
				virtual_ip = NULL;
			}
		}

		if (up)
		{
			iface = charon->kernel_interface->get_interface(
												charon->kernel_interface, me);
			if (iface)
			{
				cache_iface(this, child_sa->get_reqid(child_sa), iface);
			}
		}
		else
		{
			iface = uncache_iface(this, child_sa->get_reqid(child_sa));
		}

		/* determine IPv4/IPv6 and client/host situation */
		is_host = my_ts->is_host(my_ts, me);
		is_ipv6 = is_host ? (me->get_family(me) == AF_INET6) :
							(my_ts->get_type(my_ts) == TS_IPV6_ADDR_RANGE);

		/* build the command with all env variables.
		 * TODO: PLUTO_PEER_CA and PLUTO_NEXT_HOP are currently missing
		 */
		snprintf(command, sizeof(command),
				 "2>&1 "
				"PLUTO_VERSION='1.1' "
				"PLUTO_VERB='%s%s%s' "
				"PLUTO_CONNECTION='%s' "
				"PLUTO_INTERFACE='%s' "
				"PLUTO_REQID='%u' "
				"PLUTO_ME='%H' "
				"PLUTO_MY_ID='%Y' "
				"PLUTO_MY_CLIENT='%s/%s' "
				"PLUTO_MY_CLIENT_NET='%s' "
				"PLUTO_MY_CLIENT_MASK='%s' "
				"PLUTO_MY_PORT='%u' "
				"PLUTO_MY_PROTOCOL='%u' "
				"PLUTO_PEER='%H' "
				"PLUTO_PEER_ID='%Y' "
				"PLUTO_PEER_CLIENT='%s/%s' "
				"PLUTO_PEER_CLIENT_NET='%s' "
				"PLUTO_PEER_CLIENT_MASK='%s' "
				"PLUTO_PEER_PORT='%u' "
				"PLUTO_PEER_PROTOCOL='%u' "
				"%s"
				"%s"
				"%s",
				 up ? "up" : "down",
				 is_host ? "-host" : "-client",
				 is_ipv6 ? "-v6" : "",
				 config->get_name(config),
				 iface ? iface : "unknown",
				 child_sa->get_reqid(child_sa),
				 me, ike_sa->get_my_id(ike_sa),
				 my_client, my_client_mask,
				 my_client, my_client_mask,
				 my_ts->get_from_port(my_ts),
				 my_ts->get_protocol(my_ts),
				 other, ike_sa->get_other_id(ike_sa),
				 other_client, other_client_mask,
				 other_client, other_client_mask,
				 other_ts->get_from_port(other_ts),
				 other_ts->get_protocol(other_ts),
				 virtual_ip,
				 config->get_hostaccess(config) ? "PLUTO_HOST_ACCESS='1' " : "",
				 script);
		free(my_client);
		free(other_client);
		free(virtual_ip);
		free(iface);

		DBG3(DBG_CHD, "running updown script: %s", command);
		shell = popen(command, "r");

		if (shell == NULL)
		{
			DBG1(DBG_CHD, "could not execute updown script '%s'", script);
			return;
		}

		while (TRUE)
		{
			char resp[128];

			if (fgets(resp, sizeof(resp), shell) == NULL)
			{
				if (ferror(shell))
				{
					DBG1(DBG_CHD, "error reading output from updown script");
					return;
				}
				else
				{
					break;
				}
			}
			else
			{
				char *e = resp + strlen(resp);
				if (e > resp && e[-1] == '\n')
				{	/* trim trailing '\n' */
					e[-1] = '\0';
				}
				DBG1(DBG_CHD, "updown: %s", resp);
			}
		}
		pclose(shell);
	}
	enumerator->destroy(enumerator);
}

/**
 * Listener implementation
 */
static bool child_state_change(private_updown_listener_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	child_sa_state_t old;

	if (ike_sa)
	{
		old = child_sa->get_state(child_sa);

		if ((old == CHILD_INSTALLED && state != CHILD_REKEYING ) ||
			(old == CHILD_DELETING && state == CHILD_DESTROYING))
		{
			updown(this, ike_sa, child_sa, FALSE);
		}
		else if (state == CHILD_INSTALLED)
		{
			updown(this, ike_sa, child_sa, TRUE);
		}
	}
	return TRUE;
}

/**
 * Implementation of updown_listener_t.destroy.
 */
static void destroy(private_updown_listener_t *this)
{
	this->iface_cache->destroy(this->iface_cache);
	free(this);
}

/**
 * See header
 */
updown_listener_t *updown_listener_create()
{
	private_updown_listener_t *this = malloc_thing(private_updown_listener_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.child_state_change = (void*)child_state_change;
	this->public.destroy = (void(*)(updown_listener_t*))destroy;

	this->iface_cache = linked_list_create();

	return &this->public;
}

