/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2016 Andreas Steffen
 * Copyright (C) 2022 Noel Kuntze
 *
 * Copyright (C) secunet Security Networks AG
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
#include <unistd.h>

#include "updownv2_listener.h"

#include <utils/process.h>
#include <daemon.h>
#include <config/child_cfg.h>
#include <threading/mutex.h>
#include <threading/rwlock.h>

typedef struct private_updownv2_listener_t private_updownv2_listener_t;

/**
 * Private data of an updownv2_listener_t object.
 */
struct private_updownv2_listener_t {

	/**
	 * Public updownv2_listener_t interface.
	 */
	updownv2_listener_t public;

	/**
	 * List of cached interface names
	 */
	linked_list_t *iface_cache;

	/**
	 * DNS attribute handler
	 */
	updownv2_handler_t *handler;

	/*
	 * Whether to serialise execution of the updown script
	 */

	bool serialise_execution;

	/**
	 * Mutex to serialise executions of the updown script with
	 */
	mutex_t *mutex;

	/**
	 * RWlock to serialise access to the config with
	 */

	rwlock_t *config_access;
};


typedef struct cache_entry_t cache_entry_t;

/**
 * Cache line in the interface name cache.
 */
struct cache_entry_t {
	/** reqid of the CHILD_SA */
	uint32_t reqid;
	/** cached interface name */
	char *iface;
};


ENUM(updown_bus_events_names, UP,
                            CHILD_REKEY,
    "UP",
    "DOWN",
    "IKE_UPDATE",
    "CHILD_REKEY");


/**
 * Insert an interface name to the cache
 */
static void cache_iface(private_updownv2_listener_t *this, uint32_t reqid,
						char *iface)
{
	cache_entry_t *entry = malloc_thing(cache_entry_t);

	entry->reqid = reqid;
	entry->iface = strdup(iface);

	this->iface_cache->insert_first(this->iface_cache, entry);
}

/**
 * Get a cached iface and optionally remove it
 */
static char *get_cached_iface(private_updownv2_listener_t *this, uint32_t reqid, bool uncache)
{
	enumerator_t *enumerator;
	cache_entry_t *entry;
	char *iface = NULL;

	enumerator = this->iface_cache->create_enumerator(this->iface_cache);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->reqid == reqid)
		{
			iface = entry->iface;
			if (uncache)
			{
				this->iface_cache->remove_at(this->iface_cache, enumerator);
				free(entry);				
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	return iface;
}

/**
 * Allocate and push a format string to the environment
 */
static bool push_env(char *envp[], u_int count, char *fmt, ...)
{
	int i = 0;
	char *str;
	va_list args;

	while (envp[i])
	{
		if (++i + 1 >= count)
		{
			return FALSE;
		}
	}
	va_start(args, fmt);
	if (vasprintf(&str, fmt, args) >= 0)
	{
		envp[i] = str;
	}
	va_end(args);
	return envp[i] != NULL;
}

/**
 * Free all allocated environment strings
 */
static void free_env(char *envp[])
{
	int i;

	for (i = 0; envp[i]; i++)
	{
		free(envp[i]);
	}
}

/**
 * Push variables for handled DNS attributes
 */
static void push_dns_env(private_updownv2_listener_t *this, ike_sa_t *ike_sa,
						 char *envp[], u_int count)
{
	enumerator_t *enumerator;
	host_t *host;
	int v4 = 0, v6 = 0;

	if (this->handler)
	{
		enumerator = this->handler->create_dns_enumerator(this->handler,
											ike_sa->get_unique_id(ike_sa));
		while (enumerator->enumerate(enumerator, &host))
		{
			switch (host->get_family(host))
			{
				case AF_INET:
					push_env(envp, count, "STRONGSWAN_DNS4_%d=%H", ++v4, host);
					break;
				case AF_INET6:
					push_env(envp, count, "STRONGSWAN_DNS6_%d=%H", ++v6, host);
					break;
				default:
					continue;
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Push variables for local/remote virtual IPs
 */
static void push_vip_env(private_updownv2_listener_t *this, ike_sa_t *ike_sa,
						 char *envp[], u_int count, bool local)
{
	enumerator_t *enumerator;
	host_t *host;
	int v4 = 0, v6 = 0;
	bool first = TRUE;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, local);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (first)
		{	/* legacy variable for first VIP */
			first = FALSE;
			push_env(envp, count, "STRONGSWAN_%s_SOURCEIP=%H",
					 local ? "LOCAL" : "REMOTE", host);
		}
		switch (host->get_family(host))
		{
			case AF_INET:
				push_env(envp, count, "STRONGSWAN_%s_SOURCEIP4_%d=%H",
						 local ? "LOCAL" : "REMOTE", ++v4, host);
				break;
			case AF_INET6:
				push_env(envp, count, "STRONGSWAN_%s_SOURCEIP6_%d=%H",
						 local ? "LOCAL" : "REMOTE", ++v6, host);
				break;
			default:
				continue;
		}
	}
	enumerator->destroy(enumerator);
}

#define	PORT_BUF_LEN	12

/**
 * Determine proper values for port env variable
 */
static char* get_port(traffic_selector_t *me, traffic_selector_t *other,
					  char *port_buf, bool local)
{
	uint16_t port, to, from;

	switch (max(me->get_protocol(me), other->get_protocol(other)))
	{
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
		{
			port = max(me->get_from_port(me), other->get_from_port(other));
			snprintf(port_buf, PORT_BUF_LEN, "%u",
					 local ? traffic_selector_icmp_type(port)
						   : traffic_selector_icmp_code(port));
			return port_buf;
		}
	}
	if (local)
	{
		from = me->get_from_port(me);
		to   = me->get_to_port(me);
	}
	else
	{
		from = other->get_from_port(other);
		to   = other->get_to_port(other);
	}
	if (from == to || (from == 0 && to == 65535))
	{
		snprintf(port_buf, PORT_BUF_LEN, "%u", from);
	}
	else
	{
		snprintf(port_buf, PORT_BUF_LEN, "%u:%u", from, to);
	}
	return port_buf;
}

void run_script(private_updownv2_listener_t *this, char *envp[], child_cfg_t *config)
{
	int out;	
	process_t *process;	
	FILE *shell;	
	this->config_access->read_lock(this->config_access);

	if (this->serialise_execution)
	{
		this->mutex->lock(this->mutex);	
	}
	
	process = process_start_shell(envp, NULL, &out, NULL, "2>&1 %s",
								  config->get_updown(config));
	if (process)
	{
		shell = fdopen(out, "r");
		if (shell)
		{
			while (TRUE)
			{
				char resp[128];

				if (fgets(resp, sizeof(resp), shell) == NULL)
				{
					if (ferror(shell))
					{
						DBG1(DBG_CHD, "error reading from updown script");
					}
					break;
				}
				else
				{
					char *e = resp + strlen(resp);
					if (e > resp && e[-1] == '\n')
					{
						e[-1] = '\0';
					}
					DBG1(DBG_CHD, "updownv2: %s", resp);
				}
			}
			fclose(shell);
		}
		else
		{
			close(out);
		}
		process->wait(process, NULL);
	}

	if (this->serialise_execution)
	{
		this->mutex->unlock(this->mutex);	
	}
	this->config_access->unlock(this->config_access);
}


static void prepare_ike_sa_info(private_updownv2_listener_t *this, char *envp[], size_t len, ike_sa_t *ike_sa,
	updown_bus_events_t event_type)
{
	host_t *me = ike_sa->get_my_host(ike_sa), *other = ike_sa->get_other_host(ike_sa);
	ike_sa_id_t *ike_sa_id = ike_sa->get_id(ike_sa);
	push_env(envp, len, "PATH=%s", getenv("PATH"));	
	push_env(envp, len, "STRONGSWAN_VERSION=%s", VERSION);
	push_env(envp, len, "STRONGSWAN_VERB=%N", updown_bus_events_names, event_type);	
	push_env(envp, len, "STRONGSWAN_OUTSIDE_ADDR_FAMILY=%s", me->get_family(me) == AF_INET6 ? "IPv6" : "IPv4");
	push_env(envp, len, "STRONGSWAN_IKE_SA_UNIQUEID=%u", ike_sa->get_unique_id(ike_sa));

	/* these are 64 bit, how do we do or do we need to switch byte order here? */
	push_env(envp, len, "STRONGSWAN_IKE_SA_INITIATOR_SPI=0x%08llx", ike_sa_id->get_initiator_spi(ike_sa_id));
	push_env(envp, len, "STRONGSWAN_IKE_SA_RESPONDER_SPI=0x%08llx", ike_sa_id->get_responder_spi(ike_sa_id));

	push_env(envp, len, "STRONGSWAN_IKE_SA_STATE=%N", ike_sa_state_names, ike_sa->get_state(ike_sa));
	push_env(envp, len, "STRONGSWAN_LOCAL=%H", me);
	push_env(envp, len, "STRONGSWAN_LOCAL_ID=%Y", ike_sa->get_my_id(ike_sa));
	push_env(envp, len, "STRONGSWAN_LOCAL_PORT=%u", me->get_port(me));

	push_env(envp, len, "STRONGSWAN_REMOTE=%H", other);
	push_env(envp, len, "STRONGSWAN_REMOTE_PORT=%u", other->get_port(other));	
	push_env(envp, len, "STRONGSWAN_REMOTE_ID=%Y",
			 ike_sa->get_other_id(ike_sa));

	if (ike_sa->has_condition(ike_sa, COND_EAP_AUTHENTICATED) ||
		ike_sa->has_condition(ike_sa, COND_XAUTH_AUTHENTICATED))
	{
		push_env(envp, len, "STRONGSWAN_IKE_SA_EAP_ID=%Y",
				 ike_sa->get_other_eap_id(ike_sa));
	}
	push_vip_env(this, ike_sa, envp, len, TRUE);
	push_vip_env(this, ike_sa, envp, len, FALSE);

	push_dns_env(this, ike_sa, envp, len);

	if (ike_sa->has_condition(ike_sa, COND_NAT_ANY))
	{
		push_env(envp, len, "STRONGSWAN_UDP_ENC=%u",
				 other->get_port(other));
	}
}

/*
 * TODO: fill all the information from the child_sa in. To be called for each child_sa the IKE_SA has.
 */
static void add_child_sa_information(private_updownv2_listener_t *this,
	char *envp[], size_t len, ike_sa_t *ike_sa, child_sa_t *child_sa, uint32_t num_child_sa)
{
	mark_t mark;
	uint8_t mask;
	uint32_t if_id;
	bool is_host, is_ipv6;	
	enumerator_t *enumerator;
	uint32_t num_ts = 0;
	char port_buf[PORT_BUF_LEN];
	host_t *me = ike_sa->get_my_host(ike_sa), *host;	
	traffic_selector_t *my_ts, *other_ts;		
	child_cfg_t *child_sa_cfg = child_sa->get_config(child_sa);
	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_CONNECTION=%s",
			 num_child_sa, child_sa->get_name(child_sa));

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_STATE=%N",
			 num_child_sa, child_sa_state_names, child_sa->get_state(child_sa));

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_REQID=%u",
			 num_child_sa, child_sa->get_reqid(child_sa));

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_UNIQUEID=%u",
			 num_child_sa, child_sa->get_unique_id(child_sa));

	/* printed in the same order ip xfrm state shows them and spi matches in iptables/
	 * nftables apply it (hopefully?) */
	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_SPI_IN=0x%08x",
			 num_child_sa, htonl(child_sa->get_spi(child_sa, TRUE)));

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_SPI_OUT=0x%08x",
			 num_child_sa, htonl(child_sa->get_spi(child_sa, FALSE)));

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_PROTO=%s",
			 num_child_sa, child_sa->get_protocol(child_sa) == PROTO_ESP ? "esp" : "ah");

	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_MODE=%N",
			 num_child_sa, ipsec_mode_names, child_sa->get_mode(child_sa));

	mark = child_sa->get_mark(child_sa, TRUE);

	if (mark.value)
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_MARK_IN=%u/0x%08x",
				 num_child_sa, mark.value, mark.mask);
	}
	mark = child_sa->get_mark(child_sa, FALSE);

	if (mark.value)
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_MARK_OUT=%u/0x%08x",
				 num_child_sa, mark.value, mark.mask);
	}

	/* if_id_in */
	if_id = child_sa->get_if_id(child_sa, TRUE);
	if (if_id)
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_IF_ID_IN=%u", num_child_sa, if_id);
	} 

	/* if_id_out */
	if_id = child_sa->get_if_id(child_sa, FALSE);
	if (if_id)
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_IF_ID_OUT=%u", num_child_sa, if_id);
	}

	if (child_sa->get_ipcomp(child_sa) != IPCOMP_NONE)
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_IPCOMP=1", num_child_sa);
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_IPCOMP_ALGO=%N", num_child_sa, ipcomp_transform_names,  child_sa->get_ipcomp(child_sa));

		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_CPI_IN=%.8x", num_child_sa, htonl(child_sa->get_cpi(child_sa, TRUE)));
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_CPI_OUT=%.8x", num_child_sa, htonl(child_sa->get_cpi(child_sa, FALSE)));
	}

	if (child_sa_cfg->has_option(child_sa_cfg, OPT_HOSTACCESS))
	{
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_HOST_ACCESS=1", num_child_sa);
	}


	enumerator = child_sa->create_policy_enumerator(child_sa);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		/* split IPv4 and IPv6 subnets */

		/*
		 * the traffic selector is split into IPv4 and IPv6 subnets for better handling.
		 * The protocol and port information is also split off into their own variables
		 * STRONGSWAN_LOCAL_TS_SUBNET_%d=%+H/%u # will result in, for example, 
		 *	STRONGSWAN_LOCAL_TS_SUBNET_0=10.10.10.0/24
		 * STRONGSWAN_REMOTE_TS_SUBNET_%d=%+H/%u # will result in the same format as above, 
		 *	just for the remote TS
		 * STRONGSWAN_LOCAL_TS_PROTOCOL_%d=%u # will result in the protocol number for your local ts
		 * STRONGSWAN_REMOTE_TS_PROTOCOL_%d=%u # will do the same for the remote_ts as STRONGSWAN_LOCAL_TS_PROTOCOL_%d does for the local_ts
		 * STRONGSWAN_LOCAL_TS_PORT_%d=%s # will result in the port number if the port is set. It will not be set if there is no port set.
		 * STRONGSWAN_REMOTE_TS_PORT_%d=%s # will do the same for the local_ts as STRONGSWAN_LOCAL_TS_PORT_%d does for the local_ts
		 * STRONGSWAN_TS_%d_IPV6=%d # tells if the TS is IPv6 (or IPv4)
		*/
		is_host = my_ts->is_host(my_ts, me);
		if (is_host)
		{
			is_ipv6 = me->get_family(me) == AF_INET6;
		}
		else
		{
			is_ipv6 = my_ts->get_type(my_ts) == TS_IPV6_ADDR_RANGE;
		}

		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_TS_%d_IPV6=%d", num_child_sa, num_ts, is_ipv6);

		if (!my_ts->to_subnet(my_ts, &host, &mask))
		{
			DBG1(DBG_CHD, "updown approximates local TS %R "
						  "by next larger subnet", my_ts);
		}

		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_LOCAL_TS_SUBNET_%d=%+H/%u", num_child_sa, num_ts, host, mask);
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_LOCAL_TS_PROTOCOL_%d=%u", num_child_sa, num_ts, my_ts->get_protocol(my_ts));
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_LOCAL_TS_PORT=%s", num_child_sa, get_port(my_ts, other_ts, port_buf, TRUE));
		host->destroy(host);

		if (!other_ts->to_subnet(other_ts, &host, &mask))
		{
			DBG1(DBG_CHD, "updown approximates remote TS %R "
						  "by next larger subnet", other_ts);
		}

		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_REMOTE_TS_SUBNET_%d=%+H/%u", num_child_sa, num_ts, host, mask);
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_REMOTE_TS_PROTOCOL_%d=%u", num_child_sa, num_ts, other_ts->get_protocol(other_ts));
		push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_REMOTE_TS_PORT_%d=%s", num_child_sa, num_ts, get_port(my_ts, other_ts, port_buf, FALSE));
		host->destroy(host);

		num_ts++;
	}
	enumerator->destroy(enumerator);	
	push_env(envp, len, "STRONGSWAN_CHILD_SA_%u_NUM_TS=%d", num_child_sa, num_ts);

}

/**
 * handle child_sa up or down event from the bus
 */
static void child_sa_updown(private_updownv2_listener_t *this, ike_sa_t *ike_sa,
						child_sa_t *child_sa, child_cfg_t *config, bool up)
{
	host_t *me = ike_sa->get_my_host(ike_sa), *other = ike_sa->get_other_host(ike_sa), *host;
	updown_bus_events_t event_type = up ? UP : DOWN;
	char *iface;
	char *envp[256] = {};
	
	prepare_ike_sa_info(this, envp, countof(envp), ike_sa, event_type);

	add_child_sa_information(this, envp, countof(envp), ike_sa, child_sa, 0);

	if (event_type == UP)
	{
		host = charon->kernel->get_nexthop(charon->kernel, other, -1, me,
										   &iface);
		if (host && iface)
		{
			cache_iface(this, child_sa->get_reqid(child_sa), iface);
		}
		else
		{
			iface = NULL;
		}
		DESTROY_IF(host);
	}
	else
	{
		iface = get_cached_iface(this, child_sa->get_reqid(child_sa), TRUE);
	}

	push_env(envp, countof(envp), "STRONGSWAN_ROUTING_INTERFACE=%s",
			 iface ? iface : "unknown");

	this->config_access->read_lock(this->config_access);

	if (this->serialise_execution)
	{
		this->mutex->lock(this->mutex);	
	}
	run_script(this, envp, config);
	free(iface);
	free_env(envp);
}

bool handle_child_sa_rekey(private_updownv2_listener_t *this, ike_sa_t *ike_sa, child_cfg_t *config, child_sa_t *old, child_sa_t *new)
{
	char *envp[256] = {};
	prepare_ike_sa_info(this, envp, countof(envp), ike_sa, CHILD_REKEY);
	add_child_sa_information(this, envp, countof(envp), ike_sa, old, 0);
	add_child_sa_information(this, envp, countof(envp), ike_sa, new, 1);
	run_script(this, envp, config);
	return TRUE;
}

/**
 * Essentially forward all relevant information to change any fw rules or other integrations
 * for the new changed addresses
 * Populated environment variables:
 * STRONGSWAN_VERB="update"
 * STRONGSWAN_OUTSIDE_ADDR_FAMILY=%s
 * STRONGSWAN_UNIQUEID=%u
 * STRONGSWAN_LOCAL=%H
 * STRONGSWAN_LOCAL_PORT=%u
 * STRONGSWAN_LOCAL_ADDRS_NEW=%H* 
 * STRONGSWAN_LOCAL_PORT_NEW=%u
 * STRONGSWAN_LOCAL_ID=%Y
 * STRONGSWAN_REMOTE=%H
 * STRONGSWAN_REMOTE_PORT=%u
 * STRONGSWAN_REMOTE_ADDRS_NEW=%H
 * STRONGSWAN_REMOTE_PORT_NEW=%u
 * STRONGSWAN_REMOTE_ID=%Y 
 * STRONGSWAN_EAP_ID=%Y
 * STRONGSWAN_UDP_ENC=%u
 * STRONGSWAN_CHILD_SA_UPDATE_REQID_%d=%s
 * STRONGSWAN_PROTO_%d=%s
 * STRONGSWAN_MARK_IN_%d=
 * 
 */
bool handle_ike_update(private_updownv2_listener_t *this, ike_sa_t *ike_sa, host_t *local,
	host_t *remote)
{
	char *envp[256] = {}, *cpy[countof(envp)] = {};
	child_sa_t *child_sa;
	child_cfg_t *config;
	uint32_t offset = 0;
	enumerator_t *enumerator = ike_sa->create_child_sa_enumerator(ike_sa);

	/* VERSION from config.h */
	push_env(envp, countof(envp), "STRONGSWAN_VERSION=%s", VERSION);

	prepare_ike_sa_info(this, envp, countof(envp), ike_sa, IKE_UPDATE);

	/* Get offset */
	for (offset=0; envp[offset]; offset++){};

	
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		config = child_sa->get_config(child_sa);
		if (config->get_updown(config))
		{
			memcpy(&cpy, &envp, sizeof(cpy));
			add_child_sa_information(this, cpy, countof(cpy), ike_sa, child_sa, 0);
			run_script(this, cpy, config);
		}
	}
	enumerator->destroy(enumerator);
	
	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
	private_updownv2_listener_t *this, ike_sa_t *ike_sa, child_sa_t *old, child_sa_t *new)
{
	child_cfg_t *config = new->get_config(new);
	if (config->get_updown(config))
	{
		handle_child_sa_rekey(this, ike_sa, config, old, new);
	}
	return TRUE;	
}


METHOD(listener_t, child_updown, bool,
	private_updownv2_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	/* TODO: up event is also fired for reauth and down event for old IKE_SA happens later than for new IKE_SA */
	/* How do we deal with that? */
	child_cfg_t *config = child_sa->get_config(child_sa);
	if (config->get_updown(config))
	{
		child_sa_updown(this, ike_sa, child_sa, config, up);
	}
	return TRUE;
}

/**
 * need to be able to update addresses if people use them
 */

METHOD(listener_t, ike_update, bool,
	private_updownv2_listener_t *this, ike_sa_t *ike_sa, host_t *local,
    host_t *remote)
{
	return handle_ike_update(this, ike_sa, local, remote);
}

METHOD(updownv2_listener_t, destroy, void,
	private_updownv2_listener_t *this)
{
	this->iface_cache->destroy(this->iface_cache);
	this->mutex->destroy(this->mutex);
	this->config_access->destroy(this->config_access);
	free(this);
}


bool get_serialise_execution()
{
	return lib->settings->get_bool(lib->settings, "%s.plugins.updownv2.serialise_execution", FALSE, lib->ns);
}

METHOD(updownv2_listener_t, reload, bool,
	private_updownv2_listener_t *this)
{
	this->config_access->write_lock(this->config_access);
	this->serialise_execution = get_serialise_execution();
	this->config_access->unlock(this->config_access);
	return TRUE;
}


/**
 * See header
 */
updownv2_listener_t *updownv2_listener_create(updownv2_handler_t *handler)
{
	private_updownv2_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown,
				.ike_update = _ike_update,
				.child_rekey = _child_rekey,
			},
			.destroy = _destroy,
			.reload = _reload,
		},
		.iface_cache = linked_list_create(),
		.handler = handler,
		.serialise_execution = get_serialise_execution(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.config_access = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
