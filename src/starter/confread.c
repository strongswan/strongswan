/* strongSwan IPsec config file parser
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: confread.c,v 1.37 2006/04/17 19:35:07 as Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"

#include "keywords.h"
#include "parser.h"
#include "confread.h"
#include "args.h"
#include "interfaces.h"

static const char ike_defaults[] = "3des-sha, 3des-md5";
static const char esp_defaults[] = "3des-sha1, 3des-md5";

static const char firewall_defaults[] = "ipsec _updown iptables";

static void
default_values(starter_config_t *cfg)
{
	if (cfg == NULL)
		return;

	memset(cfg, 0, sizeof(struct starter_config));

    /* is there enough space for all seen flags? */
	assert(KW_SETUP_LAST - KW_SETUP_FIRST <
		sizeof(cfg->setup.seen) * BITS_PER_BYTE);
	assert(KW_CONN_LAST  - KW_CONN_FIRST <
		sizeof(cfg->conn_default.seen) * BITS_PER_BYTE);
	assert(KW_END_LAST - KW_END_FIRST <
		sizeof(cfg->conn_default.right.seen) * BITS_PER_BYTE);
	assert(KW_CA_LAST - KW_CA_FIRST <
		sizeof(cfg->ca_default.seen) * BITS_PER_BYTE);

	cfg->setup.seen        = LEMPTY;
	cfg->setup.fragicmp    = TRUE;
	cfg->setup.hidetos     = TRUE;
	cfg->setup.uniqueids   = TRUE;
	cfg->setup.interfaces  = new_list("%defaultroute");
	cfg->setup.charonstart = TRUE;
	cfg->setup.plutostart  = TRUE;

	cfg->conn_default.seen    = LEMPTY;
	cfg->conn_default.startup = STARTUP_NO;
	cfg->conn_default.state   = STATE_IGNORE;
	cfg->conn_default.policy  = POLICY_ENCRYPT | POLICY_TUNNEL | POLICY_RSASIG | POLICY_PFS;

	cfg->conn_default.ike                   = clone_str(ike_defaults, "ike_defaults");
	cfg->conn_default.esp                   = clone_str(esp_defaults, "esp_defaults");
	cfg->conn_default.sa_ike_life_seconds   = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
	cfg->conn_default.sa_ipsec_life_seconds = PLUTO_SA_LIFE_DURATION_DEFAULT;
	cfg->conn_default.sa_rekey_margin       = SA_REPLACEMENT_MARGIN_DEFAULT;
	cfg->conn_default.sa_rekey_fuzz         = SA_REPLACEMENT_FUZZ_DEFAULT;
	cfg->conn_default.sa_keying_tries       = SA_REPLACEMENT_RETRIES_DEFAULT;
	cfg->conn_default.addr_family           = AF_INET;
	cfg->conn_default.tunnel_addr_family    = AF_INET;

	cfg->conn_default.left.seen  = LEMPTY;
	cfg->conn_default.right.seen = LEMPTY;

	anyaddr(AF_INET, &cfg->conn_default.left.addr);
	anyaddr(AF_INET, &cfg->conn_default.left.nexthop);
	anyaddr(AF_INET, &cfg->conn_default.left.srcip);
	anyaddr(AF_INET, &cfg->conn_default.right.addr);
	anyaddr(AF_INET, &cfg->conn_default.right.nexthop);
	anyaddr(AF_INET, &cfg->conn_default.right.srcip);

	cfg->ca_default.seen = LEMPTY;
}

#define KW_POLICY_FLAG(sy, sn, fl) \
		if (streq(kw->value, sy)) { conn->policy |= fl; } \
		else if (streq(kw->value, sn)) { conn->policy &= ~fl; } \
		else { plog("# bad policy value: %s=%s", kw->entry->name, kw->value); cfg->err++; }

static void
load_setup(starter_config_t *cfg, config_parsed_t *cfgp)
{
	kw_list_t *kw;

	DBG(DBG_CONTROL,
		DBG_log("Loading config setup")
    )

	for (kw = cfgp->config_setup; kw; kw = kw->next)
	{
		bool assigned = FALSE;

		kw_token_t token = kw->entry->token;
 
		if (token < KW_SETUP_FIRST || token > KW_SETUP_LAST)
		{
			plog("# unsupported keyword '%s' in config setup", kw->entry->name);
			cfg->err++;
			continue;
		}

		if (!assign_arg(token, KW_SETUP_FIRST, kw, (char *)cfg, &assigned))
		{
			plog("  bad argument value in config setup");
			cfg->err++;
			continue;
		}
	}
}

static void
kw_end(starter_conn_t *conn, starter_end_t *end, kw_token_t token
    , kw_list_t *kw, char *conn_name, starter_config_t *cfg)
{
	err_t ugh = NULL;
	bool assigned = FALSE;
	int has_port_wildcard;        /* set if port is %any */

	char *name  = kw->entry->name;
	char *value = kw->value;

	if (!assign_arg(token, KW_END_FIRST, kw, (char *)end, &assigned))
		goto err;

	if (token == KW_SENDCERT)
	{
		if (end->sendcert == CERT_YES_SEND)
			end->sendcert = CERT_ALWAYS_SEND;
		else if (end->sendcert == CERT_NO_SEND)
			end->sendcert = CERT_NEVER_SEND;
	}

	if (assigned)
		return;

	switch (token)
	{
	case KW_HOST:
		if (streq(value, "%defaultroute"))
		{
			if (cfg->defaultroute.defined)
			{
				end->addr    = cfg->defaultroute.addr;
				end->nexthop = cfg->defaultroute.nexthop;
			}
			else
			{
				plog("# default route not known: %s=%s", name, value);
				goto err;
			}
		}
		else if (streq(value,"%any"))
		{
			anyaddr(conn->addr_family, &end->addr);
		}
		else if (value[0] == '%')
		{
			if (end->iface)
				pfree(end->iface);
			end->iface = clone_str(value+1, "iface");
			if (starter_iface_find(end->iface, conn->addr_family, &end->addr, &end->nexthop) == -1)
			{
				conn->state = STATE_INVALID;
			}
		}
		else
		{
			ugh = ttoaddr(value, 0, conn->addr_family, &end->addr);
			if (ugh != NULL)
			{
				plog("# bad addr: %s=%s [%s]", name, value, ugh);
				goto err;
			}
		}
		break;
	case KW_NEXTHOP:
		if (streq(value, "%defaultroute"))
		{
			if (cfg->defaultroute.defined)
				end->nexthop = cfg->defaultroute.nexthop;
			else
			{
				plog("# default route not known: %s=%s", name, value);
				goto err;
			}
		}
		else if (streq(value, "%direct"))
			ugh = anyaddr(conn->addr_family, &end->nexthop);
		else
			ugh = ttoaddr(value, 0, conn->addr_family, &end->nexthop);

		if (ugh != NULL)
		{
			plog("# bad addr: %s=%s [%s]", name, value, ugh);
			goto err;
		}
		break;
	case KW_SUBNET:
		if ((strlen(value) >= 6 && strncmp(value,"vhost:",6) == 0)
		||  (strlen(value) >= 5 && strncmp(value,"vnet:",5) == 0))
		{
			end->virt = clone_str(value, "virt");
		}
		else
		{
			end->has_client = TRUE;
			ugh = ttosubnet(value, 0, conn->tunnel_addr_family, &end->subnet);
			if (ugh != NULL)
			{
				plog("# bad subnet: %s=%s [%s]", name, value, ugh);
				goto err;
			}
		}
		break;
	case KW_SUBNETWITHIN:
		end->has_client = TRUE;
		end->has_client_wildcard = TRUE;
		ugh = ttosubnet(value, 0, conn->tunnel_addr_family, &end->subnet);
		break;
	case KW_PROTOPORT:
		ugh = ttoprotoport(value, 0, &end->protocol, &end->port, &has_port_wildcard);
		end->has_port_wildcard = has_port_wildcard;
		break;
	case KW_SOURCEIP:
		if (streq(value, "%modeconfig") || streq(value, "%modecfg"))
		{
			end->modecfg = TRUE;
		}
		else
		{
			ugh = ttoaddr(value, 0, conn->addr_family, &end->srcip);
			if (ugh != NULL)
			{
				plog("# bad addr: %s=%s [%s]", name, value, ugh);
				goto err;
			}
			end->has_srcip = TRUE;
		}
		conn->policy |= POLICY_TUNNEL;
		break;
	default:
		break;
	}
	return;

err:
	plog("  bad argument value in conn '%s'", conn_name);
	cfg->err++;
}

/*
 * handles left|rightfirewall and left|rightupdown parameters
 */
static void
handle_firewall( const char *label, starter_end_t *end, starter_config_t *cfg)
{
	if (end->firewall && (end->seen & LELEM(KW_FIREWALL - KW_END_FIRST)))
	{
		if (end->updown != NULL)
		{
			plog("# cannot have both %sfirewall and %supdown", label, label);
			cfg->err++;
		}
		else
		{
			end->updown = clone_str(firewall_defaults, "firewall_defaults");
			end->firewall = FALSE;
		}
	}
}

/*
 * parse a conn section
 */
static void
load_conn(starter_conn_t *conn, kw_list_t *kw, starter_config_t *cfg)
{
	char *conn_name = (conn->name == NULL)? "%default":conn->name;

	for ( ; kw; kw = kw->next)
	{
		bool assigned = FALSE;

		kw_token_t token = kw->entry->token;

		if (token >= KW_LEFT_FIRST && token <= KW_LEFT_LAST)
		{
			kw_end(conn, &conn->left, token - KW_LEFT_FIRST + KW_END_FIRST
				,  kw, conn_name, cfg);
			continue;
		}
		else if (token >= KW_RIGHT_FIRST && token <= KW_RIGHT_LAST)
		{
			kw_end(conn, &conn->right, token - KW_RIGHT_FIRST + KW_END_FIRST
				 , kw, conn_name, cfg);
			continue;
		}

		if (token == KW_AUTO)
		{
			token = KW_CONN_SETUP;
		}
		else if (token == KW_ALSO)
		{
			if (cfg->parse_also)
			{
				also_t *also = alloc_thing(also_t, "also_t");

				also->name = clone_str(kw->value, "also");
				also->next = conn->also;
				conn->also = also;

				DBG(DBG_CONTROL,
					DBG_log("  also=%s", kw->value)
				)
			}
			continue;
		}

		if (token < KW_CONN_FIRST || token > KW_CONN_LAST)
		{
			plog("# unsupported keyword '%s' in conn '%s'"
				, kw->entry->name, conn_name);
			cfg->err++;
			continue;
		}

		if (!assign_arg(token, KW_CONN_FIRST, kw, (char *)conn, &assigned))
		{
			plog("  bad argument value in conn '%s'", conn_name);
			cfg->err++;
			continue;
		}

		if (assigned)
			continue;

		switch (token)
		{
		case KW_TYPE:
			conn->policy &= ~(POLICY_TUNNEL | POLICY_SHUNT_MASK);
			if (streq(kw->value, "tunnel"))
				conn->policy |= POLICY_TUNNEL;
			else if (streq(kw->value, "passthrough") || streq(kw->value, "pass"))
				conn->policy |= POLICY_SHUNT_PASS;
			else if (streq(kw->value, "drop"))
				conn->policy |= POLICY_SHUNT_DROP;
			else if (streq(kw->value, "reject"))
				conn->policy |= POLICY_SHUNT_REJECT;
			else if (strcmp(kw->value, "transport") != 0)
			{
				plog("# bad policy value: %s=%s", kw->entry->name, kw->value);
				cfg->err++;
			}
			break;
		case KW_PFS:
			KW_POLICY_FLAG("yes", "no", POLICY_PFS)
			break;
		case KW_COMPRESS:
			KW_POLICY_FLAG("yes", "no", POLICY_COMPRESS)
			break; 
		case KW_AUTH:
			KW_POLICY_FLAG("ah", "esp", POLICY_AUTHENTICATE)
			break; 
		case KW_AUTHBY:
			conn->policy &= ~(POLICY_RSASIG | POLICY_PSK | POLICY_ENCRYPT);

			if (strcmp(kw->value, "never") != 0)
			{
				char *value = kw->value;
				char *second = strchr(kw->value, '|');

				if (second != NULL)
					*second = '\0';

				/* also handles the cases secret|rsasig and rsasig|secret */
				for (;;)
				{
					if (streq(value, "rsasig"))
						conn->policy |= POLICY_RSASIG | POLICY_ENCRYPT;
					else if (streq(value, "secret"))
						conn->policy |= POLICY_PSK | POLICY_ENCRYPT;
					else
					{
						plog("# bad policy value: %s=%s", kw->entry->name, kw->value);
						cfg->err++;
						break;
					}
					if (second == NULL)
						break;
					value = second;
					second = NULL; /* traverse the loop no more than twice */
				}
			}
			break;
		case KW_REKEY:
			KW_POLICY_FLAG("no", "yes", POLICY_DONT_REKEY)
			break;
		default:
			break;
		}
	}
	handle_firewall("left", &conn->left, cfg);
	handle_firewall("right", &conn->right, cfg);
}

/*
 * initialize a conn object with the default conn
 */
static void
conn_default(char *name, starter_conn_t *conn, starter_conn_t *def)
{
	memcpy(conn, def, sizeof(starter_conn_t));
	conn->name = clone_str(name, "conn name");

	clone_args(KW_CONN_FIRST, KW_CONN_LAST, (char *)conn, (char *)def);
	clone_args(KW_END_FIRST, KW_END_LAST, (char *)&conn->left, (char *)&def->left);
	clone_args(KW_END_FIRST, KW_END_LAST, (char *)&conn->right, (char *)&def->right);
}

/*
 * parse a ca section
 */
static void
load_ca(starter_ca_t *ca, kw_list_t *kw, starter_config_t *cfg)
{
	char *ca_name = (ca->name == NULL)? "%default":ca->name;

	for ( ; kw; kw = kw->next)
	{
		bool assigned = FALSE;

		kw_token_t token = kw->entry->token;

		if (token == KW_AUTO)
		{
			token = KW_CA_SETUP;
		}
		else if (token == KW_ALSO)
		{
			if (cfg->parse_also)
			{
				also_t *also = alloc_thing(also_t, "also_t");

				also->name = clone_str(kw->value, "also");
				also->next = ca->also;
				ca->also = also;

				DBG(DBG_CONTROL,
					DBG_log("  also=%s", kw->value)
				)
	    	}
			continue;
		}

		if (token < KW_CA_FIRST || token > KW_CA_LAST)
		{
			plog("# unsupported keyword '%s' in ca '%s'", kw->entry->name, ca_name);
			cfg->err++;
			continue;
		}

		if (!assign_arg(token, KW_CA_FIRST, kw, (char *)ca, &assigned))
		{
			plog("  bad argument value in ca '%s'", ca_name);
			cfg->err++;
		}
	}

	/* treat 'route' and 'start' as 'add' */
	if (ca->startup != STARTUP_NO)
		ca->startup = STARTUP_ADD;
}

/*
 * initialize a ca object with the default ca
 */
static void
ca_default(char *name, starter_ca_t *ca, starter_ca_t *def)
{
	memcpy(ca, def, sizeof(starter_ca_t));
	ca->name = clone_str(name, "ca name");

	clone_args(KW_CA_FIRST, KW_CA_LAST, (char *)ca, (char *)def);
}

static kw_list_t*
find_also_conn(const char* name, starter_conn_t *conn, starter_config_t *cfg);

static void
load_also_conns(starter_conn_t *conn, also_t *also, starter_config_t *cfg)
{
	while (also != NULL)
	{
		kw_list_t *kw = find_also_conn(also->name, conn, cfg);

		if (kw == NULL)
		{
			plog("  conn '%s' cannot include '%s'", conn->name, also->name);
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("conn '%s' includes '%s'", conn->name, also->name)
			)
			/* only load if no error occurred in the first round */
			if (cfg->err == 0)
				load_conn(conn, kw, cfg);
		}
		also = also->next;
	}
}

/*
 * find a conn included by also
 */
static kw_list_t*
find_also_conn(const char* name, starter_conn_t *conn, starter_config_t *cfg)
{
	starter_conn_t *c = cfg->conn_first;

	while (c != NULL)
	{
		if (streq(name, c->name))
		{
			if (conn->visit == c->visit)
			{
				plog("# detected also loop");
				cfg->err++;
				return NULL;
			}
			c->visit = conn->visit;
			load_also_conns(conn, c->also, cfg);
			return c->kw;
		}
		c = c->next;
	}

	plog("# also '%s' not found", name);
	cfg->err++;
	return NULL;
}

static kw_list_t*
find_also_ca(const char* name, starter_ca_t *ca, starter_config_t *cfg);

static void
load_also_cas(starter_ca_t *ca, also_t *also, starter_config_t *cfg)
{
	while (also != NULL)
	{
		kw_list_t *kw = find_also_ca(also->name, ca, cfg);

		if (kw == NULL)
		{
			plog("  ca '%s' cannot include '%s'", ca->name, also->name);
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("ca '%s' includes '%s'", ca->name, also->name)
			)
			/* only load if no error occurred in the first round */
			if (cfg->err == 0)
			load_ca(ca, kw, cfg);
		}
		also = also->next;
	}
}

/*
 * find a ca included by also
 */
static kw_list_t*
find_also_ca(const char* name, starter_ca_t *ca, starter_config_t *cfg)
{
	starter_ca_t *c = cfg->ca_first;

	while (c != NULL)
	{
		if (streq(name, c->name))
		{
			if (ca->visit == c->visit)
			{
				plog("# detected also loop");
				cfg->err++;
				return NULL;
			}
			c->visit = ca->visit;
			load_also_cas(ca, c->also, cfg);
			return c->kw;
		}
		c = c->next;
	}

	plog("# also '%s' not found", name);
	cfg->err++;
	return NULL;
}



/*
 * load and parse an IPsec configuration file
 */
starter_config_t *
confread_load(const char *file)
{
	starter_config_t *cfg = NULL;
	config_parsed_t  *cfgp;
	section_list_t   *sconn, *sca;
	starter_conn_t   *conn;
	starter_ca_t     *ca;

	u_int visit	= 0;

	/* load IPSec configuration file  */
	cfgp = parser_load_conf(file);
	if (!cfgp)
		return NULL;

	cfg = (starter_config_t *)alloc_thing(starter_config_t, "starter_config_t");

	/* set default values */
	default_values(cfg);

	/* determine default route */
	get_defaultroute(&cfg->defaultroute);

	/* load config setup section */
	load_setup(cfg, cfgp);

	/* in the first round parse also statements */
	cfg->parse_also = TRUE;

	/* find %default ca section */
	for (sca = cfgp->ca_first; sca; sca = sca->next)
	{
		if (streq(sca->name, "%default"))
		{
			DBG(DBG_CONTROL,
				DBG_log("Loading ca %%default")
			)
			load_ca(&cfg->ca_default, sca->kw, cfg);
		}
	}

	/* parameters defined in ca %default sections can be overloads */
	cfg->ca_default.seen = LEMPTY;

	/* load other ca sections */
	for (sca = cfgp->ca_first; sca; sca = sca->next)
	{
		/* skip %default ca section */
		if (streq(sca->name, "%default"))
			continue;

		DBG(DBG_CONTROL,
			DBG_log("Loading ca '%s'", sca->name)
		)
		ca = (starter_ca_t *)alloc_thing(starter_ca_t, "starter_ca_t");

		ca_default(sca->name, ca, &cfg->ca_default);
		ca->kw =  sca->kw;
		ca->next = NULL;

		if (cfg->ca_last)
			cfg->ca_last->next = ca;
		cfg->ca_last = ca;
		if (!cfg->ca_first)
			cfg->ca_first = ca;

		load_ca(ca, ca->kw, cfg);
	}

	for (ca = cfg->ca_first; ca; ca = ca->next)
	{
		also_t *also = ca->also;
	
		while (also != NULL)
		{
			kw_list_t *kw = find_also_ca(also->name, cfg->ca_first, cfg);

			load_ca(ca, kw, cfg);
			also = also->next;
		}

		if (ca->startup != STARTUP_NO)
			ca->state = STATE_TO_ADD;
	}

	/* find %default conn sections */
	for (sconn = cfgp->conn_first; sconn; sconn = sconn->next)
	{
		if (streq(sconn->name, "%default"))
		{
			DBG(DBG_CONTROL,
				DBG_log("Loading conn %%default")
			)
			load_conn(&cfg->conn_default, sconn->kw, cfg);
		}
	}

	/* parameter defined in conn %default sections can be overloaded */
	cfg->conn_default.seen       = LEMPTY;
	cfg->conn_default.right.seen = LEMPTY;
	cfg->conn_default.left.seen  = LEMPTY;

	/* load other conn sections */
	for (sconn = cfgp->conn_first; sconn; sconn = sconn->next)
	{
		/* skip %default conn section */
		if (streq(sconn->name, "%default"))
			continue;

		DBG(DBG_CONTROL,
			DBG_log("Loading conn '%s'", sconn->name)
		)
		conn = (starter_conn_t *)alloc_thing(starter_conn_t, "starter_conn_t");

		conn_default(sconn->name, conn, &cfg->conn_default);
		conn->kw =  sconn->kw;
		conn->next = NULL;

		if (cfg->conn_last)
			cfg->conn_last->next = conn;
		cfg->conn_last = conn;
		if (!cfg->conn_first)
			cfg->conn_first = conn;

		load_conn(conn, conn->kw, cfg);
	}

	/* in the second round do not parse also statements */
	cfg->parse_also = FALSE;

	for (ca = cfg->ca_first; ca; ca = ca->next)
	{
		ca->visit = ++visit;
		load_also_cas(ca, ca->also, cfg);

		if (ca->startup != STARTUP_NO)
			ca->state = STATE_TO_ADD;
	}

	for (conn = cfg->conn_first; conn; conn = conn->next)
	{
		conn->visit = ++visit;
		load_also_conns(conn, conn->also, cfg);

		if (conn->startup != STARTUP_NO)
			conn->state = STATE_TO_ADD;
	}

	parser_free_conf(cfgp);

	if (cfg->err)
	{
		plog("### %d parsing error%s ###", cfg->err, (cfg->err > 1)?"s":"");
		confread_free(cfg);
		cfg = NULL;
	}

	return cfg;
}

/*
 * free the memory used by also_t objects
 */
static void
free_also(also_t *head)
{
	while (head != NULL)
	{
		also_t *also = head;

		head = also->next;
		pfree(also->name);
		pfree(also);
	}
}

/*
 * free the memory used by a starter_conn_t object
 */
static void
confread_free_conn(starter_conn_t *conn)
{
	free_args(KW_END_FIRST, KW_END_LAST,  (char *)&conn->left);
	free_args(KW_END_FIRST, KW_END_LAST,  (char *)&conn->right);
	free_args(KW_CONN_NAME, KW_CONN_LAST, (char *)conn);
	free_also(conn->also);
}

/*
 * free the memory used by a starter_ca_t object
 */
static void
confread_free_ca(starter_ca_t *ca)
{
	free_args(KW_CA_NAME, KW_CA_LAST, (char *)ca);
	free_also(ca->also);
}

/*
 * free the memory used by a starter_config_t object
 */
void 
confread_free(starter_config_t *cfg)
{
	starter_conn_t *conn = cfg->conn_first;
	starter_ca_t   *ca   = cfg->ca_first;

	free_args(KW_SETUP_FIRST, KW_SETUP_LAST, (char *)cfg);

	confread_free_conn(&cfg->conn_default);

	while (conn != NULL)
	{
		starter_conn_t *conn_aux = conn;

		conn = conn->next;
		confread_free_conn(conn_aux);
		pfree(conn_aux);
	}

	confread_free_ca(&cfg->ca_default);

	while (ca != NULL)
	{
		starter_ca_t *ca_aux = ca;

		ca = ca->next;
		confread_free_ca(ca_aux);
		pfree(ca_aux);
	}

	pfree(cfg);
}
