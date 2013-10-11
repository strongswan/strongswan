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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>

#include <library.h>
#include <utils/debug.h>

#include "keywords.h"
#include "confread.h"
#include "args.h"
#include "files.h"

#define IKE_LIFETIME_DEFAULT         10800 /* 3 hours */
#define IPSEC_LIFETIME_DEFAULT        3600 /* 1 hour */
#define SA_REPLACEMENT_MARGIN_DEFAULT  540 /* 9 minutes */
#define SA_REPLACEMENT_FUZZ_DEFAULT    100 /* 100% of margin */
#define SA_REPLACEMENT_RETRIES_DEFAULT   3

static const char ike_defaults[] = "aes128-sha1-modp2048,3des-sha1-modp1536";
static const char esp_defaults[] = "aes128-sha1,3des-sha1";

static const char firewall_defaults[] = IPSEC_SCRIPT " _updown iptables";

static bool daemon_exists(char *daemon, char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
	{
		DBG1(DBG_APP, "Disabling %sstart option, '%s' not found", daemon, path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Process deprecated keywords
 */
static bool is_deprecated(kw_token_t token, kw_list_t *kw, char *name)
{
	switch (token)
	{
		case KW_SETUP_DEPRECATED:
		case KW_PKCS11_DEPRECATED:
			DBG1(DBG_APP, "# deprecated keyword '%s' in config setup",
				 kw->entry->name);
			break;
		case KW_CONN_DEPRECATED:
		case KW_END_DEPRECATED:
		case KW_PFS_DEPRECATED:
			DBG1(DBG_APP, "# deprecated keyword '%s' in conn '%s'",
				 kw->entry->name, name);
			break;
		case KW_CA_DEPRECATED:
			DBG1(DBG_APP, "# deprecated keyword '%s' in ca '%s'",
				 kw->entry->name, name);
			break;
		default:
			return FALSE;
	}
	/* additional messages for some */
	switch (token)
	{
		case KW_PKCS11_DEPRECATED:
			DBG1(DBG_APP, "  use the 'pkcs11' plugin instead", kw->entry->name);
			break;
		case KW_PFS_DEPRECATED:
			DBG1(DBG_APP, "  PFS is enabled by specifying a DH group in the "
				 "'esp' cipher suite", kw->entry->name);
			break;
		default:
			break;
	}
	return TRUE;
}

static void default_values(starter_config_t *cfg)
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

	cfg->setup.seen        = SEEN_NONE;
	cfg->setup.uniqueids   = TRUE;

#ifdef START_CHARON
	cfg->setup.charonstart = TRUE;
#endif

	cfg->conn_default.seen    = SEEN_NONE;
	cfg->conn_default.startup = STARTUP_NO;
	cfg->conn_default.state   = STATE_IGNORE;
	cfg->conn_default.mode    = MODE_TUNNEL;
	cfg->conn_default.options = SA_OPTION_MOBIKE;

	cfg->conn_default.ike                   = strdupnull(ike_defaults);
	cfg->conn_default.esp                   = strdupnull(esp_defaults);
	cfg->conn_default.sa_ike_life_seconds   = IKE_LIFETIME_DEFAULT;
	cfg->conn_default.sa_ipsec_life_seconds = IPSEC_LIFETIME_DEFAULT;
	cfg->conn_default.sa_rekey_margin       = SA_REPLACEMENT_MARGIN_DEFAULT;
	cfg->conn_default.sa_rekey_fuzz         = SA_REPLACEMENT_FUZZ_DEFAULT;
	cfg->conn_default.sa_keying_tries       = SA_REPLACEMENT_RETRIES_DEFAULT;
	cfg->conn_default.install_policy        = TRUE;
	cfg->conn_default.dpd_delay             =  30; /* seconds */
	cfg->conn_default.dpd_timeout           = 150; /* seconds */

	cfg->conn_default.left.seen  = SEEN_NONE;
	cfg->conn_default.right.seen = SEEN_NONE;

	cfg->conn_default.left.sendcert  = CERT_SEND_IF_ASKED;
	cfg->conn_default.right.sendcert = CERT_SEND_IF_ASKED;

	cfg->conn_default.left.ikeport = 500;
	cfg->conn_default.right.ikeport = 500;

	cfg->conn_default.left.to_port = 0xffff;
	cfg->conn_default.right.to_port = 0xffff;

	cfg->ca_default.seen = SEEN_NONE;
}

#define KW_SA_OPTION_FLAG(sy, sn, fl) \
		if (streq(kw->value, sy)) { conn->options |= fl; } \
		else if (streq(kw->value, sn)) { conn->options &= ~fl; } \
		else { DBG1(DBG_APP, "# bad option value: %s=%s", kw->entry->name, kw->value); cfg->err++; }

static void load_setup(starter_config_t *cfg, config_parsed_t *cfgp)
{
	kw_list_t *kw;

	DBG2(DBG_APP, "Loading config setup");

	for (kw = cfgp->config_setup; kw; kw = kw->next)
	{
		bool assigned = FALSE;

		kw_token_t token = kw->entry->token;

		if ((int)token < KW_SETUP_FIRST || token > KW_SETUP_LAST)
		{
			DBG1(DBG_APP, "# unsupported keyword '%s' in config setup",
				 kw->entry->name);
			cfg->err++;
			continue;
		}

		if (is_deprecated(token, kw, ""))
		{
			cfg->non_fatal_err++;
			continue;
		}

		if (!assign_arg(token, KW_SETUP_FIRST, kw, (char *)cfg, &assigned))
		{
			DBG1(DBG_APP, "  bad argument value in config setup");
			cfg->err++;
			continue;
		}
	}

	/* verify the executables are actually available */
#ifdef START_CHARON
	cfg->setup.charonstart = cfg->setup.charonstart &&
							 daemon_exists(daemon_name, cmd);
#else
	cfg->setup.charonstart = FALSE;
#endif
}

static void kw_end(starter_conn_t *conn, starter_end_t *end, kw_token_t token,
				   kw_list_t *kw, char *conn_name, starter_config_t *cfg)
{
	bool assigned = FALSE;

	char *name  = kw->entry->name;
	char *value = kw->value;

	if (is_deprecated(token, kw, conn_name))
	{
		cfg->non_fatal_err++;
		return;
	}

	if (!assign_arg(token, KW_END_FIRST, kw, (char *)end, &assigned))
		goto err;

	/* post processing of some keywords that were assigned automatically */
	switch (token)
	{
	case KW_HOST:
		if (value && strlen(value) > 0 && value[0] == '%')
		{
			if (streq(value, "%defaultroute"))
			{
				value = "%any";
			}
			if (!streq(value, "%any") && !streq(value, "%any4") &&
				!streq(value, "%any6"))
			{	/* allow_any prefix */
				end->allow_any = TRUE;
				value++;
			}
		}
		free(end->host);
		end->host = strdupnull(value);
		break;
	case KW_SOURCEIP:
		conn->mode = MODE_TUNNEL;
		conn->proxy_mode = FALSE;
		break;
	case KW_SENDCERT:
		if (end->sendcert == CERT_YES_SEND)
		{
			end->sendcert = CERT_ALWAYS_SEND;
		}
		else if (end->sendcert == CERT_NO_SEND)
		{
			end->sendcert = CERT_NEVER_SEND;
		}
		break;
	default:
		break;
	}

	if (assigned)
		return;

	/* individual processing of keywords that were not assigned automatically */
	switch (token)
	{
	case KW_PROTOPORT:
	{
		struct protoent *proto;
		struct servent *svc;
		char *sep, *port = "", *endptr;
		long int p;

		sep = strchr(value, '/');
		if (sep)
		{	/* protocol/port */
			*sep = '\0';
			port = sep + 1;
		}

		if (streq(value, "%any"))
		{
			end->protocol = 0;
		}
		else
		{
			proto = getprotobyname(value);
			if (proto)
			{
				end->protocol = proto->p_proto;
			}
			else
			{
				p = strtol(value, &endptr, 0);
				if ((*value && *endptr) || p < 0 || p > 0xff)
				{
					DBG1(DBG_APP, "# bad protocol: %s=%s", name, value);
					goto err;
				}
				end->protocol = (u_int8_t)p;
			}
		}
		if (streq(port, "%any"))
		{
			end->from_port = 0;
			end->to_port = 0xffff;
		}
		else if (streq(port, "%opaque"))
		{
			end->from_port = 0xffff;
			end->to_port = 0;
		}
		else if (*port)
		{
			svc = getservbyname(port, NULL);
			if (svc)
			{
				end->from_port = end->to_port = ntohs(svc->s_port);
			}
			else
			{
				p = strtol(port, &endptr, 0);
				if (p < 0 || p > 0xffff)
				{
					DBG1(DBG_APP, "# bad port: %s=%s", name, port);
					goto err;
				}
				end->from_port = p;
				if (*endptr == '-')
				{
					port = endptr + 1;
					p = strtol(port, &endptr, 0);
					if (p < 0 || p > 0xffff)
					{
						DBG1(DBG_APP, "# bad port: %s=%s", name, port);
						goto err;
					}
				}
				end->to_port = p;
				if (*endptr)
				{
					DBG1(DBG_APP, "# bad port: %s=%s", name, port);
					goto err;
				}
			}
		}
		if (sep)
		{	/* restore the original text in case also= is used */
			*sep = '/';
		}
		break;
	}
	default:
		break;
	}
	return;

err:
	DBG1(DBG_APP, "  bad argument value in conn '%s'", conn_name);
	cfg->err++;
}

/*
 * handles left|rightfirewall and left|rightupdown parameters
 */
static void handle_firewall(const char *label, starter_end_t *end,
							starter_config_t *cfg)
{
	if (end->firewall && (end->seen & SEEN_KW(KW_FIREWALL, KW_END_FIRST)))
	{
		if (end->updown != NULL)
		{
			DBG1(DBG_APP, "# cannot have both %sfirewall and %supdown", label,
				 label);
			cfg->err++;
		}
		else
		{
			end->updown = strdupnull(firewall_defaults);
			end->firewall = FALSE;
		}
	}
}

/*
 * parse a conn section
 */
static void load_conn(starter_conn_t *conn, kw_list_t *kw, starter_config_t *cfg)
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
				also_t *also = malloc_thing(also_t);

				also->name = strdupnull(kw->value);
				also->next = conn->also;
				conn->also = also;

				DBG2(DBG_APP, "  also=%s", kw->value);
			}
			continue;
		}

		if (token < KW_CONN_FIRST || token > KW_CONN_LAST)
		{
			DBG1(DBG_APP, "# unsupported keyword '%s' in conn '%s'",
				 kw->entry->name, conn_name);
			cfg->err++;
			continue;
		}

		if (is_deprecated(token, kw, conn_name))
		{
			cfg->non_fatal_err++;
			continue;
		}

		if (!assign_arg(token, KW_CONN_FIRST, kw, (char *)conn, &assigned))
		{
			DBG1(DBG_APP, "  bad argument value in conn '%s'", conn_name);
			cfg->err++;
			continue;
		}

		if (assigned)
			continue;

		switch (token)
		{
		case KW_TYPE:
			conn->mode = MODE_TRANSPORT;
			conn->proxy_mode = FALSE;
			if (streq(kw->value, "tunnel"))
			{
				conn->mode = MODE_TUNNEL;
			}
			else if (streq(kw->value, "beet"))
			{
				conn->mode = MODE_BEET;
			}
			else if (streq(kw->value, "transport_proxy"))
			{
				conn->mode = MODE_TRANSPORT;
				conn->proxy_mode = TRUE;
			}
			else if (streq(kw->value, "passthrough") || streq(kw->value, "pass"))
			{
				conn->mode = MODE_PASS;
			}
			else if (streq(kw->value, "drop") || streq(kw->value, "reject"))
			{
				conn->mode = MODE_DROP;
			}
			else if (!streq(kw->value, "transport"))
			{
				DBG1(DBG_APP, "# bad policy value: %s=%s", kw->entry->name,
					 kw->value);
				cfg->err++;
			}
			break;
		case KW_COMPRESS:
			KW_SA_OPTION_FLAG("yes", "no", SA_OPTION_COMPRESS)
			break;
		case KW_MARK:
			if (!mark_from_string(kw->value, &conn->mark_in))
			{
				cfg->err++;
				break;
			}
			conn->mark_out = conn->mark_in;
			break;
		case KW_MARK_IN:
			if (!mark_from_string(kw->value, &conn->mark_in))
			{
				cfg->err++;
			}
			break;
		case KW_MARK_OUT:
			if (!mark_from_string(kw->value, &conn->mark_out))
			{
				cfg->err++;
			}
			break;
		case KW_TFC:
			if (streq(kw->value, "%mtu"))
			{
				conn->tfc = -1;
			}
			else
			{
				char *endptr;

				conn->tfc = strtoul(kw->value, &endptr, 10);
				if (*endptr != '\0')
				{
					DBG1(DBG_APP, "# bad integer value: %s=%s", kw->entry->name,
						 kw->value);
					cfg->err++;
				}
			}
			break;
		case KW_KEYINGTRIES:
			if (streq(kw->value, "%forever"))
			{
				conn->sa_keying_tries = 0;
			}
			else
			{
				char *endptr;

				conn->sa_keying_tries = strtoul(kw->value, &endptr, 10);
				if (*endptr != '\0')
				{
					DBG1(DBG_APP, "# bad integer value: %s=%s", kw->entry->name,
						 kw->value);
					cfg->err++;
				}
			}
			break;
		case KW_REKEY:
			KW_SA_OPTION_FLAG("no", "yes", SA_OPTION_DONT_REKEY)
			break;
		case KW_REAUTH:
			KW_SA_OPTION_FLAG("no", "yes", SA_OPTION_DONT_REAUTH)
			break;
		case KW_MOBIKE:
			KW_SA_OPTION_FLAG("yes", "no", SA_OPTION_MOBIKE)
			break;
		case KW_FORCEENCAPS:
			KW_SA_OPTION_FLAG("yes", "no", SA_OPTION_FORCE_ENCAP)
			break;
		case KW_MODECONFIG:
			KW_SA_OPTION_FLAG("push", "pull", SA_OPTION_MODECFG_PUSH)
			break;
		case KW_XAUTH:
			KW_SA_OPTION_FLAG("server", "client", SA_OPTION_XAUTH_SERVER)
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
static void conn_default(char *name, starter_conn_t *conn, starter_conn_t *def)
{
	memcpy(conn, def, sizeof(starter_conn_t));
	conn->name = strdupnull(name);

	clone_args(KW_CONN_FIRST, KW_CONN_LAST, (char *)conn, (char *)def);
	clone_args(KW_END_FIRST, KW_END_LAST, (char *)&conn->left, (char *)&def->left);
	clone_args(KW_END_FIRST, KW_END_LAST, (char *)&conn->right, (char *)&def->right);
}

/*
 * parse a ca section
 */
static void load_ca(starter_ca_t *ca, kw_list_t *kw, starter_config_t *cfg)
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
				also_t *also = malloc_thing(also_t);

				also->name = strdupnull(kw->value);
				also->next = ca->also;
				ca->also = also;

				DBG2(DBG_APP, "  also=%s", kw->value);
			}
			continue;
		}

		if (token < KW_CA_FIRST || token > KW_CA_LAST)
		{
			DBG1(DBG_APP, "# unsupported keyword '%s' in ca '%s'",
				 kw->entry->name, ca_name);
			cfg->err++;
			continue;
		}

		if (is_deprecated(token, kw, ca_name))
		{
			cfg->non_fatal_err++;
			continue;
		}

		if (!assign_arg(token, KW_CA_FIRST, kw, (char *)ca, &assigned))
		{
			DBG1(DBG_APP, "  bad argument value in ca '%s'", ca_name);
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
static void ca_default(char *name, starter_ca_t *ca, starter_ca_t *def)
{
	memcpy(ca, def, sizeof(starter_ca_t));
	ca->name = strdupnull(name);

	clone_args(KW_CA_FIRST, KW_CA_LAST, (char *)ca, (char *)def);
}

static kw_list_t* find_also_conn(const char* name, starter_conn_t *conn,
								 starter_config_t *cfg);

static void load_also_conns(starter_conn_t *conn, also_t *also,
							starter_config_t *cfg)
{
	while (also != NULL)
	{
		kw_list_t *kw = find_also_conn(also->name, conn, cfg);

		if (kw == NULL)
		{
			DBG1(DBG_APP, "  conn '%s' cannot include '%s'", conn->name,
				 also->name);
		}
		else
		{
			DBG2(DBG_APP, "conn '%s' includes '%s'", conn->name, also->name);
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
static kw_list_t* find_also_conn(const char* name, starter_conn_t *conn,
								 starter_config_t *cfg)
{
	starter_conn_t *c = cfg->conn_first;

	while (c != NULL)
	{
		if (streq(name, c->name))
		{
			if (conn->visit == c->visit)
			{
				DBG1(DBG_APP, "# detected also loop");
				cfg->err++;
				return NULL;
			}
			c->visit = conn->visit;
			load_also_conns(conn, c->also, cfg);
			return c->kw;
		}
		c = c->next;
	}

	DBG1(DBG_APP, "# also '%s' not found", name);
	cfg->err++;
	return NULL;
}

static kw_list_t* find_also_ca(const char* name, starter_ca_t *ca,
							   starter_config_t *cfg);

static void load_also_cas(starter_ca_t *ca, also_t *also, starter_config_t *cfg)
{
	while (also != NULL)
	{
		kw_list_t *kw = find_also_ca(also->name, ca, cfg);

		if (kw == NULL)
		{
			DBG1(DBG_APP, "  ca '%s' cannot include '%s'", ca->name,
				 also->name);
		}
		else
		{
			DBG2(DBG_APP, "ca '%s' includes '%s'", ca->name, also->name);
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
static kw_list_t* find_also_ca(const char* name, starter_ca_t *ca,
							   starter_config_t *cfg)
{
	starter_ca_t *c = cfg->ca_first;

	while (c != NULL)
	{
		if (streq(name, c->name))
		{
			if (ca->visit == c->visit)
			{
				DBG1(DBG_APP, "# detected also loop");
				cfg->err++;
				return NULL;
			}
			c->visit = ca->visit;
			load_also_cas(ca, c->also, cfg);
			return c->kw;
		}
		c = c->next;
	}

	DBG1(DBG_APP, "# also '%s' not found", name);
	cfg->err++;
	return NULL;
}

/*
 * free the memory used by also_t objects
 */
static void free_also(also_t *head)
{
	while (head != NULL)
	{
		also_t *also = head;

		head = also->next;
		free(also->name);
		free(also);
	}
}

/*
 * free the memory used by a starter_conn_t object
 */
static void confread_free_conn(starter_conn_t *conn)
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
void confread_free(starter_config_t *cfg)
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
		free(conn_aux);
	}

	confread_free_ca(&cfg->ca_default);

	while (ca != NULL)
	{
		starter_ca_t *ca_aux = ca;

		ca = ca->next;
		confread_free_ca(ca_aux);
		free(ca_aux);
	}

	free(cfg);
}

/*
 * load and parse an IPsec configuration file
 */
starter_config_t* confread_load(const char *file)
{
	starter_config_t *cfg = NULL;
	config_parsed_t  *cfgp;
	section_list_t   *sconn, *sca;
	starter_conn_t   *conn;
	starter_ca_t     *ca;

	u_int total_err;
	u_int visit	= 0;

	/* load IPSec configuration file  */
	cfgp = parser_load_conf(file);
	if (!cfgp)
	{
		return NULL;
	}
	cfg = malloc_thing(starter_config_t);

	/* set default values */
	default_values(cfg);

	/* load config setup section */
	load_setup(cfg, cfgp);

	/* in the first round parse also statements */
	cfg->parse_also = TRUE;

	/* find %default ca section */
	for (sca = cfgp->ca_first; sca; sca = sca->next)
	{
		if (streq(sca->name, "%default"))
		{
			DBG2(DBG_APP, "Loading ca %%default");
			load_ca(&cfg->ca_default, sca->kw, cfg);
		}
	}

	/* parameters defined in ca %default sections can be overloads */
	cfg->ca_default.seen = SEEN_NONE;

	/* load other ca sections */
	for (sca = cfgp->ca_first; sca; sca = sca->next)
	{
		u_int previous_err;

		/* skip %default ca section */
		if (streq(sca->name, "%default"))
			continue;

		DBG2(DBG_APP, "Loading ca '%s'", sca->name);
		ca = malloc_thing(starter_ca_t);

		ca_default(sca->name, ca, &cfg->ca_default);
		ca->kw =  sca->kw;
		ca->next = NULL;

		previous_err = cfg->err;
		load_ca(ca, ca->kw, cfg);
		if (cfg->err > previous_err)
		{
			/* errors occurred - free the ca */
			confread_free_ca(ca);
			cfg->non_fatal_err += cfg->err - previous_err;
			cfg->err = previous_err;
		}
		else
		{
			/* success - insert the ca into the chained list */
			if (cfg->ca_last)
				cfg->ca_last->next = ca;
			cfg->ca_last = ca;
			if (!cfg->ca_first)
				cfg->ca_first = ca;
		}
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
			DBG2(DBG_APP, "Loading conn %%default");
			load_conn(&cfg->conn_default, sconn->kw, cfg);
		}
	}

	/* parameters defined in conn %default sections can be overloaded */
	cfg->conn_default.seen       = SEEN_NONE;
	cfg->conn_default.right.seen = SEEN_NONE;
	cfg->conn_default.left.seen  = SEEN_NONE;

	/* load other conn sections */
	for (sconn = cfgp->conn_first; sconn; sconn = sconn->next)
	{
		u_int previous_err;

		/* skip %default conn section */
		if (streq(sconn->name, "%default"))
			continue;

		DBG2(DBG_APP, "Loading conn '%s'", sconn->name);
		conn = malloc_thing(starter_conn_t);

		conn_default(sconn->name, conn, &cfg->conn_default);
		conn->kw =  sconn->kw;
		conn->next = NULL;

		previous_err = cfg->err;
		load_conn(conn, conn->kw, cfg);
		if (cfg->err > previous_err)
		{
			/* error occurred - free the conn */
			confread_free_conn(conn);
			cfg->non_fatal_err += cfg->err - previous_err;
			cfg->err = previous_err;
		}
		else
		{
			/* success - insert the conn into the chained list */
			if (cfg->conn_last)
				cfg->conn_last->next = conn;
			cfg->conn_last = conn;
			if (!cfg->conn_first)
				cfg->conn_first = conn;
		}
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

	total_err = cfg->err + cfg->non_fatal_err;
	if (total_err > 0)
	{
		DBG1(DBG_APP, "### %d parsing error%s (%d fatal) ###",
			 total_err, (total_err > 1)?"s":"", cfg->err);
	}

	return cfg;
}
