/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "vici_config.h"
#include "vici_builder.h"

#include <daemon.h>
#include <threading/rwlock.h>
#include <collections/linked_list.h>

#include <stdio.h>
#include <netdb.h>

typedef struct private_vici_config_t private_vici_config_t;

/**
 * Private data of an vici_config_t object.
 */
struct private_vici_config_t {

	/**
	 * Public vici_config_t interface.
	 */
	vici_config_t public;

	/**
	 * Dispatcher
	 */
	vici_dispatcher_t *dispatcher;

	/**
	 * List of loaded connections, as peer_cfg_t
	 */
	linked_list_t *conns;

	/**
	 * Lock for conns list
	 */
	rwlock_t *lock;
};

METHOD(backend_t, create_peer_cfg_enumerator, enumerator_t*,
	private_vici_config_t *this, identification_t *me, identification_t *other)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(this->conns->create_enumerator(this->conns),
									 (void*)this->lock->unlock, this->lock);
}

/**
 * Enumerator filter function for ike configs
 */
static bool ike_filter(void *data, peer_cfg_t **in, ike_cfg_t **out)
{
	*out = (*in)->get_ike_cfg(*in);
	return TRUE;
}

METHOD(backend_t, create_ike_cfg_enumerator, enumerator_t*,
	private_vici_config_t *this, host_t *me, host_t *other)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->conns->create_enumerator(this->conns),
									(void*)ike_filter, this->lock,
									(void*)this->lock->unlock);
}

METHOD(backend_t, get_peer_cfg_by_name, peer_cfg_t*,
	private_vici_config_t *this, char *name)
{
	peer_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	this->lock->read_lock(this->lock);
	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	return found;
}

/**
 * Create a (error) reply message
 */
static vici_message_t* create_reply(char *fmt, ...)
{
	vici_builder_t *builder;
	va_list args;

	builder = vici_builder_create();
	builder->add_kv(builder, "success", fmt ? "no" : "yes");
	if (fmt)
	{
		va_start(args, fmt);
		builder->vadd_kv(builder, "errmsg", fmt, args);
		va_end(args);
	}
	return builder->finalize(builder);
}

/**
 * A rule to parse a key/value or list item
 */
typedef struct {
	/** name of the key/value or list */
	char *name;
	/** function to parse value */
	bool (*parse)(void *out, chunk_t value);
	/** result, passed to parse() */
	void *out;
} parse_rule_t;

/**
 * Parse key/values using a rule-set
 */
static bool parse_rules(parse_rule_t *rules, int count, char *name,
						chunk_t value, vici_message_t **reply)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (streq(name, rules[i].name))
		{
			if (rules[i].parse(rules[i].out, value))
			{
				return TRUE;
			}
			*reply = create_reply("invalid value for: %s, config discarded",
								  name);
			return FALSE;
		}
	}
	*reply = create_reply("unknown option: %s, config discarded", name);
	return FALSE;
}

/**
 * Parse callback data, passed to each callback
 */
typedef struct {
	private_vici_config_t *this;
	vici_message_t *reply;
} request_data_t;

/**
 * Data associated to a peer config
 */
typedef struct {
	request_data_t *request;
	u_int32_t version;
	bool aggressive;
	bool encap;
	bool mobike;
	bool send_certreq;
	bool pull;
	cert_policy_t send_cert;
	u_int64_t dpd_delay;
	u_int64_t dpd_timeout;
	fragmentation_t fragmentation;
	unique_policy_t unique;
	u_int32_t keyingtries;
	u_int32_t local_port;
	u_int32_t remote_port;
	char *local_addrs;
	char *remote_addrs;
	linked_list_t *local;
	linked_list_t *remote;
	linked_list_t *proposals;
	linked_list_t *children;
	linked_list_t *vips;
	u_int64_t reauth_time;
	u_int64_t rekey_time;
	u_int64_t over_time;
	u_int64_t rand_time;
} peer_data_t;

/**
 * Log relevant auth config data
 */
static void log_auth(auth_cfg_t *auth)
{
	enumerator_t *enumerator;
	auth_rule_t rule;
	union {
		uintptr_t u;
		identification_t *id;
		char *str;
	} v;

	enumerator = auth->create_enumerator(auth);
	while (enumerator->enumerate(enumerator, &rule, &v))
	{
		switch (rule)
		{
			case AUTH_RULE_AUTH_CLASS:
				DBG2(DBG_CFG, "   class = %N", auth_class_names, v.u);
				break;
			case AUTH_RULE_EAP_TYPE:
				DBG2(DBG_CFG, "   eap-type = %N", eap_type_names, v.u);
				break;
			case AUTH_RULE_EAP_VENDOR:
				DBG2(DBG_CFG, "   eap-vendor = %u", v.u);
				break;
			case AUTH_RULE_XAUTH_BACKEND:
				DBG2(DBG_CFG, "   xauth = %s", v.str);
				break;
			case AUTH_RULE_CRL_VALIDATION:
				DBG2(DBG_CFG, "   revocation = %N", cert_validation_names, v.u);
				break;
			case AUTH_RULE_IDENTITY:
				DBG2(DBG_CFG, "   id = %Y", v.id);
				break;
			case AUTH_RULE_AAA_IDENTITY:
				DBG2(DBG_CFG, "   aaa_id = %Y", v.id);
				break;
			case AUTH_RULE_EAP_IDENTITY:
				DBG2(DBG_CFG, "   eap_id = %Y", v.id);
				break;
			case AUTH_RULE_XAUTH_IDENTITY:
				DBG2(DBG_CFG, "   xauth_id = %Y", v.id);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Log parsed peer data
 */
static void log_peer_data(peer_data_t *data)
{
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	host_t *host;

	DBG2(DBG_CFG, "  version = %u", data->version);
	DBG2(DBG_CFG, "  local_addrs = %s", data->local_addrs);
	DBG2(DBG_CFG, "  remote_addrs = %s", data->remote_addrs);
	DBG2(DBG_CFG, "  local_port = %u", data->local_port);
	DBG2(DBG_CFG, "  remote_port = %u", data->remote_port);
	DBG2(DBG_CFG, "  send_certreq = %u", data->send_certreq);
	DBG2(DBG_CFG, "  send_cert = %N", cert_policy_names, data->send_cert);
	DBG2(DBG_CFG, "  mobike = %u", data->mobike);
	DBG2(DBG_CFG, "  aggressive = %u", data->aggressive);
	DBG2(DBG_CFG, "  encap = %u", data->encap);
	DBG2(DBG_CFG, "  dpd_delay = %llu", data->dpd_delay);
	DBG2(DBG_CFG, "  dpd_timeout = %llu", data->dpd_timeout);
	DBG2(DBG_CFG, "  fragmentation = %u",  data->fragmentation);
	DBG2(DBG_CFG, "  unique = %N", unique_policy_names, data->unique);
	DBG2(DBG_CFG, "  keyingtries = %u", data->keyingtries);
	DBG2(DBG_CFG, "  reauth_time = %llu", data->reauth_time);
	DBG2(DBG_CFG, "  rekey_time = %llu", data->rekey_time);
	DBG2(DBG_CFG, "  over_time = %llu", data->over_time);
	DBG2(DBG_CFG, "  rand_time = %llu", data->rand_time);
	DBG2(DBG_CFG, "  proposals = %#P", data->proposals);

	if (data->vips->get_count(data->vips))
	{
		DBG2(DBG_CFG, "  vips:");
	}
	enumerator = data->vips->create_enumerator(data->vips);
	while (enumerator->enumerate(enumerator, &host))
	{
		DBG2(DBG_CFG, "   %H", host);
	}
	enumerator->destroy(enumerator);

	enumerator = data->local->create_enumerator(data->local);
	while (enumerator->enumerate(enumerator, &auth))
	{
		DBG2(DBG_CFG, "  local:");
		log_auth(auth);
	}
	enumerator->destroy(enumerator);

	enumerator = data->remote->create_enumerator(data->remote);
	while (enumerator->enumerate(enumerator, &auth))
	{
		DBG2(DBG_CFG, "  remote:");
		log_auth(auth);
	}
	enumerator->destroy(enumerator);
}

/**
 * Clean up peer config data
 */
static void free_peer_data(peer_data_t *data)
{
	data->local->destroy_offset(data->local,
									offsetof(auth_cfg_t, destroy));
	data->remote->destroy_offset(data->remote,
									offsetof(auth_cfg_t, destroy));
	data->children->destroy_offset(data->children,
									offsetof(child_cfg_t, destroy));
	data->proposals->destroy_offset(data->proposals,
									offsetof(proposal_t, destroy));
	data->vips->destroy_offset(data->vips, offsetof(host_t, destroy));
	free(data->local_addrs);
	free(data->remote_addrs);
}

/**
 * CHILD config data
 */
typedef struct {
	request_data_t *request;
	lifetime_cfg_t lft;
	char* updown;
	bool hostaccess;
	bool ipcomp;
	ipsec_mode_t mode;
	action_t dpd_action;
	u_int32_t reqid;
	u_int32_t tfc;
	mark_t mark_in;
	mark_t mark_out;
	u_int64_t inactivity;
	linked_list_t *proposals;
	linked_list_t *local_ts;
	linked_list_t *remote_ts;
} child_data_t;

/**
 * Log parsed CHILD config data
 */
static void log_child_data(child_data_t *data, char *name)
{
	DBG2(DBG_CFG, "  child %s:", name);
	DBG2(DBG_CFG, "   rekey_time = %llu", data->lft.time.rekey);
	DBG2(DBG_CFG, "   life_time = %llu", data->lft.time.life);
	DBG2(DBG_CFG, "   rand_time = %llu", data->lft.time.jitter);
	DBG2(DBG_CFG, "   rekey_bytes = %llu", data->lft.bytes.rekey);
	DBG2(DBG_CFG, "   life_bytes = %llu", data->lft.bytes.life);
	DBG2(DBG_CFG, "   rand_bytes = %llu", data->lft.bytes.jitter);
	DBG2(DBG_CFG, "   rekey_packets = %llu", data->lft.packets.rekey);
	DBG2(DBG_CFG, "   life_packets = %llu", data->lft.packets.life);
	DBG2(DBG_CFG, "   rand_packets = %llu", data->lft.packets.jitter);
	DBG2(DBG_CFG, "   updown = %s", data->updown);
	DBG2(DBG_CFG, "   hostaccess = %u", data->hostaccess);
	DBG2(DBG_CFG, "   ipcomp = %u", data->ipcomp);
	DBG2(DBG_CFG, "   mode = %N", ipsec_mode_names, data->mode);
	DBG2(DBG_CFG, "   dpd_action = %N", action_names, data->dpd_action);
	DBG2(DBG_CFG, "   reqid = %u", data->reqid);
	DBG2(DBG_CFG, "   tfc = %u", data->tfc);
	DBG2(DBG_CFG, "   mark_in = %u/%u",
		 data->mark_in.value, data->mark_in.mask);
	DBG2(DBG_CFG, "   mark_out = %u/%u",
		 data->mark_out.value, data->mark_out.mask);
	DBG2(DBG_CFG, "   inactivity = %llu", data->inactivity);
	DBG2(DBG_CFG, "   proposals = %#P", data->proposals);
	DBG2(DBG_CFG, "   local_ts = %#R", data->local_ts);
	DBG2(DBG_CFG, "   remote_ts = %#R", data->remote_ts);
}

/**
 * Clean up CHILD config data
 */
static void free_child_data(child_data_t *data)
{
	data->proposals->destroy_offset(data->proposals,
									offsetof(proposal_t, destroy));
	data->local_ts->destroy_offset(data->local_ts,
									offsetof(traffic_selector_t, destroy));
	data->remote_ts->destroy_offset(data->remote_ts,
									offsetof(traffic_selector_t, destroy));
	free(data->updown);
}

/**
 * Auth config data
 */
typedef struct {
	request_data_t *request;
	auth_cfg_t *cfg;
} auth_data_t;

/**
 * Common proposal parsing
 */
static bool parse_proposal(linked_list_t *list, protocol_id_t proto, chunk_t v)
{
	char buf[128];
	proposal_t *proposal;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	if (strcaseeq("default", buf))
	{
		proposal = proposal_create_default(proto);
	}
	else
	{
		proposal = proposal_create_from_string(proto, buf);
	}
	if (!proposal)
	{
		return FALSE;
	}
	list->insert_last(list, proposal);
	return TRUE;
}

/**
 * Parse IKE proposal
 */
CALLBACK(parse_ike_proposal, bool,
	linked_list_t *out, chunk_t v)
{
	return parse_proposal(out, PROTO_IKE, v);
}

/**
 * Parse ESP proposal
 */
CALLBACK(parse_esp_proposal, bool,
	linked_list_t *out, chunk_t v)
{
	return parse_proposal(out, PROTO_ESP, v);
}

/**
 * Parse AH proposal
 */
CALLBACK(parse_ah_proposal, bool,
	linked_list_t *out, chunk_t v)
{
	return parse_proposal(out, PROTO_AH, v);
}

/**
 * Parse a traffic selector
 */
CALLBACK(parse_ts, bool,
	linked_list_t *out, chunk_t v)
{
	char buf[128], *protoport, *sep, *port = "", *end;
	traffic_selector_t *ts;
	struct protoent *protoent;
	struct servent *svc;
	long int p;
	u_int16_t from = 0, to = 0xffff;
	u_int8_t proto = 0;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}

	protoport = strchr(buf, '[');
	if (protoport)
	{
		*(protoport++) = '\0';

		sep = strrchr(protoport, ']');
		if (!sep)
		{
			return FALSE;
		}
		*sep = '\0';

		sep = strchr(protoport, '/');
		if (sep)
		{	/* protocol/port */
			*sep = '\0';
			port = sep + 1;
		}

		if (streq(protoport, "any"))
		{
			proto = 0;
		}
		else
		{
			protoent = getprotobyname(protoport);
			if (protoent)
			{
				proto = protoent->p_proto;
			}
			else
			{
				p = strtol(protoport, &end, 0);
				if ((*protoport && *end) || p < 0 || p > 0xff)
				{
					return FALSE;
				}
				proto = (u_int8_t)p;
			}
		}
		if (streq(port, "opaque"))
		{
			from = 0xffff;
			to = 0;
		}
		else if (*port && !streq(port, "any"))
		{
			svc = getservbyname(port, NULL);
			if (svc)
			{
				from = to = ntohs(svc->s_port);
			}
			else
			{
				p = strtol(port, &end, 0);
				if (p < 0 || p > 0xffff)
				{
					return FALSE;
				}
				from = p;
				if (*end == '-')
				{
					port = end + 1;
					p = strtol(port, &end, 0);
					if (p < 0 || p > 0xffff)
					{
						return FALSE;
					}
				}
				to = p;
				if (*end)
				{
					return FALSE;
				}
			}
		}
	}
	if (streq(buf, "dynamic"))
	{
		ts = traffic_selector_create_dynamic(proto, from, to);
	}
	else
	{
		ts = traffic_selector_create_from_cidr(buf, proto, from, to);
	}
	if (!ts)
	{
		return FALSE;
	}
	out->insert_last(out, ts);
	return TRUE;
}

/**
 * Parse a string
 */
CALLBACK(parse_string, bool,
	char **out, chunk_t v)
{
	if (!chunk_printable(v, NULL, ' '))
	{
		return FALSE;
	}
	free(*out);
	*out = NULL;
	if (asprintf(out, "%.*s", (int)v.len, v.ptr) == -1)
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Map a string to an integer
 */
typedef struct {
	char *str;
	int d;
} enum_map_t;

/**
 * Parse a string to an integer mapping
 */
static bool parse_map(enum_map_t *map, int count, int *out, chunk_t v)
{
	char buf[128];
	int i;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	for (i = 0; i < count; i++)
	{
		if (strcaseeq(map[i].str, buf))
		{
			*out = map[i].d;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Parse a boolean
 */
CALLBACK(parse_bool, bool,
	bool *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "yes",		TRUE	},
		{ "true",		TRUE	},
		{ "enabled",	TRUE	},
		{ "1",			TRUE	},
		{ "no",			FALSE	},
		{ "false",		FALSE	},
		{ "disabled",	FALSE	},
		{ "0",			FALSE	},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a ipsec_mode_t
 */
CALLBACK(parse_mode, bool,
	ipsec_mode_t *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "tunnel",		MODE_TUNNEL		},
		{ "transport",	MODE_TRANSPORT	},
		{ "beet",		MODE_BEET		},
		{ "drop",		MODE_DROP		},
		{ "pass",		MODE_PASS		},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse an action_t
 */
CALLBACK(parse_action, bool,
	action_t *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "start",		ACTION_RESTART	},
		{ "restart",	ACTION_RESTART	},
		{ "route",		ACTION_ROUTE	},
		{ "none",		ACTION_NONE		},
		{ "clear",		ACTION_NONE		},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a u_int32_t
 */
CALLBACK(parse_uint32, bool,
	u_int32_t *out, chunk_t v)
{
	char buf[16], *end;
	u_long l;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	l = strtoul(buf, &end, 0);
	if (*end == 0)
	{
		*out = l;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a u_int64_t
 */
CALLBACK(parse_uint64, bool,
	u_int64_t *out, chunk_t v)
{
	char buf[16], *end;
	unsigned long long l;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	l = strtoull(buf, &end, 0);
	if (*end == 0)
	{
		*out = l;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a relative time
 */
CALLBACK(parse_time, bool,
	u_int64_t *out, chunk_t v)
{
	char buf[16], *end;
	u_long l;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}

	l = strtoul(buf, &end, 0);
	while (*end == ' ')
	{
		end++;
	}
	switch (*end)
	{
		case 'd':
		case 'D':
			l *= 24;
			/* fall */
		case 'h':
		case 'H':
			l *= 60;
			/* fall */
		case 'm':
		case 'M':
			l *= 60;
			/* fall */
		case 's':
		case 'S':
			end++;
			break;
		case '\0':
			break;
		default:
			return FALSE;
	}
	if (*end)
	{
		return FALSE;
	}
	*out = l;
	return TRUE;
}

/**
 * Parse byte volume
 */
CALLBACK(parse_bytes, bool,
	u_int64_t *out, chunk_t v)
{
	char buf[16], *end;
	unsigned long long l;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}

	l = strtoull(buf, &end, 0);
	while (*end == ' ')
	{
		end++;
	}
	switch (*end)
	{
		case 'g':
		case 'G':
			l *= 1024;
			/* fall */
		case 'm':
		case 'M':
			l *= 1024;
			/* fall */
		case 'k':
		case 'K':
			l *= 1024;
			end++;
			break;
		case '\0':
			break;
		default:
			return FALSE;
	}
	if (*end)
	{
		return FALSE;
	}
	*out = l;
	return TRUE;
}

/**
 * Parse a mark_t
 */
CALLBACK(parse_mark, bool,
	mark_t *out, chunk_t v)
{
	char buf[32];

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	return mark_from_string(buf, out);
}

/**
 * Parse authentication config
 */
CALLBACK(parse_auth, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	char buf[64], *pos;
	eap_vendor_type_t *type;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	if (strcaseeq(buf, "pubkey"))
	{
		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
		return TRUE;
	}
	if (strcaseeq(buf, "psk"))
	{
		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
		return TRUE;
	}
	if (strcasepfx(buf, "xauth"))
	{
		pos = strchr(buf, '-');
		if (pos)
		{
			cfg->add(cfg, AUTH_RULE_XAUTH_BACKEND, strdup(++pos));
		}
		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_XAUTH);
		return TRUE;
	}
	if (strcasepfx(buf, "eap"))
	{
		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);

		type = eap_vendor_type_from_string(buf);
		if (type)
		{
			cfg->add(cfg, AUTH_RULE_EAP_TYPE, type->type);
			if (type->vendor)
			{
				cfg->add(cfg, AUTH_RULE_EAP_VENDOR, type->vendor);
			}
			free(type);
		}
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse identity; add as auth rule to config
 */
static bool parse_id(auth_cfg_t *cfg, auth_rule_t rule, chunk_t v)
{
	char buf[256];

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	cfg->add(cfg, rule, identification_create_from_string(buf));
	return TRUE;
}

/**
 * Parse IKE identity
 */
CALLBACK(parse_ike_id, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	return parse_id(cfg, AUTH_RULE_IDENTITY, v);
}

/**
 * Parse AAA identity
 */
CALLBACK(parse_aaa_id, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	return parse_id(cfg, AUTH_RULE_AAA_IDENTITY, v);
}

/**
 * Parse EAP identity
 */
CALLBACK(parse_eap_id, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	return parse_id(cfg, AUTH_RULE_EAP_IDENTITY, v);
}

/**
 * Parse XAuth identity
 */
CALLBACK(parse_xauth_id, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	return parse_id(cfg, AUTH_RULE_XAUTH_IDENTITY, v);
}

/**
 * Parse revocation status
 */
CALLBACK(parse_revocation, bool,
	auth_cfg_t *cfg, chunk_t v)
{
	enum_map_t map[] = {
		{ "strict",		VALIDATION_GOOD		},
		{ "ifuri",		VALIDATION_SKIPPED	},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		cfg->add(cfg, AUTH_RULE_CRL_VALIDATION, d);
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse list items to comma separated strings
 */
CALLBACK(parse_stringlist, bool,
	char **out, chunk_t v)
{
	char *current;

	if (!chunk_printable(v, NULL, ' '))
	{
		return FALSE;
	}
	current = *out;
	if (current)
	{
		if (asprintf(out, "%s, %.*s", current, (int)v.len, v.ptr) == -1)
		{
			return FALSE;
		}
		free(current);
	}
	else
	{
		if (asprintf(out, "%.*s", (int)v.len, v.ptr) == -1)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Parse an fragmentation_t
 */
CALLBACK(parse_frag, bool,
	fragmentation_t *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "yes",		FRAGMENTATION_YES		},
		{ "no",			FRAGMENTATION_NO		},
		{ "force",		FRAGMENTATION_FORCE		},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a cert_policy_t
 */
CALLBACK(parse_send_cert, bool,
	cert_policy_t *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "ifasked",	CERT_SEND_IF_ASKED	},
		{ "always",		CERT_ALWAYS_SEND	},
		{ "never",		CERT_NEVER_SEND		},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a unique_policy_t
 */
CALLBACK(parse_unique, bool,
	unique_policy_t *out, chunk_t v)
{
	enum_map_t map[] = {
		{ "never",		UNIQUE_NEVER		},
		{ "no",			UNIQUE_NO			},
		{ "replace",	UNIQUE_REPLACE		},
		{ "keep",		UNIQUE_KEEP			},
	};
	int d;

	if (parse_map(map, countof(map), &d, v))
	{
		*out = d;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse host_t into a list
 */
CALLBACK(parse_hosts, bool,
	linked_list_t *list, chunk_t v)
{
	char buf[64];
	host_t *host;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	host = host_create_from_string(buf, 0);
	if (!host)
	{
		return FALSE;
	}
	list->insert_last(list, host);
	return TRUE;
}

CALLBACK(child_li, bool,
	child_data_t *child, vici_message_t *message, char *name, chunk_t value)
{
	parse_rule_t rules[] = {
		{ "ah_proposals",	parse_ah_proposal,	child->proposals			},
		{ "esp_proposals",	parse_esp_proposal,	child->proposals			},
		{ "local_ts",		parse_ts,			child->local_ts				},
		{ "remote_ts",		parse_ts,			child->remote_ts			},
	};

	return parse_rules(rules, countof(rules), name, value,
					   &child->request->reply);
}

CALLBACK(child_kv, bool,
	child_data_t *child, vici_message_t *message, char *name, chunk_t value)
{
	parse_rule_t rules[] = {
		{ "updown",			parse_string,		&child->updown				},
		{ "hostaccess",		parse_bool,			&child->hostaccess			},
		{ "mode",			parse_mode,			&child->mode				},
		{ "rekey_time",		parse_time,			&child->lft.time.rekey		},
		{ "life_time",		parse_time,			&child->lft.time.life		},
		{ "rand_time",		parse_time,			&child->lft.time.jitter		},
		{ "rekey_bytes",	parse_bytes,		&child->lft.bytes.rekey		},
		{ "life_bytes",		parse_bytes,		&child->lft.bytes.life		},
		{ "rand_bytes",		parse_bytes,		&child->lft.bytes.jitter	},
		{ "rekey_packets",	parse_uint64,		&child->lft.packets.rekey	},
		{ "life_packets",	parse_uint64,		&child->lft.packets.life	},
		{ "rand_packets",	parse_uint64,		&child->lft.packets.jitter	},
		{ "dpd_action",		parse_action,		&child->dpd_action			},
		{ "ipcomp",			parse_bool,			&child->ipcomp				},
		{ "inactivity",		parse_time,			&child->inactivity			},
		{ "reqid",			parse_uint32,		&child->reqid				},
		{ "mark_in",		parse_mark,			&child->mark_in				},
		{ "mark_out",		parse_mark,			&child->mark_out			},
		{ "tfc_padding",	parse_uint32,		&child->tfc					},
	};

	return parse_rules(rules, countof(rules), name, value,
					   &child->request->reply);
}

CALLBACK(auth_kv, bool,
	auth_data_t *auth, vici_message_t *message, char *name, chunk_t value)
{
	parse_rule_t rules[] = {
		{ "auth",			parse_auth,			auth->cfg					},
		{ "id",				parse_ike_id,		auth->cfg					},
		{ "aaa_id",			parse_aaa_id,		auth->cfg					},
		{ "eap_id",			parse_eap_id,		auth->cfg					},
		{ "xauth_id",		parse_xauth_id,		auth->cfg					},
		{ "revocation",		parse_revocation,	auth->cfg					},
	};

	return parse_rules(rules, countof(rules), name, value,
					   &auth->request->reply);
}

CALLBACK(peer_li, bool,
	peer_data_t *peer, vici_message_t *message, char *name, chunk_t value)
{
	parse_rule_t rules[] = {
		{ "local_addrs",	parse_stringlist,	&peer->local_addrs			},
		{ "remote_addrs",	parse_stringlist,	&peer->remote_addrs			},
		{ "proposals",		parse_ike_proposal,	peer->proposals				},
		{ "vips",			parse_hosts,		peer->vips					},
	};

	return parse_rules(rules, countof(rules), name, value,
					   &peer->request->reply);
}

CALLBACK(peer_kv, bool,
	peer_data_t *peer, vici_message_t *message, char *name, chunk_t value)
{
	parse_rule_t rules[] = {
		{ "version",		parse_uint32,		&peer->version				},
		{ "aggressive",		parse_bool,			&peer->aggressive			},
		{ "pull",			parse_bool,			&peer->pull					},
		{ "encap",			parse_bool,			&peer->encap				},
		{ "mobike",			parse_bool,			&peer->mobike				},
		{ "dpd_delay",		parse_time,			&peer->dpd_delay			},
		{ "dpd_timeout",	parse_time,			&peer->dpd_timeout			},
		{ "fragmentation",	parse_frag,			&peer->fragmentation		},
		{ "send_certreq",	parse_bool,			&peer->send_certreq			},
		{ "send_cert",		parse_send_cert,	&peer->send_cert			},
		{ "keyingtries",	parse_uint32,		&peer->keyingtries			},
		{ "unique",			parse_unique,		&peer->unique				},
		{ "local_port",		parse_uint32,		&peer->local_port			},
		{ "remote_port",	parse_uint32,		&peer->remote_port			},
		{ "reauth_time",	parse_time,			&peer->reauth_time			},
		{ "rekey_time",		parse_time,			&peer->rekey_time			},
		{ "over_time",		parse_time,			&peer->over_time			},
		{ "rand_time",		parse_time,			&peer->rand_time			},
	};

	return parse_rules(rules, countof(rules), name, value,
					   &peer->request->reply);
}

CALLBACK(children_sn, bool,
	peer_data_t *peer, vici_message_t *message, vici_parse_context_t *ctx,
	char *name)
{
	child_data_t child = {
		.request = peer->request,
		.proposals = linked_list_create(),
		.local_ts = linked_list_create(),
		.remote_ts = linked_list_create(),
		.mode = MODE_TUNNEL,
		.dpd_action = ACTION_NONE,
	};
	child_cfg_t *cfg;
	proposal_t *proposal;
	traffic_selector_t *ts;

	if (!message->parse(message, ctx, NULL, child_kv, child_li, &child))
	{
		free_child_data(&child);
		return FALSE;
	}

	if (child.local_ts->get_count(child.local_ts) == 0)
	{
		child.local_ts->insert_last(child.local_ts,
							traffic_selector_create_dynamic(0, 0, 65535));
	}
	if (child.remote_ts->get_count(child.remote_ts) == 0)
	{
		child.remote_ts->insert_last(child.remote_ts,
							traffic_selector_create_dynamic(0, 0, 65535));
	}
	if (child.proposals->get_count(child.proposals) == 0)
	{
		child.proposals->insert_last(child.proposals,
									 proposal_create_default(PROTO_ESP));
	}

	log_child_data(&child, name);

	cfg = child_cfg_create(name, &child.lft, child.updown,
						child.hostaccess, child.mode, ACTION_NONE,
						child.dpd_action, ACTION_NONE, child.ipcomp,
						child.inactivity, child.reqid, &child.mark_in,
						&child.mark_out, child.tfc);

	while (child.local_ts->remove_first(child.local_ts,
										(void**)&ts) == SUCCESS)
	{
		cfg->add_traffic_selector(cfg, TRUE, ts);
	}
	while (child.remote_ts->remove_first(child.remote_ts,
										 (void**)&ts) == SUCCESS)
	{
		cfg->add_traffic_selector(cfg, FALSE, ts);
	}
	while (child.proposals->remove_first(child.proposals,
										 (void**)&proposal) == SUCCESS)
	{
		cfg->add_proposal(cfg, proposal);
	}

	peer->children->insert_last(peer->children, cfg);

	free_child_data(&child);

	return TRUE;
}

CALLBACK(peer_sn, bool,
	peer_data_t *peer, vici_message_t *message, vici_parse_context_t *ctx,
	char *name)
{
	if (strcaseeq(name, "children"))
	{
		return message->parse(message, ctx, children_sn, NULL, NULL, peer);
	}
	if (strcasepfx(name, "local") ||
		strcasepfx(name, "remote"))
	{
		auth_data_t auth = {
			.request = peer->request,
			.cfg = auth_cfg_create(),
		};

		if (!message->parse(message, ctx, NULL, auth_kv, NULL, &auth))
		{
			auth.cfg->destroy(auth.cfg);
			return FALSE;
		}

		if (strcasepfx(name, "local"))
		{
			peer->local->insert_last(peer->local, auth.cfg);
		}
		else
		{
			peer->remote->insert_last(peer->remote, auth.cfg);
		}
		return TRUE;
	}
	peer->request->reply = create_reply("invalid section: %s", name);
	return FALSE;
}

/**
 * Replace children of a peer config by a new config
 */
static void replace_children(private_vici_config_t *this,
							 peer_cfg_t *from, peer_cfg_t *to)
{
	enumerator_t *enumerator;
	child_cfg_t *child;

	enumerator = to->create_child_cfg_enumerator(to);
	while (enumerator->enumerate(enumerator, &child))
	{
		to->remove_child_cfg(to, enumerator);
		child->destroy(child);
	}
	enumerator->destroy(enumerator);

	enumerator = from->create_child_cfg_enumerator(from);
	while (enumerator->enumerate(enumerator, &child))
	{
		from->remove_child_cfg(from, enumerator);
		to->add_child_cfg(to, child);
	}
	enumerator->destroy(enumerator);
}

/**
 * Merge/replace a peer config with existing configs
 */
static void merge_config(private_vici_config_t *this, peer_cfg_t *peer_cfg)
{
	enumerator_t *enumerator;
	peer_cfg_t *current;
	ike_cfg_t *ike_cfg;
	bool merged = FALSE;

	this->lock->write_lock(this->lock);

	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(peer_cfg->get_name(peer_cfg), current->get_name(current)))
		{
			ike_cfg = current->get_ike_cfg(current);
			if (peer_cfg->equals(peer_cfg, current) &&
				ike_cfg->equals(ike_cfg, peer_cfg->get_ike_cfg(peer_cfg)))
			{
				DBG1(DBG_CFG, "updated vici connection: %s",
					 peer_cfg->get_name(peer_cfg));
				replace_children(this, peer_cfg, current);
				peer_cfg->destroy(peer_cfg);
			}
			else
			{
				DBG1(DBG_CFG, "replaced vici connection: %s",
					 peer_cfg->get_name(peer_cfg));
				this->conns->remove_at(this->conns, enumerator);
				current->destroy(current);
				this->conns->insert_last(this->conns, peer_cfg);
			}
			merged = TRUE;
			break;
		}

	}
	enumerator->destroy(enumerator);

	if (!merged)
	{
		DBG1(DBG_CFG, "added vici connection: %s", peer_cfg->get_name(peer_cfg));
		this->conns->insert_last(this->conns, peer_cfg);
	}

	this->lock->unlock(this->lock);
}

CALLBACK(config_sn, bool,
	request_data_t *request, vici_message_t *message,
	vici_parse_context_t *ctx, char *name)
{
	peer_data_t peer = {
		.request = request,
		.local = linked_list_create(),
		.remote = linked_list_create(),
		.vips = linked_list_create(),
		.children = linked_list_create(),
		.proposals = linked_list_create(),
		.mobike = TRUE,
		.send_certreq = TRUE,
		.pull = TRUE,
		.send_cert = CERT_SEND_IF_ASKED,
		.version = IKE_ANY,
		.local_port = IKEV2_UDP_PORT,
		.remote_port = IKEV2_UDP_PORT,
		.fragmentation = FRAGMENTATION_NO,
		.unique = UNIQUE_NO,
		.keyingtries = 1,
	};
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	auth_cfg_t *auth_cfg;
	proposal_t *proposal;

	DBG2(DBG_CFG, " conn %s:", name);

	if (!message->parse(message, ctx, peer_sn, peer_kv, peer_li, &peer))
	{
		free_peer_data(&peer);
		return FALSE;
	}

	if (peer.local->get_count(peer.local) == 0)
	{
		free_peer_data(&peer);
		peer.request->reply = create_reply("missing local auth config");
		return FALSE;
	}
	if (peer.remote->get_count(peer.remote) == 0)
	{
		auth_cfg = auth_cfg_create();
		peer.remote->insert_last(peer.remote, auth_cfg);
	}
	if (peer.proposals->get_count(peer.proposals) == 0)
	{
		peer.proposals->insert_last(peer.proposals,
									proposal_create_default(PROTO_IKE));
	}
	if (!peer.local_addrs)
	{
		peer.local_addrs = strdup("%any");
	}
	if (!peer.remote_addrs)
	{
		peer.remote_addrs = strdup("%any");
	}

	log_peer_data(&peer);

	ike_cfg = ike_cfg_create(peer.version, peer.send_certreq, peer.encap,
						peer.local_addrs, peer.local_port,
						peer.remote_addrs, peer.remote_port,
						peer.fragmentation, 0);
	peer_cfg = peer_cfg_create(name, ike_cfg, peer.send_cert, peer.unique,
						peer.keyingtries, peer.rekey_time, peer.reauth_time,
						peer.rand_time, peer.over_time, peer.mobike,
						peer.aggressive, peer.pull,
						peer.dpd_delay, peer.dpd_timeout,
						FALSE, NULL, NULL);

	while (peer.local->remove_first(peer.local,
									(void**)&auth_cfg) == SUCCESS)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, TRUE);
	}
	while (peer.remote->remove_first(peer.remote,
									 (void**)&auth_cfg) == SUCCESS)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, FALSE);
	}
	while (peer.children->remove_first(peer.children,
									   (void**)&child_cfg) == SUCCESS)
	{
		peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	}
	while (peer.proposals->remove_first(peer.proposals,
										(void**)&proposal) == SUCCESS)
	{
		ike_cfg->add_proposal(ike_cfg, proposal);
	}

	free_peer_data(&peer);

	merge_config(request->this, peer_cfg);

	return TRUE;
}

CALLBACK(load_conn, vici_message_t*,
	private_vici_config_t *this, char *name, u_int id, vici_message_t *message)
{
	request_data_t request = {
		.this = this,
	};

	if (!message->parse(message, NULL, config_sn, NULL, NULL, &request))
	{
		if (request.reply)
		{
			return request.reply;
		}
		return create_reply("parsing request failed");
	}
	return create_reply(NULL);
}

CALLBACK(unload_conn, vici_message_t*,
	private_vici_config_t *this, char *name, u_int id, vici_message_t *message)
{
	enumerator_t *enumerator;
	peer_cfg_t *cfg;
	bool found = FALSE;
	char *conn;

	conn = message->get_str(message, NULL, "name");
	if (!conn)
	{
		return create_reply("missing connection name to unload");
	}

	this->lock->write_lock(this->lock);
	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, &cfg))
	{
		if (streq(cfg->get_name(cfg), conn))
		{
			this->conns->remove_at(this->conns, enumerator);
			cfg->destroy(cfg);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!found)
	{
		return create_reply("connection '%s' not found for unloading", conn);
	}
	return create_reply(NULL);
}

CALLBACK(get_conns, vici_message_t*,
	private_vici_config_t *this, char *name, u_int id, vici_message_t *message)
{
	vici_builder_t *builder;
	enumerator_t *enumerator;
	peer_cfg_t *cfg;

	builder = vici_builder_create();
	builder->begin_list(builder, "conns");

	this->lock->read_lock(this->lock);
	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, &cfg))
	{
		builder->add_li(builder, "%s", cfg->get_name(cfg));
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	builder->end_list(builder);

	return builder->finalize(builder);
}

static void manage_command(private_vici_config_t *this,
						   char *name, vici_command_cb_t cb, bool reg)
{
	this->dispatcher->manage_command(this->dispatcher, name,
									 reg ? cb : NULL, this);
}

/**
 * (Un-)register dispatcher functions
 */
static void manage_commands(private_vici_config_t *this, bool reg)
{
	manage_command(this, "load-conn", load_conn, reg);
	manage_command(this, "unload-conn", unload_conn, reg);
	manage_command(this, "get-conns", get_conns, reg);
}

METHOD(vici_config_t, destroy, void,
	private_vici_config_t *this)
{
	manage_commands(this, FALSE);
	this->conns->destroy_offset(this->conns, offsetof(peer_cfg_t, destroy));
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
vici_config_t *vici_config_create(vici_dispatcher_t *dispatcher)
{
	private_vici_config_t *this;

	INIT(this,
		.public = {
			.backend = {
				.create_peer_cfg_enumerator = _create_peer_cfg_enumerator,
				.create_ike_cfg_enumerator = _create_ike_cfg_enumerator,
				.get_peer_cfg_by_name = _get_peer_cfg_by_name,
			},
			.destroy = _destroy,
		},
		.dispatcher = dispatcher,
		.conns = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	manage_commands(this, TRUE);

	return &this->public;
}
