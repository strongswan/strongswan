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

#include "ha_sync_child.h"

typedef struct private_ha_sync_child_t private_ha_sync_child_t;
typedef struct serialized_child_sa_t serialized_child_sa_t;
typedef struct serialized_ts_t serialized_ts_t;

/**
 * Private data of an ha_sync_child_t object.
 */
struct private_ha_sync_child_t {

	/**
	 * Public ha_sync_child_t interface.
	 */
	ha_sync_child_t public;
};

/* version number of serialization fromat */
#define SERIALIZE_VERSION 1

/**
 * A serialized traffic selector
 */
struct serialized_ts_t {
	u_int8_t type;
	u_int8_t protocol;
	u_int8_t dynamic;
	struct {
		u_int8_t addr[16];
		u_int16_t port;
	} from, to;
};

/**
 * A serialized CHILD_SA
 */
struct serialized_child_sa_t {

	u_int8_t version;

	/* per CHILD values */
	u_int8_t protocol;
	u_int8_t mode;
	u_int8_t encap;
	u_int8_t ipcomp;
	u_int32_t soft_lifetime;
	u_int32_t hard_lifetime;

	/* configuration name */
	char config[32];

	/* algs and keys */
	struct {
		u_int16_t alg;
		u_int16_t keylen;
		u_int8_t in[64], out[64];
	} integrity, encryption;

	struct {
		u_int32_t spi;
		u_int16_t cpi;

		u_int8_t addr_fam;
		u_int8_t addr[16];
		u_int16_t port;

		/* traffic selector, currently only one, TODO */
		serialized_ts_t ts;
	} in, out;
};

/**
 * Serialize a traffic selector list
 */
static void serialize_ts_list(linked_list_t *ts_list, serialized_ts_t *ser)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	chunk_t chunk;
	int i = 0;

	enumerator = ts_list->create_enumerator(ts_list);
	if (enumerator->enumerate(enumerator, &ts))
	{
		ser->type = ts->get_type(ts);
		ser->protocol = ts->get_protocol(ts);
		ser->dynamic = ts->is_dynamic(ts);
		ser->from.port = htons(ts->get_from_port(ts));
		ser->to.port = htons(ts->get_to_port(ts));
		chunk = ts->get_from_address(ts);
		memcpy(ser->from.addr, chunk.ptr, min(chunk.len, sizeof(ser->from.addr)));
		chunk = ts->get_to_address(ts);
		memcpy(ser->to.addr, chunk.ptr, min(chunk.len, sizeof(ser->to.addr)));
	}
	enumerator->destroy(enumerator);
}

/**
 * Serialize a CHILD_SA
 */
static chunk_t serialize(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	serialized_child_sa_t *ser;
	child_cfg_t *config;
	host_t *me, *other;
	chunk_t chunk;

	config = child_sa->get_config(child_sa);
	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	ser = malloc_thing(serialized_child_sa_t);
	memset(ser, 0, sizeof(serialized_child_sa_t));

	ser->version = SERIALIZE_VERSION;
	ser->protocol = child_sa->get_protocol(child_sa);
	ser->mode = child_sa->get_mode(child_sa);
	ser->encap = child_sa->has_encap(child_sa);
	ser->ipcomp = child_sa->get_ipcomp(child_sa);
	ser->soft_lifetime = child_sa->get_lifetime(child_sa, FALSE);
	ser->hard_lifetime = child_sa->get_lifetime(child_sa, TRUE);
	ser->in.spi = child_sa->get_spi(child_sa, TRUE);
	ser->in.cpi = child_sa->get_cpi(child_sa, TRUE);
	ser->out.spi = child_sa->get_spi(child_sa, FALSE);
	ser->out.cpi = child_sa->get_cpi(child_sa, FALSE);
	snprintf(ser->config, sizeof(ser->config), config->get_name(config));

	ser->integrity.alg = child_sa->get_integrity(child_sa, TRUE, &chunk);
	ser->integrity.keylen = chunk.len;
	memcpy(ser->integrity.in, chunk.ptr, ser->integrity.keylen);
	child_sa->get_integrity(child_sa, FALSE, &chunk);
	memcpy(ser->integrity.out, chunk.ptr, ser->integrity.keylen);

	ser->encryption.alg = child_sa->get_encryption(child_sa, TRUE, &chunk);
	ser->encryption.keylen = chunk.len;
	memcpy(ser->encryption.in, chunk.ptr, ser->encryption.keylen);
	child_sa->get_integrity(child_sa, FALSE, &chunk);
	memcpy(ser->encryption.out, chunk.ptr, ser->encryption.keylen);

	ser->in.addr_fam = me->get_family(me);
	ser->in.port = htons(me->get_port(me));
	chunk = me->get_address(me);
	memcpy(ser->in.addr, chunk.ptr, chunk.len);

	ser->out.addr_fam = other->get_family(other);
	ser->out.port = htons(other->get_port(other));
	chunk = other->get_address(other);
	memcpy(ser->out.addr, chunk.ptr, chunk.len);

	serialize_ts_list(child_sa->get_traffic_selectors(child_sa, TRUE),
					  &ser->in.ts);
	serialize_ts_list(child_sa->get_traffic_selectors(child_sa, FALSE),
					  &ser->out.ts);

	return chunk_create((void*)ser, sizeof(serialized_child_sa_t));
}

/**
 * Listener implementation
 */
static bool child_state_change(private_ha_sync_child_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	if (state == CHILD_INSTALLED)
	{
		chunk_t chunk;

		chunk = serialize(ike_sa, child_sa);
		DBG1(DBG_IKE, "NEW CHILD: %B", &chunk);

		chunk_clear(&chunk);
	}
	return TRUE;
}

/**
 * Implementation of ha_sync_child_t.destroy.
 */
static void destroy(private_ha_sync_child_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_sync_child_t *ha_sync_child_create()
{
	private_ha_sync_child_t *this = malloc_thing(private_ha_sync_child_t);

	memset(&this->public.listener, 0, sizeof(listener_t));

	this->public.listener.child_state_change = (void*)child_state_change;
	this->public.destroy = (void(*)(ha_sync_child_t*))destroy;

	return &this->public;
}

