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

#include "ha_sync_segments.h"

#include <utils/linked_list.h>

typedef u_int32_t u32;
typedef u_int8_t u8;

#include <linux/jhash.h>

#define MAX_SEGMENTS 16

typedef struct private_ha_sync_segments_t private_ha_sync_segments_t;

/**
 * Private data of an ha_sync_segments_t object.
 */
struct private_ha_sync_segments_t {

	/**
	 * Public ha_sync_segments_t interface.
	 */
	ha_sync_segments_t public;

	/**
	 * Init value for jhash
	 */
	u_int initval;

	/**
	 * Total number of ClusterIP segments
	 */
	u_int segment_count;

	/**
	 * mask of active segments
	 */
	u_int16_t active;
};

/**
 * Check if a host address is in the CLUSTERIP segment
 */
static bool in_segment(private_ha_sync_segments_t *this,
					   host_t *host, u_int segment)
{
	if (host->get_family(host) == AF_INET)
	{
		unsigned long hash;
		u_int32_t addr;

		addr = *(u_int32_t*)host->get_address(host).ptr;
		hash = jhash_1word(ntohl(addr), this->initval);

		if ((((u_int64_t)hash * this->segment_count) >> 32) + 1 == segment)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Log currently active segments
 */
static void log_segments(private_ha_sync_segments_t *this, bool activated,
						 u_int segment)
{
	char buf[64], *pos = buf;
	int i;
	bool first = TRUE;

	for (i = 0; i < this->segment_count; i++)
	{
		if (this->active & 0x01 << i)
		{
			if (first)
			{
				first = FALSE;
			}
			else
			{
				pos += snprintf(pos, buf + sizeof(buf) - pos, ",");
			}
			pos += snprintf(pos, buf + sizeof(buf) - pos, "%d", i+1);
		}
	}
	DBG1(DBG_CFG, "HA sync segments %d %sactivated, now active: %s",
		 segment, activated ? "" : "de", buf);
}

/**
 * Implementation of ha_sync_segments_t.activate
 */
static void activate(private_ha_sync_segments_t *this, u_int segment)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	u_int16_t mask = 0x01 << (segment - 1);

	DBG1(DBG_CFG, "activating segment %d", segment);

	if (segment > 0 && segment <= this->segment_count && !(this->active & mask))
	{
		this->active |= mask;

		enumerator = charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) == IKE_PASSIVE &&
				in_segment(this, ike_sa->get_other_host(ike_sa), segment))
			{
				ike_sa->set_state(ike_sa, IKE_ESTABLISHED);
			}
		}
		enumerator->destroy(enumerator);

		log_segments(this, TRUE, segment);
	}
}

/**
 * Implementation of ha_sync_segments_t.deactivate
 */
static void deactivate(private_ha_sync_segments_t *this, u_int segment)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	u_int16_t mask = 0x01 << (segment - 1);

	if (segment > 0 && segment <= this->segment_count && (this->active & mask))
	{
		this->active &= ~mask;

		enumerator = charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
				in_segment(this, ike_sa->get_other_host(ike_sa), segment))
			{
				ike_sa->set_state(ike_sa, IKE_PASSIVE);
			}
		}
		enumerator->destroy(enumerator);

		log_segments(this, FALSE, segment);
	}
}

/**
 * Implementation of ha_sync_segments_t.destroy.
 */
static void destroy(private_ha_sync_segments_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_sync_segments_t *ha_sync_segments_create()
{
	private_ha_sync_segments_t *this = malloc_thing(private_ha_sync_segments_t);
	enumerator_t *enumerator;
	u_int segment;
	char *str;

	this->public.activate = (void(*)(ha_sync_segments_t*, u_int segment))activate;
	this->public.deactivate = (void(*)(ha_sync_segments_t*, u_int segment))deactivate;
	this->public.destroy = (void(*)(ha_sync_segments_t*))destroy;

	this->initval = 0;
	this->active = 0;
	this->segment_count = lib->settings->get_int(lib->settings,
								"charon.plugins.ha_sync.segment_count", 1);
	this->segment_count = min(this->segment_count, MAX_SEGMENTS);
	str = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.active_segments", "1");
	enumerator = enumerator_create_token(str, ",", " ");
	while (enumerator->enumerate(enumerator, &str))
	{
		segment = atoi(str);
		if (segment && segment < MAX_SEGMENTS)
		{
			this->active |= 0x01 << (segment - 1);
		}
	}
	enumerator->destroy(enumerator);

	return &this->public;
}

