/*
 * Copyright (C) 2009 Martin Willi
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

#include "ha_sync_kernel.h"

typedef u_int32_t u32;
typedef u_int8_t u8;

#include <linux/jhash.h>

typedef struct private_ha_sync_kernel_t private_ha_sync_kernel_t;

/**
 * Private data of an ha_sync_kernel_t object.
 */
struct private_ha_sync_kernel_t {

	/**
	 * Public ha_sync_kernel_t interface.
	 */
	ha_sync_kernel_t public;

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
	segment_mask_t active;
};

/**
 * Implementation of ha_sync_kernel_t.in_segment
 */
static bool in_segment(private_ha_sync_kernel_t *this, host_t *host, u_int segment)
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
 * Implementation of ha_sync_kernel_t.destroy.
 */
static void destroy(private_ha_sync_kernel_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_sync_kernel_t *ha_sync_kernel_create(u_int count, segment_mask_t active,
										char *external, char *internal)
{
	private_ha_sync_kernel_t *this = malloc_thing(private_ha_sync_kernel_t);

	this->public.in_segment = (bool(*)(ha_sync_kernel_t*, host_t *host, u_int segment))in_segment;
	this->public.destroy = (void(*)(ha_sync_kernel_t*))destroy;

	this->initval = 0;
	this->segment_count = count;

	return &this->public;
}

