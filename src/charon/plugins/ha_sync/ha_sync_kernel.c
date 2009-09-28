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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
	u_int count;

	/**
	 * List of virtual addresses, as host_t*
	 */
	linked_list_t *virtuals;
};

/**
 * Implementation of ha_sync_kernel_t.in_segment
 */
static bool in_segment(private_ha_sync_kernel_t *this,
					   host_t *host, u_int segment)
{
	if (host->get_family(host) == AF_INET)
	{
		unsigned long hash;
		u_int32_t addr;

		addr = *(u_int32_t*)host->get_address(host).ptr;
		hash = jhash_1word(ntohl(addr), this->initval);

		if ((((u_int64_t)hash * this->count) >> 32) + 1 == segment)
		{
			return TRUE;
		}
	}
	return FALSE;
}
/**
 * Activate/Deactivate a segment
 */
static void activate_deactivate(private_ha_sync_kernel_t *this,
								u_int segment, char op)
{
	enumerator_t *enumerator;
	host_t *host;
	char cmd[8], file[256];
	int fd;

	enumerator = this->virtuals->create_enumerator(this->virtuals);
	while (enumerator->enumerate(enumerator, &host))
	{
		snprintf(file, sizeof(file), "/proc/net/ipt_CLUSTERIP/%H", host);
		snprintf(cmd, sizeof(cmd), "%c%d\n", op, segment);

		fd = open(file, O_WRONLY);
		if (fd == -1)
		{
			DBG1(DBG_CFG, "opening CLUSTERIP file '%s' failed: %s",
				 file, strerror(errno));
			continue;
		}
		if (write(fd, cmd, strlen(cmd) == -1))
		{
			DBG1(DBG_CFG, "writing to CLUSTERIP file '%s' failed: %s",
				 file, strerror(errno));
		}
		close(fd);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of ha_sync_kernel_t.activate
 */
static void activate(private_ha_sync_kernel_t *this, u_int segment)
{
	activate_deactivate(this, segment, '+');
}

/**
 * Implementation of ha_sync_kernel_t.deactivate
 */
static void deactivate(private_ha_sync_kernel_t *this, u_int segment)
{
	activate_deactivate(this, segment, '-');
}

/**
 * Mangle IPtable rules for virtual addresses
 */
static bool mangle_rules(private_ha_sync_kernel_t *this, bool add)
{
	enumerator_t *enumerator;
	host_t *host;
	u_char i, mac = 0x20;
	char *iface, buf[256];

	enumerator = this->virtuals->create_enumerator(this->virtuals);
	while (enumerator->enumerate(enumerator, &host))
	{
		iface = charon->kernel_interface->get_interface(
											charon->kernel_interface, host);
		if (!iface)
		{
			DBG1(DBG_CFG, "cluster address %H not installed, ignored", host);
			this->virtuals->remove_at(this->virtuals, enumerator);
			host->destroy(host);
			continue;
		}
		/* iptables insists of a local node specification, enable node 1 */
		snprintf(buf, sizeof(buf),
				 "/sbin/iptables -%c INPUT -i %s -d %H -j CLUSTERIP --new "
				 "--hashmode sourceip --clustermac 01:00:5e:00:00:%2x "
				 "--total-nodes %d --local-node 1",
				 add ? 'A' : 'D', iface, host, mac++, this->count);
		free(iface);
		if (system(buf) != 0)
		{
			DBG1(DBG_CFG, "installing CLUSTERIP rule '%s' failed", buf);
		}
	}
	enumerator->destroy(enumerator);

	if (add)
	{
		for (i = 2; i <= this->count; i++)
		{
			activate(this, i);
		}
	}
	return TRUE;
}

/**
 * Parse the list of virtual cluster addresses
 */
static void parse_virtuals(private_ha_sync_kernel_t *this, char *virtual)
{
	enumerator_t *enumerator;
	host_t *host;

	enumerator = enumerator_create_token(virtual, ",", " ");
	while (enumerator->enumerate(enumerator, &virtual))
	{
		host = host_create_from_string(virtual, 0);
		if (host)
		{
			this->virtuals->insert_last(this->virtuals, host);
		}
		else
		{
			DBG1(DBG_CFG, "virtual cluster address '%s' invalid, ignored",
				 virtual);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of ha_sync_kernel_t.destroy.
 */
static void destroy(private_ha_sync_kernel_t *this)
{
	mangle_rules(this, FALSE);
	this->virtuals->destroy_offset(this->virtuals, offsetof(host_t, destroy));
	free(this);
}

/**
 * See header
 */
ha_sync_kernel_t *ha_sync_kernel_create(u_int count, char *virtuals)
{
	private_ha_sync_kernel_t *this = malloc_thing(private_ha_sync_kernel_t);

	this->public.in_segment = (bool(*)(ha_sync_kernel_t*, host_t *host, u_int segment))in_segment;
	this->public.activate = (void(*)(ha_sync_kernel_t*, u_int segment))activate;
	this->public.deactivate = (void(*)(ha_sync_kernel_t*, u_int segment))deactivate;
	this->public.destroy = (void(*)(ha_sync_kernel_t*))destroy;

	this->initval = 0;
	this->count = count;
	this->virtuals = linked_list_create();

	parse_virtuals(this, virtuals);

	if (!mangle_rules(this, TRUE))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

