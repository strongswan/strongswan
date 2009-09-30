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

#include "ha_kernel.h"

typedef u_int32_t u32;
typedef u_int8_t u8;

#include <linux/jhash.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CLUSTERIP_DIR "/proc/net/ipt_CLUSTERIP"

typedef struct private_ha_kernel_t private_ha_kernel_t;

/**
 * Private data of an ha_kernel_t object.
 */
struct private_ha_kernel_t {

	/**
	 * Public ha_kernel_t interface.
	 */
	ha_kernel_t public;

	/**
	 * Init value for jhash
	 */
	u_int initval;

	/**
	 * Total number of ClusterIP segments
	 */
	u_int count;
};

/**
 * Implementation of ha_kernel_t.in_segment
 */
static bool in_segment(private_ha_kernel_t *this, host_t *host, u_int segment)
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
 * Activate/Deactivate a segment for a given clusterip file
 */
static void enable_disable(private_ha_kernel_t *this, u_int segment,
						   char *file, bool enable)
{
	char cmd[8];
	int fd;

	snprintf(cmd, sizeof(cmd), "%c%d\n", enable ? '+' : '-', segment);

	fd = open(file, O_WRONLY);
	if (fd == -1)
	{
		DBG1(DBG_CFG, "opening CLUSTERIP file '%s' failed: %s",
			 file, strerror(errno));
		return;
	}
	if (write(fd, cmd, strlen(cmd) == -1))
	{
		DBG1(DBG_CFG, "writing to CLUSTERIP file '%s' failed: %s",
			 file, strerror(errno));
	}
	close(fd);
}

/**
 * Get the currenlty active segments in the kernel for a clusterip file
 */
static segment_mask_t get_active(private_ha_kernel_t *this, char *file)
{
	char buf[256];
	segment_mask_t mask = 0;
	ssize_t len;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_CFG, "opening CLUSTERIP file '%s' failed: %s",
			 file, strerror(errno));
		return 0;
	}
	len = read(fd, buf, sizeof(buf)-1);
	if (len == -1)
	{
		DBG1(DBG_CFG, "reading from CLUSTERIP file '%s' failed: %s",
			 file, strerror(errno));
	}
	else
	{
		enumerator_t *enumerator;
		u_int segment;
		char *token;

		buf[len] = '\0';
		enumerator = enumerator_create_token(buf, ",", " ");
		while (enumerator->enumerate(enumerator, &token))
		{
			segment = atoi(token);
			if (segment)
			{
				mask |= SEGMENTS_BIT(segment);
			}
		}
		enumerator->destroy(enumerator);
	}
	return mask;
}

/**
 * Implementation of ha_kernel_t.activate
 */
static void activate(private_ha_kernel_t *this, u_int segment)
{
	enumerator_t *enumerator;
	char *file;

	enumerator = enumerator_create_directory(CLUSTERIP_DIR);
	while (enumerator->enumerate(enumerator, NULL, &file, NULL))
	{
		enable_disable(this, segment, file, TRUE);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of ha_kernel_t.deactivate
 */
static void deactivate(private_ha_kernel_t *this, u_int segment)
{
	enumerator_t *enumerator;
	char *file;

	enumerator = enumerator_create_directory(CLUSTERIP_DIR);
	while (enumerator->enumerate(enumerator, NULL, &file, NULL))
	{
		enable_disable(this, segment, file, FALSE);
	}
	enumerator->destroy(enumerator);
}

/**
 * Disable all not-yet disabled segments on all clusterip addresses
 */
static void disable_all(private_ha_kernel_t *this)
{
	enumerator_t *enumerator;
	segment_mask_t active;
	char *file;
	int i;

	enumerator = enumerator_create_directory(CLUSTERIP_DIR);
	while (enumerator->enumerate(enumerator, NULL, &file, NULL))
	{
		active = get_active(this, file);
		for (i = 1; i <= this->count; i++)
		{
			if (active & SEGMENTS_BIT(i))
			{
				enable_disable(this, i, file, FALSE);
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of ha_kernel_t.destroy.
 */
static void destroy(private_ha_kernel_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_kernel_t *ha_kernel_create(u_int count)
{
	private_ha_kernel_t *this = malloc_thing(private_ha_kernel_t);

	this->public.in_segment = (bool(*)(ha_kernel_t*, host_t *host, u_int segment))in_segment;
	this->public.activate = (void(*)(ha_kernel_t*, u_int segment))activate;
	this->public.deactivate = (void(*)(ha_kernel_t*, u_int segment))deactivate;
	this->public.destroy = (void(*)(ha_kernel_t*))destroy;

	this->initval = 0;
	this->count = count;

	disable_all(this);

	return &this->public;
}

