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
 * Segmentate a calculated hash
 */
static u_int hash2segment(private_ha_kernel_t *this, u_int64_t hash)
{
	return ((hash * this->count) >> 32) + 1;
}

/**
 * Get a host as an integer for hashing
 */
static u_int32_t host2int(host_t *host)
{
	if (host->get_family(host) == AF_INET)
	{
		return *(u_int32_t*)host->get_address(host).ptr;
	}
	return 0;
}

METHOD(ha_kernel_t, get_segment, u_int,
	private_ha_kernel_t *this, host_t *host)
{
	unsigned long hash;
	u_int32_t addr;

	addr = host2int(host);
	hash = jhash_1word(ntohl(addr), this->initval);

	return hash2segment(this, hash);
}

METHOD(ha_kernel_t, get_segment_spi, u_int,
	private_ha_kernel_t *this, host_t *host, u_int32_t spi)
{
	unsigned long hash;
	u_int32_t addr;

	addr = host2int(host);
	hash = jhash_2words(ntohl(addr), ntohl(spi), this->initval);

	return hash2segment(this, hash);
}

METHOD(ha_kernel_t, get_segment_int, u_int,
	private_ha_kernel_t *this, int n)
{
	unsigned long hash;

	hash = jhash_1word(ntohl(n), this->initval);

	return hash2segment(this, hash);
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

METHOD(ha_kernel_t, activate, void,
	private_ha_kernel_t *this, u_int segment)
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

METHOD(ha_kernel_t, deactivate, void,
	private_ha_kernel_t *this, u_int segment)
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
		if (chown(file, charon->uid, charon->gid) != 0)
		{
			DBG1(DBG_CFG, "changing ClusterIP permissions failed: %s",
				 strerror(errno));
		}
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

METHOD(ha_kernel_t, destroy, void,
	private_ha_kernel_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_kernel_t *ha_kernel_create(u_int count)
{
	private_ha_kernel_t *this;

	INIT(this,
		.public = {
			.get_segment = _get_segment,
			.get_segment_spi = _get_segment_spi,
			.get_segment_int = _get_segment_int,
			.activate = _activate,
			.deactivate = _deactivate,
			.destroy = _destroy,
		},
		.initval = 0,
		.count = count,
	);

	disable_all(this);

	return &this->public;
}

