/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tun_device.h"

#include <library.h>
#include <debug.h>
#include <threading/thread.h>

#define TUN_DEFAULT_MTU 1500

typedef struct private_tun_device_t private_tun_device_t;

struct private_tun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;

	/**
	 * The TUN device's file descriptor
	 */
	int tunfd;

	/**
	 * Name of the TUN device
	 */
	char if_name[IFNAMSIZ];

	/**
	 * Socket used for ioctl() to set interface addr, ...
	 */
	int sock;

	/**
	 * The current MTU
	 */
	int mtu;
};

/**
 * Set the sockaddr_t from the given netmask
 */
static void set_netmask(struct ifreq *ifr, int family, u_int8_t netmask)
{
	int len, bytes, bits;
	char *target;

	switch (family)
	{
		case AF_INET:
		{
			struct sockaddr_in *addr = (struct sockaddr_in*)&ifr->ifr_addr;
			addr->sin_family = AF_INET;
			target = (char*)&addr->sin_addr;
			len = 4;
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6*)&ifr->ifr_addr;
			addr->sin6_family = AF_INET6;
			target = (char*)&addr->sin6_addr;
			len = 16;
			break;
		}
		default:
			return;
	}

	bytes = (netmask + 7) / 8;
	bits = (bytes * 8) - netmask;

	memset(target, 0xff, bytes);
	memset(target + bytes, 0x00, len - bytes);
	target[bytes - 1] = bits ? (u_int8_t)(0xff << bits) : 0xff;
}

METHOD(tun_device_t, set_address, bool,
	private_tun_device_t *this, host_t *addr, u_int8_t netmask)
{
	struct ifreq ifr;
	int family;

	family = addr->get_family(addr);
	if ((netmask > 32 && family == AF_INET) || netmask > 128)
	{
		DBG1(DBG_LIB, "failed to set address on %s: invalid netmask",
			 this->if_name);
		return FALSE;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	memcpy(&ifr.ifr_addr, addr->get_sockaddr(addr), sizeof(sockaddr_t));

	if (ioctl(this->sock, SIOCSIFADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}

	set_netmask(&ifr, family, netmask);

	if (ioctl(this->sock, SIOCSIFNETMASK, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set netmask on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, up, bool,
	private_tun_device_t *this)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);

	if (ioctl(this->sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to get interface flags for %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}

	ifr.ifr_flags |= IFF_RUNNING | IFF_UP;

	if (ioctl(this->sock, SIOCSIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set interface flags on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	if (ioctl(this->sock, SIOCSIFMTU, &ifr) < 0)
	{
		return FALSE;
	}
	this->mtu = mtu;
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
	struct ifreq ifr;

	if (this->mtu > 0)
	{
		return this->mtu;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	this->mtu = TUN_DEFAULT_MTU;

	if (ioctl(this->sock, SIOCGIFMTU, &ifr) == 0)
	{
		this->mtu = ifr.ifr_mtu;
	}
	return this->mtu;
}

METHOD(tun_device_t, get_name, char*,
	private_tun_device_t *this)
{
	return this->if_name;
}

METHOD(tun_device_t, write_packet, bool,
	private_tun_device_t *this, chunk_t packet)
{
	ssize_t s;

	s = write(this->tunfd, packet.ptr, packet.len);
	if (s < 0)
	{
		DBG1(DBG_LIB, "failed to write packet to TUN device %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	else if (s != packet.len)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_tun_device_t *this, chunk_t *packet)
{
	ssize_t len;
	fd_set set;
	bool old;

	FD_ZERO(&set);
	FD_SET(this->tunfd, &set);

	old = thread_cancelability(TRUE);
	len = select(this->tunfd + 1, &set, NULL, NULL, NULL);
	thread_cancelability(old);

	if (len < 0)
	{
		DBG1(DBG_LIB, "select on TUN device %s failed: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	/* FIXME: this is quite expensive for lots of small packets, copy from
	 * local buffer instead? */
	*packet = chunk_alloc(get_mtu(this));
	len = read(this->tunfd, packet->ptr, packet->len);
	if (len < 0)
	{
		DBG1(DBG_LIB, "reading from TUN device %s failed: %s", this->if_name,
			 strerror(errno));
		chunk_free(packet);
		return FALSE;
	}
	packet->len = len;
	return TRUE;
}

METHOD(tun_device_t, destroy, void,
	private_tun_device_t *this)
{
	if (this->tunfd > 0)
	{
		close(this->tunfd);
	}
	if (this->sock > 0)
	{
		close(this->sock);
	}
	free(this);
}

/**
 * Allocate a TUN device
 */
static int tun_alloc(char dev[IFNAMSIZ])
{
	struct ifreq ifr;
	int fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/net/tun: %s", strerror(errno));
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	/* TUN device, no packet info */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to configure TUN device: %s", strerror(errno));
		close(fd);
		return -1;
	}
	strncpy(dev, ifr.ifr_name, IFNAMSIZ);
	return fd;
}

/*
 * Described in header
 */
tun_device_t *tun_device_create(const char *name_tmpl)
{
	private_tun_device_t *this;

	INIT(this,
		.public = {
			.read_packet = _read_packet,
			.write_packet = _write_packet,
			.get_mtu = _get_mtu,
			.set_mtu = _set_mtu,
			.get_name = _get_name,
			.set_address = _set_address,
			.up = _up,
			.destroy = _destroy,
		},
		.tunfd = -1,
		.sock = -1,
	);

	strncpy(this->if_name, name_tmpl ?: "tun%d", IFNAMSIZ);
	this->if_name[IFNAMSIZ-1] = '\0';

	this->tunfd = tun_alloc(this->if_name);
	if (this->tunfd < 0)
	{
		destroy(this);
		return NULL;
	}
	DBG1(DBG_LIB, "created TUN device: %s", this->if_name);

	this->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (this->sock < 0)
	{
		DBG1(DBG_LIB, "failed to open socket to configure TUN device");
		destroy(this);
		return NULL;
	}
	return &this->public;
}
