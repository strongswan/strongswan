/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2012 Martin Willi
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

/*
 * Copyright (C) 2016 Noel Kuntze
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "tun_device.h"

#include <utils/debug.h>
#include <threading/thread.h>

#if !defined(__APPLE__) && !defined(__linux__) && !defined(HAVE_NET_IF_TUN_H) && !defined(W32)

tun_device_t *tun_device_create(const char *name_tmpl)
{
	DBG1(DBG_LIB, "TUN devices are not supported");
	return NULL;
}

#else /* TUN devices supported */

#include <errno.h>
#include <fcntl.h>
#if !defined(WIN32)
#include <netinet/in.h>
#endif
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <netinet/in_var.h>
#include <sys/kern_control.h>
#elif defined(__linux__)
#include <linux/types.h>
#include <linux/if_tun.h>
#elif __FreeBSD__ >= 10
#include <net/if_tun.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#elif defined(WIN32)
#include <tap-windows.h>
#include <winioctl.h>
#include "win32.h"
#else
#include <net/if_tun.h>
#endif

#define TUN_DEFAULT_MTU 1500

typedef struct private_tun_device_t private_tun_device_t;

struct private_tun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;
#ifdef WIN32
        /**
         * The TUN device's file handle
         */
        HANDLE *tunhandle;
        /**
         * Name of the TUN device
         */
        char if_name[256];
#else
	/**
	 * The TUN device's file descriptor
	 */
	int tunfd;
	/**
	 * Name of the TUN device
	 */
	char if_name[IFNAMSIZ];
#endif /* WIN32 */
	/**
	 * Socket used for ioctl() to set interface addr, ...
	 */
	int sock;

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;
};

/**
 * FreeBSD 10 deprecated the SIOCSIFADDR etc. commands.
 */
#if __FreeBSD__ >= 10

static bool set_address_and_mask(struct in_aliasreq *ifra, host_t *addr,
								 uint8_t netmask)
{
	host_t *mask;

	memcpy(&ifra->ifra_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));
	/* set the same address as destination address */
	memcpy(&ifra->ifra_dstaddr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifra->ifra_mask, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);
	return TRUE;
}

/**
 * Set the address using the more flexible SIOCAIFADDR/SIOCDIFADDR commands
 * on FreeBSD 10 an newer.
 */
static bool set_address_impl(private_tun_device_t *this, host_t *addr,
							 uint8_t netmask)
{
	struct in_aliasreq ifra;

	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, this->if_name, IFNAMSIZ);

	if (this->address)
	{	/* remove the existing address first */
		if (!set_address_and_mask(&ifra, this->address, this->netmask))
		{
			return FALSE;
		}
		if (ioctl(this->sock, SIOCDIFADDR, &ifra) < 0)
		{
			DBG1(DBG_LIB, "failed to remove existing address on %s: %s",
				 this->if_name, strerror(errno));
			return FALSE;
		}
	}
	if (!set_address_and_mask(&ifra, addr, netmask))
	{
		return FALSE;
	}
	if (ioctl(this->sock, SIOCAIFADDR, &ifra) < 0)
	{
		DBG1(DBG_LIB, "failed to add address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

#elif defined(WIN32)
        /* method definitions for Windows */
/**
 * Set the address using registry and fileIO shennanigans on Windows.
 */
static bool set_address_impl(private_tun_device_t *this, host_t *addr,
							 uint8_t netmask)
{
    return TRUE;
}

#else /* __FreeBSD__ */
/**
 * Set the address using the classic SIOCSIFADDR etc. commands on other systems.
 */
static bool set_address_impl(private_tun_device_t *this, host_t *addr,
							 uint8_t netmask)
{
	struct ifreq ifr;
	host_t *mask;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	memcpy(&ifr.ifr_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	if (ioctl(this->sock, SIOCSIFADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
#ifdef __APPLE__
	if (ioctl(this->sock, SIOCSIFDSTADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set dest address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
#endif /* __APPLE__ */

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifr.ifr_addr, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);

	if (ioctl(this->sock, SIOCSIFNETMASK, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set netmask on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

#endif /* __FreeBSD__ */

METHOD(tun_device_t, set_address, bool,
	private_tun_device_t *this, host_t *addr, uint8_t netmask)
{
	if (!set_address_impl(this, addr, netmask))
	{
		return FALSE;
	}
	DESTROY_IF(this->address);
	this->address = addr->clone(addr);
	this->netmask = netmask;
	return TRUE;
}

METHOD(tun_device_t, get_address, host_t*,
	private_tun_device_t *this, uint8_t *netmask)
{
	if (netmask && this->address)
	{
		*netmask = this->netmask;
	}
	return this->address;
}
/* Fix for WIN32 */
METHOD(tun_device_t, up, bool,
	private_tun_device_t *this)
{
#ifdef WIN32
        ULONG status = TRUE;
        DWORD len;
        if (!DeviceIoControl (this->tunhandle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
			  &status, sizeof (status),
			  &status, sizeof (status), &len, NULL))
        {
            DBG1(DBG_LIB, "failed to set the interface %s to up", this->if_name);
            return FALSE;
        }
#else
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
#endif /* WIN32 */
	return TRUE;
}

/* Fix for WIN32 */
METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
#ifdef WIN32
        return NOT_SUPPORTED;
#else
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	if (ioctl(this->sock, SIOCSIFMTU, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set MTU on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
#endif
	this->mtu = mtu;
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
#ifdef WIN32
        ULONG mtu;
        DWORD len;
        if (DeviceIoControl (this->tunhandle, TAP_WIN_IOCTL_GET_MTU,
			 &mtu, sizeof (mtu),
			 &mtu, sizeof (mtu), &len, NULL))
        {
            this->mtu = (int) mtu;
        }
#else
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
#endif /* WIN32 */
	return this->mtu;
}

METHOD(tun_device_t, get_name, char*,
	private_tun_device_t *this)
{
	return this->if_name;
}
#ifdef WIN32
METHOD(tun_device_t, get_handle, HANDLE,
        private_tun_device_t *this)
{
        return this->tunhandle;
}
#else
METHOD(tun_device_t, get_fd, int,
	private_tun_device_t *this)
{
	return this->tunfd;
}
#endif /* WIN32 */
METHOD(tun_device_t, write_packet, bool,
	private_tun_device_t *this, chunk_t packet)
{
#ifdef __APPLE__
	/* UTUN's expect the packets to be prepended by a 32-bit protocol number
	 * instead of parsing the packet again, we assume IPv4 for now */
	uint32_t proto = htonl(AF_INET);
	packet = chunk_cata("cc", chunk_from_thing(proto), packet);
#elif defined(WIN32)
        bool status;
        DWORD size;
        status = WriteFile(*(this->tunhandle), (LPCVOID) &packet.ptr,
            packet.len, (LPDWORD) &size, NULL);
        if (!status)
        {
		DBG1(DBG_LIB, "failed to write packet to TUN device %s: %u",
			 this->if_name, (uint32_t) GetLastError());
                /*
                 * TODO: Translate integer to human readable string
                 */
		return FALSE;
        }
        if (size != packet.len)
        {
                return FALSE;
        }
#else
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
#endif /* __APPLE__ or WIN32 */
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_tun_device_t *this, chunk_t *packet)
{
	chunk_t data;
	ssize_t len;
	bool old;

	data = chunk_alloca(get_mtu(this));

	old = thread_cancelability(TRUE);
#ifdef WIN32
        bool status;
        DWORD size;
        /* Read chunk from handle */
        status = ReadFile(*(this->tunhandle), (LPVOID) &data.ptr,
            (DWORD) data.len, &size, NULL);
	thread_cancelability(old);
        if (!status)
        {
                /* TODO: Convert DWORD (GetLastError()) to human readable error string */
                DBG1(DBG_LIB, "reading from TUN device %s failed: %u", this->if_name,
                   (uint32_t) GetLastError());
                return FALSE;

        }
#else
	len = read(this->tunfd, data.ptr, data.len);
	thread_cancelability(old);
	if (len < 0)
	{
		DBG1(DBG_LIB, "reading from TUN device %s failed: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	data.len = len;
#endif /* WIN32 */
#ifdef __APPLE__
	/* UTUN's prepend packets with a 32-bit protocol number */
	data = chunk_skip(data, sizeof(uint32_t));
#endif
	*packet = chunk_clone(data);
	return TRUE;
}

METHOD(tun_device_t, destroy, void,
	private_tun_device_t *this)
{
#ifdef WIN32
        /* close file handle, destroy interface */
        CloseHandle(this->tunhandle);
#else
	if (this->tunfd > 0)
	{
		close(this->tunfd);
#ifdef __FreeBSD__
		/* tun(4) says the following: "These network interfaces persist until
		 * the if_tun.ko module is unloaded, or until removed with the
		 * ifconfig(8) command."  So simply closing the FD is not enough. */
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
		if (ioctl(this->sock, SIOCIFDESTROY, &ifr) < 0)
		{
			DBG1(DBG_LIB, "failed to destroy %s: %s", this->if_name,
				 strerror(errno));
		}
#endif
	}
#endif
	if (this->sock > 0)
	{
		close(this->sock);
	}
	DESTROY_IF(this->address);
	free(this);
}

/**
 * Initialize the tun device
 */
static bool init_tun(private_tun_device_t *this, const char *name_tmpl)
{
#ifdef __APPLE__

	struct ctl_info info;
	struct sockaddr_ctl addr;
	socklen_t size = IFNAMSIZ;

	memset(&info, 0, sizeof(info));
	memset(&addr, 0, sizeof(addr));

	this->tunfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open tundevice PF_SYSTEM socket: %s",
			 strerror(errno));
		return FALSE;
	}

	/* get a control identifier for the utun kernel extension */
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
	if (ioctl(this->tunfd, CTLIOCGINFO, &info) < 0)
	{
		DBG1(DBG_LIB, "failed to ioctl tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}

	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	/* allocate identifier dynamically */
	addr.sc_unit = 0;

	if (connect(this->tunfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_LIB, "failed to connect tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	if (getsockopt(this->tunfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
				   this->if_name, &size) < 0)
	{
		DBG1(DBG_LIB, "getting tundevice name failed: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	return TRUE;
#elif defined(WIN32)
        /* WIN32 TAP driver stuff*/
        /* Check if there is an unused tun device following the IPsec name scheme*/
        enumerator_t *enumerator;
        char *name;
        linked_list_t *possible_devices = get_tap_reg();
        /* Iterate over list */
        enumerator = possible_devices->create_enumerator(possible_devices);
        /* Try to open that device */
        while(enumerator->enumerate(enumerator, &name))
        {
            /* Set mode */
            char device_path[256];
            /* Translate dev name to guid */
            /* TODO: Fix. device_guid should be */
            snprintf (device_path, sizeof(device_path), "%s%s%s", USERMODEDEVICEDIR, name, TAP_WIN_SUFFIX);

            this->tunhandle = CreateFile(device_path, GENERIC_READ | GENERIC_WRITE, 0,
            0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
            if (this->tunhandle == INVALID_HANDLE_VALUE)
            {
            DBG1(DBG_LIB, "could not create TUN device %s", device_path);
            }
            /* device has been examined or used, free it */
            free(name);
        }

        /* possible_devices has been freed while going over the enumerator.
         * Therefore it is not necessary to free the elements in the list now.
         */
        enumerator->destroy(enumerator);
        possible_devices->destroy(possible_devices);
        /* set correct mode */
        /* We set a fake gateway of 169.254.254.128 that we route packets over
         The TAP driver strips the Ethernet header and trailer of the Ethernet frames
         before sending them back to the application that listens on the handle */
	in_addr ep[3];
	BOOL status;
        DWORD len;
        /* Local address (just fake one): 169.254.128.127 */
	ep[0] = htonl (0xA9FE8079);
        /*
         * Remote network. THe tap driver validates it by masking it with the remote_netmask
         * and then comparing hte result against the remote network (this value here).
         * If it does not match, an error is logged and initialization fails.
         * (local & remote_netmask ? local)
         * The driver does proxy arp for this network and the local address.
         */
        /* We need to integrate support for IPv6, too. */
        /* Just fake a link local address for now (169.254.128.128) */
	ep[1] = htonl (0xA9FE8080);
        /* Remote netmask (255.255.0.0) */
	ep[2] = htonl (0xFFFF0000);

        status = DeviceIoControl (this->tunhandle, TAP_WIN_IOCTL_CONFIG_TUN,
		    ep, sizeof (ep),
		    ep, sizeof (ep), &len, NULL);
        /* Set device to up */
        ULONG status = TRUE;
        if (!DeviceIoControl (this->tunhandle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
  			  &status, sizeof (status),
                            &status, sizeof (status), &len, NULL))
        {
            DBG1 (DBG_LIB, "WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
        }

            /* Give the adapter 2 seconds to come up */
        DBG3 (DBG_LIB, "Sleeping for %d seconds...", 2);
        sleep(2);
#elif defined(IFF_TUN)

	struct ifreq ifr;

	strncpy(this->if_name, name_tmpl ?: "tun%d", IFNAMSIZ);
	this->if_name[IFNAMSIZ-1] = '\0';

	this->tunfd = open("/dev/net/tun", O_RDWR);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/net/tun: %s", strerror(errno));
		return FALSE;
	}

	memset(&ifr, 0, sizeof(ifr));

	/* TUN device, no packet info */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	if (ioctl(this->tunfd, TUNSETIFF, (void*)&ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to configure TUN device: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	strncpy(this->if_name, ifr.ifr_name, IFNAMSIZ);
	return TRUE;

#else /* !IFF_TUN */

	/* this works on FreeBSD and might also work on Linux with older TUN
	 * driver versions (no IFF_TUN) */
	char devname[IFNAMSIZ];
	/* the same process is allowed to open a device again, but that's not what
	 * we want (unless we previously closed a device, which we don't know at
	 * this point).  therefore, this counter is static so we don't accidentally
	 * open a device twice */
	static int i = -1;

	if (name_tmpl)
	{
		DBG1(DBG_LIB, "arbitrary naming of TUN devices is not supported");
	}

	for (; ++i < 256; )
	{
		snprintf(devname, IFNAMSIZ, "/dev/tun%d", i);
		this->tunfd = open(devname, O_RDWR);
		if (this->tunfd > 0)
		{	/* for ioctl(2) calls only the interface name is used */
			snprintf(this->if_name, IFNAMSIZ, "tun%d", i);
			break;
		}
		DBG1(DBG_LIB, "failed to open %s: %s", this->if_name, strerror(errno));
	}
	return this->tunfd > 0;

#endif /* !__APPLE__ */
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
                        /* For WIN32, that's a handle. */
#ifdef WIN32
                        .get_handle = _get_handle,
#else
			.get_fd = _get_fd,
#endif
			.set_address = _set_address,
			.get_address = _get_address,
			.up = _up,
			.destroy = _destroy,
		},
#ifdef WIN32
                .tunhandle = NULL,
#else
		.tunfd = -1,
#endif
		.sock = -1,
	);

	if (!init_tun(this, name_tmpl))
	{
		free(this);
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

#endif /* TUN devices supported */
