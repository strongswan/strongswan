/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * Copyright (C) 2020 Dan James
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

/*
 * Based on strongswan/src/libcharon/plugins/updown for the plugin structure,
 * and PPPd (https://opensource.apple.com/source/ppp/ppp-862) for the
 * interface scanning and route table updates.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/route.h>
#include <net/if.h>

#ifdef __APPLE__

#include <net/if_dl.h>
#include <sys/sockio.h>

#endif
#ifdef __linux__
#include <net/if_arp.h>
#endif

#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#include "proxyarp_listener.h"

#include <daemon.h>
#include <config/child_cfg.h>

#define ALIGNED_CAST(type) (type)(void *)

typedef struct private_proxyarp_listener_t private_proxyarp_listener_t;

/**
 * Private data of an proxyarp_listener_t object.
 */
struct private_proxyarp_listener_t {
	/**
	 * Public proxyarp_listener_t interface.
	 */
	proxyarp_listener_t public;

	/**
	 * List of cached ARP messages
	 */
	linked_list_t *cache;

	/**
	 * Sequence used when making ARP route requests.
	 */
	u_int32_t rtm_seq;
};

static char *format_ip(char *ip_buf, size_t ip_buf_len, u_int32_t ipaddr)
{
	const u_int32_t mask = 0xff;
	snprintf(ip_buf, ip_buf_len, "%d.%d.%d.%d", ipaddr & mask,
			 (ipaddr >> 8u) & mask, (ipaddr >> 16u) & mask,
			 (ipaddr >> 24u) & mask);
	return ip_buf;
}

static char *format_mac(char *mac_buf, size_t mac_buf_len, const char *macaddr)
{
	const u_int32_t mask = 0xff;
	const unsigned char *umacaddr = (const unsigned char *) macaddr;
	snprintf(mac_buf, mac_buf_len, "%02x.%02x.%02x.%02x.%02x.%02x",
			 umacaddr[0] & mask, umacaddr[1] & mask,
			 umacaddr[2] & mask, umacaddr[3] & mask,
			 umacaddr[4] & mask, umacaddr[5] & mask);
	return mac_buf;
}

#ifdef __APPLE__

#define NEXT_IFR(ifr)      ALIGNED_CAST(struct ifreq *)\
	((char *)&ifr->ifr_addr + ifr->ifr_addr.sa_len)

typedef struct arp_msg_t arp_msg_t;

/**
 * Message format for adding and removing proxy arp entries to routing.
 */
struct arp_msg_t {
	struct rt_msghdr hdr;
	struct sockaddr_inarp dst;
	struct sockaddr_dl hwa;
	char extra[128];
};

static arp_msg_t *cache_arp_msg(private_proxyarp_listener_t *this,
								u_int32_t hisaddr)
{
	arp_msg_t *arp_msg = malloc_thing(arp_msg_t);

	memset(arp_msg, 0, sizeof(arp_msg_t));
	this->rtm_seq += 1;
	arp_msg->hdr.rtm_type = RTM_ADD;
	arp_msg->hdr.rtm_flags = RTF_ANNOUNCE | RTF_HOST | RTF_STATIC;
	arp_msg->hdr.rtm_version = RTM_VERSION;
	arp_msg->hdr.rtm_seq = this->rtm_seq;
	arp_msg->hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;
	arp_msg->hdr.rtm_inits = RTV_EXPIRE;
	arp_msg->dst.sin_len = sizeof(struct sockaddr_inarp);
	arp_msg->dst.sin_family = AF_INET;
	arp_msg->dst.sin_addr.s_addr = hisaddr;
	arp_msg->dst.sin_other = SIN_PROXY;

	this->cache->insert_first(this->cache, arp_msg);

	return arp_msg;
}

static arp_msg_t *uncache_arp_msg(private_proxyarp_listener_t *this,
								  u_int32_t hisaddr)
{
	enumerator_t *enumerator;
	arp_msg_t *r = 0;
	arp_msg_t *i;

	enumerator = this->cache->create_enumerator(this->cache);
	while (enumerator->enumerate(enumerator, &i)) {
		if (i->dst.sin_addr.s_addr == hisaddr) {
			this->cache->remove_at(this->cache, enumerator);
			r = i;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return r;
}

/* --------------------------------------------------------------------------
   get the hardware address of an interface on the same subnet as ipaddr.
   -------------------------------------------------------------------------- */
static int get_ether_addr(u_int32_t ipaddr, struct sockaddr_dl *hwaddr)
{
	short allow_flgs = IFF_UP | IFF_BROADCAST;
	short check_flgs = allow_flgs | IFF_POINTOPOINT | IFF_LOOPBACK | IFF_NOARP;
	char ip_buf[3][18];
	struct ifreq *ifr, *ifend, *ifp;
	struct ifreq ifs[32];
	struct ifreq ifreq;
	struct sockaddr_dl *dla;
	struct ifconf ifc;
	u_int32_t ina, mask;
	int ip_sockfd;

	ip_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ip_sockfd < 0) {
		DBG1(DBG_CHD, "proxyarp: %s socket(INET, DGRAM, 0): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr), errno);
		return 0;
	}

	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;
	if (ioctl(ip_sockfd, SIOCGIFCONF, &ifc) < 0) {
		DBG1(DBG_CHD, "proxyarp: %s ioctl(SIOCGIFCONF): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr), errno);
		close(ip_sockfd);
		return 0;
	}

	/*
	 * Scan through looking for an interface with an Internet address on the
	 * same subnet as `ipaddr'.
	 */
	DBG1(DBG_CHD, "proxyarp: find iface matching %s",
		 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr));

	ifend = ALIGNED_CAST(struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
	for (ifr = ifc.ifc_req; ifr < ifend; ifr = NEXT_IFR(ifr)) {
		if (ifr->ifr_addr.sa_family == AF_INET) {
			ina = (ALIGNED_CAST(struct sockaddr_in *) &ifr->ifr_addr)
					->sin_addr.s_addr;
			snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s",
					 ifr->ifr_name);
			/*
			 * Check that the interface is up, and not point-to-point
			 * or loopback.
			 */
			if (ioctl(ip_sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
				DBG1(DBG_CHD, "- %s: failed to get flags", ifr->ifr_name);
				continue;
			}
			if ((ifreq.ifr_flags & check_flgs) != allow_flgs) {
				DBG1(DBG_CHD, "- %s: wrong flags %08x != %08x", ifr->ifr_name,
					 ifreq.ifr_flags & check_flgs, allow_flgs);
				continue;
			}
			/*
			 * Get its netmask and check that it's on the right subnet.
			 */
			if (ioctl(ip_sockfd, SIOCGIFNETMASK, &ifreq) < 0) {
				DBG1(DBG_CHD, "- %s: failed to get netmask", ifr->ifr_name);
				continue;
			}
			mask = (ALIGNED_CAST(struct sockaddr_in *) &ifreq.ifr_addr)
					->sin_addr.s_addr;
			if ((ipaddr & mask) != (ina & mask)) {
				DBG1(DBG_CHD, "- %s: wrong subnet %s/%s/%s", ifr->ifr_name,
					 format_ip(ip_buf[0], sizeof(ip_buf[0]), ina),
					 format_ip(ip_buf[1], sizeof(ip_buf[1]), mask),
					 format_ip(ip_buf[2], sizeof(ip_buf[2]), ina & mask));
				continue;
			}

			DBG1(DBG_CHD, "- %s: match %s/%s/%s", ifr->ifr_name,
				 format_ip(ip_buf[0], sizeof(ip_buf[0]), ina),
				 format_ip(ip_buf[1], sizeof(ip_buf[1]), mask),
				 format_ip(ip_buf[2], sizeof(ip_buf[2]), ina & mask));
			break;
		}
	}

	close(ip_sockfd);

	if (ifr >= ifend) {
		DBG1(DBG_CHD, "proxyarp: %s no suitable interface found",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr));
		return 0;
	}

	/*
	 * Now scan through again looking for a link-level address
	 * for this interface.
	 */
	ifp = ifr;
	for (ifr = ifc.ifc_req; ifr < ifend; ifr = NEXT_IFR(ifr)) {
		const bool is_link = ifr->ifr_addr.sa_family == AF_LINK;
		if (is_link && strcmp(ifp->ifr_name, ifr->ifr_name) == 0) {
			/*
			 * Found the link-level address - copy it out
			 */
			dla = ALIGNED_CAST(struct sockaddr_dl *) &ifr->ifr_addr;
			memcpy(hwaddr, dla, dla->sdl_len);

			DBG1(DBG_CHD, "proxyarp: if=%s family=%d mac=%s",
				 ifreq.ifr_name, dla->sdl_family,
				 format_mac(ip_buf[0], sizeof(ip_buf[0]), dla->sdl_data));

			return 1;
		}
	}

	DBG1(DBG_CHD, "proxyarp: no link interface for %s", ifp->ifr_name);
	return 0;
}

/* --------------------------------------------------------------------------
   Delete all the proxy ARP entries in the cache
   -------------------------------------------------------------------------- */
static void cifproxyarps(private_proxyarp_listener_t *this)
{
	char ip_buf[1][18];
	int routes;
	enumerator_t *enumerator;
	arp_msg_t *i;

	routes = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE);
	if (routes >= 0) {
		enumerator = this->cache->create_enumerator(this->cache);
		while (enumerator->enumerate(enumerator, &i)) {
			this->cache->remove_at(this->cache, enumerator);

			this->rtm_seq += 1;
			i->hdr.rtm_type = RTM_DELETE;
			i->hdr.rtm_seq = this->rtm_seq;

			if (write(routes, i, i->hdr.rtm_msglen) < 0) {
				DBG1(DBG_CHD, "proxyarp: delete %s failed: write: %d",
					 format_ip(ip_buf[0], sizeof(ip_buf[0]),
							   i->dst.sin_addr.s_addr),
					 errno);
			}

			free(i);
		}
		enumerator->destroy(enumerator);
		close(routes);
	}
}

/* --------------------------------------------------------------------------
   Delete the proxy ARP entry for the peer
   -------------------------------------------------------------------------- */
static int cifproxyarp(private_proxyarp_listener_t *this, u_int32_t hisaddr)
{
	char ip_buf[2][18];
	int routes;
	arp_msg_t *arp_msg = uncache_arp_msg(this, hisaddr);

	if (arp_msg == 0) {
		return 0;
	}

	this->rtm_seq += 1;
	arp_msg->hdr.rtm_type = RTM_DELETE;
	arp_msg->hdr.rtm_seq = this->rtm_seq;

	routes = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE);
	if (routes < 0) {
		DBG1(DBG_CHD, "proxyarp: delete %s failed: socket: %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr), errno);
		free(arp_msg);
		return 0;
	}

	if (write(routes, arp_msg, arp_msg->hdr.rtm_msglen) < 0) {
		DBG1(DBG_CHD, "proxyarp: delete %s failed: write: %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr), errno);
		close(routes);
		free(arp_msg);
		return 0;
	}

	DBG1(DBG_CHD, "proxyarp: delete %s",
		 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr));
	close(routes);
	free(arp_msg);

	return 1;
}

/* --------------------------------------------------------------------------
   Make a proxy ARP entry for the peer
   -------------------------------------------------------------------------- */
static int sifproxyarp(private_proxyarp_listener_t *this, u_int32_t hisaddr)
{
	char ip_buf[1][18];
	int routes;
	arp_msg_t *arp_msg = cache_arp_msg(this, hisaddr);

	/*
	 * Get the hardware address of an interface on the same subnet
	 * as our local address.
	 */
	if (!get_ether_addr(hisaddr, &arp_msg->hwa)) {
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	routes = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE);
	if (routes < 0) {
		DBG1(DBG_CHD, "proxyarp: %s socket(ROUTE, RAW, ROUTE): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr), errno);
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	u_int32_t hdr_len = ((char *) &arp_msg->hwa) - ((char *) arp_msg);
	arp_msg->hdr.rtm_msglen = hdr_len + arp_msg->hwa.sdl_len;
	if (write(routes, arp_msg, arp_msg->hdr.rtm_msglen) < 0) {
		DBG1(DBG_CHD, "proxyarp: %s write(hdr=%d sdl=%d rtm=%d): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr), hdr_len,
			 arp_msg->hwa.sdl_len, arp_msg->hdr.rtm_msglen, errno);
		close(routes);
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	DBG1(DBG_CHD, "proxyarp: add %s",
		 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr));
	close(routes);

	return 1;
}

#endif /* __APPLE__ */

#ifdef __linux__
#define NEXT_IFR(ifr)      ALIGNED_CAST(struct ifreq *)\
    ((char *)ifr + sizeof(*ifr))

static struct arpreq *cache_arp_msg(private_proxyarp_listener_t *this,
									u_int32_t hisaddr)
{
	struct arpreq *arp_msg = malloc_thing(struct arpreq);
	struct sockaddr_in *si;

	memset(arp_msg, 0, sizeof(struct arpreq));

	arp_msg->arp_flags = ATF_COM | ATF_PERM | ATF_PUBL;

	si = (struct sockaddr_in *) &arp_msg->arp_pa;
	si->sin_family = AF_INET;
	si->sin_addr.s_addr = hisaddr;

	this->cache->insert_first(this->cache, arp_msg);

	return arp_msg;
}

static struct arpreq *uncache_arp_msg(private_proxyarp_listener_t *this,
									  u_int32_t hisaddr)
{
	enumerator_t *enumerator;
	struct arpreq *r = 0;
	struct arpreq *i;
	struct sockaddr_in *si;

	enumerator = this->cache->create_enumerator(this->cache);
	while (enumerator->enumerate(enumerator, &i)) {
		si = (struct sockaddr_in *) &i->arp_pa;
		if (si->sin_addr.s_addr == hisaddr) {
			this->cache->remove_at(this->cache, enumerator);
			r = i;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return r;
}

/* --------------------------------------------------------------------------
   get the hardware address of an interface on the same subnet as ipaddr.
   -------------------------------------------------------------------------- */
static int
get_ether_addr(u_int32_t ipaddr, struct sockaddr_storage *hwaddr, char *devp,
			   size_t devlen)
{
	short allow_flgs = IFF_UP | IFF_BROADCAST;
	short check_flgs = allow_flgs | IFF_POINTOPOINT | IFF_LOOPBACK | IFF_NOARP;
	char ip_buf[3][18];
	struct ifreq *ifr, *ifend;
	struct ifreq ifs[32];
	struct ifreq ifreq;
	struct ifconf ifc;
	u_int32_t ina, mask;
	int ip_sockfd;

	ip_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ip_sockfd < 0) {
		DBG1(DBG_CHD, "proxyarp: %s socket(INET, DGRAM, 0): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr), errno);
		return 0;
	}

	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;
	if (ioctl(ip_sockfd, SIOCGIFCONF, &ifc) < 0) {
		DBG1(DBG_CHD, "proxyarp: %s ioctl(SIOCGIFCONF): %d",
			 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr), errno);
		close(ip_sockfd);
		return 0;
	}

	/*
	 * Scan through looking for an interface with an Internet address on the
	 * same subnet as `ipaddr'.
	 */
	DBG1(DBG_CHD, "proxyarp: find iface matching %s",
		 format_ip(ip_buf[0], sizeof(ip_buf[0]), ipaddr));

	ifend = ALIGNED_CAST(struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
	for (ifr = ifc.ifc_req; ifr < ifend; ifr = NEXT_IFR(ifr)) {
		if (ifr->ifr_addr.sa_family == AF_INET) {
			ina = (ALIGNED_CAST(struct sockaddr_in *) &ifr->ifr_addr)
					->sin_addr.s_addr;
			snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s",
					 ifr->ifr_name);
			/*
			 * Check that the interface is up, and not point-to-point
			 * or loopback.
			 */
			if (ioctl(ip_sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
				DBG1(DBG_CHD, "- %s: failed to get flags", ifr->ifr_name);
				continue;
			}
			if ((ifreq.ifr_flags & check_flgs) != allow_flgs) {
				DBG1(DBG_CHD, "- %s: wrong flags %08x != %08x", ifr->ifr_name,
					 ifreq.ifr_flags & check_flgs, allow_flgs);
				continue;
			}
			/*
			 * Get its netmask and check that it's on the right subnet.
			 */
			if (ioctl(ip_sockfd, SIOCGIFNETMASK, &ifreq) < 0) {
				DBG1(DBG_CHD, "- %s: failed to get netmask", ifr->ifr_name);
				continue;
			}
			mask = (ALIGNED_CAST(struct sockaddr_in *) &ifreq.ifr_addr)
					->sin_addr.s_addr;
			if ((ipaddr & mask) != (ina & mask)) {
				DBG1(DBG_CHD, "- %s: wrong subnet %s/%s/%s", ifr->ifr_name,
					 format_ip(ip_buf[0], sizeof(ip_buf[0]), ina),
					 format_ip(ip_buf[1], sizeof(ip_buf[1]), mask),
					 format_ip(ip_buf[2], sizeof(ip_buf[2]), ina & mask));
				continue;
			}

			DBG1(DBG_CHD, "- %s: match %s/%s/%s", ifr->ifr_name,
				 format_ip(ip_buf[0], sizeof(ip_buf[0]), ina),
				 format_ip(ip_buf[1], sizeof(ip_buf[1]), mask),
				 format_ip(ip_buf[2], sizeof(ip_buf[2]), ina & mask));

			if (ioctl(ip_sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
				DBG1(DBG_CHD, "proxyarp: ioctl(SIOCGIFHWADDR): %d", errno);
				close(ip_sockfd);
				return 0;
			}

			DBG1(DBG_CHD, "proxyarp: if=%s family=%d mac=%s",
				 ifreq.ifr_name, ifreq.ifr_hwaddr.sa_family,
				 format_mac(ip_buf[0], sizeof(ip_buf[0]),
							ifreq.ifr_hwaddr.sa_data));
			memcpy(hwaddr, &ifreq.ifr_hwaddr, sizeof(ifreq.ifr_hwaddr));
			snprintf(devp, devlen, "%s", ifreq.ifr_name);
			break;
		}
	}

	close(ip_sockfd);

	if (ifr >= ifend) {
		DBG1(DBG_CHD, "proxyarp: no suitable interface found");
		return 0;
	}

	return 1;
}

/* --------------------------------------------------------------------------
   Delete all the proxy ARP entries in the cache
   -------------------------------------------------------------------------- */
static void cifproxyarps(private_proxyarp_listener_t *this)
{
	char ip_buf[1][18];
	int ip_sockfd;
	enumerator_t *enumerator;
	struct arpreq *i;
	struct sockaddr_in *si;

	ip_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ip_sockfd >= 0) {
		enumerator = this->cache->create_enumerator(this->cache);
		while (enumerator->enumerate(enumerator, &i)) {
			si = (struct sockaddr_in *) &i->arp_pa;
			this->cache->remove_at(this->cache, enumerator);

			if (ioctl(ip_sockfd, SIOCDARP, i) < 0) {
				DBG1(DBG_CHD, "proxyarp: delete %s failed: write: %d",
					 format_ip(ip_buf[0], sizeof(ip_buf[0]),
							   si->sin_addr.s_addr), errno);
			}

			DBG1(DBG_CHD, "proxyarp: delete entry %s",
				 format_ip(ip_buf[0], sizeof(ip_buf[0]), si->sin_addr.s_addr));
			free(i);
		}
		enumerator->destroy(enumerator);
		close(ip_sockfd);
	}
}

/* --------------------------------------------------------------------------
   Delete the proxy ARP entry for the peer
   -------------------------------------------------------------------------- */
static int cifproxyarp(private_proxyarp_listener_t *this, u_int32_t hisaddr)
{
	char ip_buf[1][18];
	int ip_sockfd;
	struct arpreq *arp_msg = uncache_arp_msg(this, hisaddr);

	if (arp_msg == 0) {
		return 0;
	}

	ip_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ip_sockfd < 0) {
		DBG1(DBG_CHD, "proxyarp: socket(INET, DGRAM, 0): %d", errno);
		free(arp_msg);
		return 0;
	}

	if (ioctl(ip_sockfd, SIOCDARP, arp_msg) < 0) {
		DBG1(DBG_CHD, "proxyarp: socket(INET, DGRAM, 0): %d", errno);
		free(arp_msg);
		return 0;
	}

	DBG1(DBG_CHD, "proxyarp: delete entry %s",
		 format_ip(ip_buf[0], sizeof(ip_buf[0]), hisaddr));

	return 1;
}

/* --------------------------------------------------------------------------
   Make a proxy ARP entry for the peer
   -------------------------------------------------------------------------- */
static int sifproxyarp(private_proxyarp_listener_t *this, u_int32_t hisaddr)
{
	int ip_sockfd;
	struct arpreq *arp_msg = cache_arp_msg(this, hisaddr);
	struct sockaddr_storage *ss = (struct sockaddr_storage *) &arp_msg->arp_ha;

	if (!get_ether_addr(hisaddr, ss, arp_msg->arp_dev,
						sizeof(arp_msg->arp_dev))) {
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	ip_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ip_sockfd < 0) {
		DBG1(DBG_CHD, "proxyarp: socket(INET, DGRAM, 0): %d", errno);
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	if (ioctl(ip_sockfd, SIOCSARP, arp_msg) < 0) {
		DBG1(DBG_CHD, "proxyarp: socket(INET, DGRAM, 0): %d", errno);
		uncache_arp_msg(this, hisaddr);
		free(arp_msg);
		return 0;
	}

	return 1;
}

#endif /* __linux__ */

/**
 * Invoke the proxyarp script once for given traffic selectors
 */
static int invoke_once(private_proxyarp_listener_t *this, ike_sa_t *ike_sa,
					   child_sa_t *child_sa, child_cfg_t *config, bool up,
					   traffic_selector_t *my_ts, traffic_selector_t *other_ts)
{
	host_t *other;
	u_int8_t cidr;
	u_int32_t hisaddr;

	other_ts->to_subnet(other_ts, &other, &cidr);
	hisaddr = ((struct sockaddr_in *) other->get_sockaddr(other))
			->sin_addr.s_addr;
	other->destroy(other);

	if (cidr == 32) {
		return up ? sifproxyarp(this, hisaddr) : cifproxyarp(this, hisaddr);
	} else {
		return 0;
	}
}

METHOD(listener_t, child_updown, bool, private_proxyarp_listener_t *this,
	   ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	child_cfg_t *config;

	config = child_sa->get_config(child_sa);
	if (/* TODO: config->get_farp(config)*/1) {
		enumerator = child_sa->create_policy_enumerator(child_sa);
		while (enumerator->enumerate(enumerator, &my_ts, &other_ts)) {
			invoke_once(this, ike_sa, child_sa, config, up, my_ts, other_ts);
		}
		enumerator->destroy(enumerator);
	}
	return TRUE;
}

METHOD(proxyarp_listener_t, destroy, void, private_proxyarp_listener_t *this)
{
	cifproxyarps(this);
	this->cache->destroy(this->cache);
	free(this);
}

/**
 * See header
 */
proxyarp_listener_t *proxyarp_listener_create()
{
	private_proxyarp_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown
			},
			.destroy = _destroy
		},
		.cache = linked_list_create(),
		.rtm_seq = 0
	);

	return &this->public;
}
