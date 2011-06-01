/*
 * Copyright (C) 2006-2010 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

/* for struct in6_pktinfo */
#define _GNU_SOURCE
#ifdef __sun
#define _XPG4_2
#define __EXTENSIONS__
#endif

#include "socket_default_socket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

#include <hydra.h>
#include <daemon.h>
#include <threading/thread.h>

/* Maximum size of a packet */
#define MAX_PACKET 10000

/* length of non-esp marker */
#define MARKER_LEN sizeof(u_int32_t)

/* from linux/udp.h */
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif /*UDP_ENCAP*/

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif /*UDP_ENCAP_ESPINUDP*/

/* these are not defined on some platforms */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_UDP
#define SOL_UDP IPPROTO_UDP
#endif

/* IPV6_RECVPKTINFO is defined in RFC 3542 which obsoletes RFC 2292 that
 * previously defined IPV6_PKTINFO */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT {{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}}
#endif

#ifndef HAVE_IN6ADDR_ANY
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#endif

typedef struct private_socket_default_socket_t private_socket_default_socket_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_default_socket_t {

	/**
	 * public functions
	 */
	socket_default_socket_t public;

	/**
	 * IPv4 socket (500)
	 */
	int ipv4;

	/**
	 * IPv4 socket for NATT (4500)
	 */
	int ipv4_natt;

	/**
	 * IPv6 socket (500)
	 */
	int ipv6;

	/**
	 * IPv6 socket for NATT (4500)
	 */
	int ipv6_natt;

	/**
	 * Maximum packet size to receive
	 */
	int max_packet;
};

METHOD(socket_t, receiver, status_t,
	private_socket_default_socket_t *this, packet_t **packet)
{
	char buffer[this->max_packet];
	chunk_t data;
	packet_t *pkt;
	host_t *source = NULL, *dest = NULL;
	int bytes_read = 0, data_offset;
	bool oldstate;

	fd_set rfds;
	int max_fd = 0, selected = 0;
	u_int16_t port = 0;

	FD_ZERO(&rfds);

	if (this->ipv4)
	{
		FD_SET(this->ipv4, &rfds);
	}
	if (this->ipv4_natt)
	{
		FD_SET(this->ipv4_natt, &rfds);
	}
	if (this->ipv6)
	{
		FD_SET(this->ipv6, &rfds);
	}
	if (this->ipv6_natt)
	{
		FD_SET(this->ipv6_natt, &rfds);
	}
	max_fd = max(max(this->ipv4, this->ipv4_natt), max(this->ipv6, this->ipv6_natt));

	DBG2(DBG_NET, "waiting for data on sockets");
	oldstate = thread_cancelability(TRUE);
	if (select(max_fd + 1, &rfds, NULL, NULL, NULL) <= 0)
	{
		thread_cancelability(oldstate);
		return FAILED;
	}
	thread_cancelability(oldstate);

	if (FD_ISSET(this->ipv4, &rfds))
	{
		port = IKEV2_UDP_PORT;
		selected = this->ipv4;
	}
	if (FD_ISSET(this->ipv4_natt, &rfds))
	{
		port = IKEV2_NATT_PORT;
		selected = this->ipv4_natt;
	}
	if (FD_ISSET(this->ipv6, &rfds))
	{
		port = IKEV2_UDP_PORT;
		selected = this->ipv6;
	}
	if (FD_ISSET(this->ipv6_natt, &rfds))
	{
		port = IKEV2_NATT_PORT;
		selected = this->ipv6_natt;
	}
	if (selected)
	{
		struct msghdr msg;
		struct cmsghdr *cmsgptr;
		struct iovec iov;
		char ancillary[64];
		union {
			struct sockaddr_in in4;
			struct sockaddr_in6 in6;
		} src;

		msg.msg_name = &src;
		msg.msg_namelen = sizeof(src);
		iov.iov_base = buffer;
		iov.iov_len = this->max_packet;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ancillary;
		msg.msg_controllen = sizeof(ancillary);
		msg.msg_flags = 0;
		bytes_read = recvmsg(selected, &msg, 0);
		if (bytes_read < 0)
		{
			DBG1(DBG_NET, "error reading socket: %s", strerror(errno));
			return FAILED;
		}
		if (msg.msg_flags & MSG_TRUNC)
		{
			DBG1(DBG_NET, "receive buffer too small, packet discarded");
			return FAILED;
		}
		DBG3(DBG_NET, "received packet %b", buffer, bytes_read);

		if (bytes_read < MARKER_LEN)
		{
			DBG3(DBG_NET, "received packet too short (%d bytes)",
				 bytes_read);
			return FAILED;
		}

		/* read ancillary data to get destination address */
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
			 cmsgptr = CMSG_NXTHDR(&msg, cmsgptr))
		{
			if (cmsgptr->cmsg_len == 0)
			{
				DBG1(DBG_NET, "error reading ancillary data");
				return FAILED;
			}

#ifdef HAVE_IN6_PKTINFO
			if (cmsgptr->cmsg_level == SOL_IPV6 &&
				cmsgptr->cmsg_type == IPV6_PKTINFO)
			{
				struct in6_pktinfo *pktinfo;
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsgptr);
				struct sockaddr_in6 dst;

				memset(&dst, 0, sizeof(dst));
				memcpy(&dst.sin6_addr, &pktinfo->ipi6_addr, sizeof(dst.sin6_addr));
				dst.sin6_family = AF_INET6;
				dst.sin6_port = htons(port);
				dest = host_create_from_sockaddr((sockaddr_t*)&dst);
			}
#endif /* HAVE_IN6_PKTINFO */
			if (cmsgptr->cmsg_level == SOL_IP &&
#ifdef IP_PKTINFO
				cmsgptr->cmsg_type == IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
				cmsgptr->cmsg_type == IP_RECVDSTADDR
#else
				FALSE
#endif
				)
			{
				struct in_addr *addr;
				struct sockaddr_in dst;

#ifdef IP_PKTINFO
				struct in_pktinfo *pktinfo;
				pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsgptr);
				addr = &pktinfo->ipi_addr;
#elif defined(IP_RECVDSTADDR)
				addr = (struct in_addr*)CMSG_DATA(cmsgptr);
#endif
				memset(&dst, 0, sizeof(dst));
				memcpy(&dst.sin_addr, addr, sizeof(dst.sin_addr));

				dst.sin_family = AF_INET;
				dst.sin_port = htons(port);
				dest = host_create_from_sockaddr((sockaddr_t*)&dst);
			}
			if (dest)
			{
				break;
			}
		}
		if (dest == NULL)
		{
			DBG1(DBG_NET, "error reading IP header");
			return FAILED;
		}
		source = host_create_from_sockaddr((sockaddr_t*)&src);

		pkt = packet_create();
		pkt->set_source(pkt, source);
		pkt->set_destination(pkt, dest);
		DBG2(DBG_NET, "received packet: from %#H to %#H", source, dest);
		data_offset = 0;
		/* remove non esp marker */
		if (dest->get_port(dest) == IKEV2_NATT_PORT)
		{
			data_offset += MARKER_LEN;
		}
		/* fill in packet */
		data.len = bytes_read - data_offset;
		data.ptr = malloc(data.len);
		memcpy(data.ptr, buffer + data_offset, data.len);
		pkt->set_data(pkt, data);
	}
	else
	{
		/* oops, shouldn't happen */
		return FAILED;
	}
	/* return packet */
	*packet = pkt;
	return SUCCESS;
}

METHOD(socket_t, sender, status_t,
	private_socket_default_socket_t *this, packet_t *packet)
{
	int sport, skt, family;
	ssize_t bytes_sent;
	chunk_t data, marked;
	host_t *src, *dst;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;

	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	data = packet->get_data(packet);

	DBG2(DBG_NET, "sending packet: from %#H to %#H", src, dst);

	/* send data */
	sport = src->get_port(src);
	family = dst->get_family(dst);
	if (sport == IKEV2_UDP_PORT)
	{
		if (family == AF_INET)
		{
			skt = this->ipv4;
		}
		else
		{
			skt = this->ipv6;
		}
	}
	else if (sport == IKEV2_NATT_PORT)
	{
		if (family == AF_INET)
		{
			skt = this->ipv4_natt;
		}
		else
		{
			skt = this->ipv6_natt;
		}
		/* NAT keepalives without marker */
		if (data.len != 1 || data.ptr[0] != 0xFF)
		{
			/* add non esp marker to packet */
			marked = chunk_alloc(data.len + MARKER_LEN);
			memset(marked.ptr, 0, MARKER_LEN);
			memcpy(marked.ptr + MARKER_LEN, data.ptr, data.len);
			/* let the packet do the clean up for us */
			packet->set_data(packet, marked);
			data = marked;
		}
	}
	else
	{
		DBG1(DBG_NET, "unable to locate a send socket for port %d", sport);
		return FAILED;
	}

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = dst->get_sockaddr(dst);;
	msg.msg_namelen = *dst->get_sockaddr_len(dst);
	iov.iov_base = data.ptr;
	iov.iov_len = data.len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (!src->is_anyaddr(src))
	{
		if (family == AF_INET)
		{
#if defined(IP_PKTINFO) || defined(IP_SENDSRCADDR)
			struct in_addr *addr;
			struct sockaddr_in *sin;
#ifdef IP_PKTINFO
			char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
			struct in_pktinfo *pktinfo;
#elif defined(IP_SENDSRCADDR)
			char buf[CMSG_SPACE(sizeof(struct in_addr))];
#endif
			msg.msg_control = buf;
			msg.msg_controllen = sizeof(buf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_IP;
#ifdef IP_PKTINFO
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(struct in_pktinfo));
			addr = &pktinfo->ipi_spec_dst;
#elif defined(IP_SENDSRCADDR)
			cmsg->cmsg_type = IP_SENDSRCADDR;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
			addr = (struct in_addr*)CMSG_DATA(cmsg);
#endif
			sin = (struct sockaddr_in*)src->get_sockaddr(src);
			memcpy(addr, &sin->sin_addr, sizeof(struct in_addr));
#endif /* IP_PKTINFO || IP_SENDSRCADDR */
		}
#ifdef HAVE_IN6_PKTINFO
		else
		{
			char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
			struct in6_pktinfo *pktinfo;
			struct sockaddr_in6 *sin;

			msg.msg_control = buf;
			msg.msg_controllen = sizeof(buf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(struct in6_pktinfo));
			sin = (struct sockaddr_in6*)src->get_sockaddr(src);
			memcpy(&pktinfo->ipi6_addr, &sin->sin6_addr, sizeof(struct in6_addr));
		}
#endif /* HAVE_IN6_PKTINFO */
	}

	bytes_sent = sendmsg(skt, &msg, 0);

	if (bytes_sent != data.len)
	{
		DBG1(DBG_NET, "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

/**
 * open a socket to send and receive packets
 */
static int open_socket(private_socket_default_socket_t *this,
					   int family, u_int16_t port)
{
	int on = TRUE;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	u_int sol, pktinfo = 0;
	int skt;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = family;
	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
			htoun32(&sin->sin_addr.s_addr, INADDR_ANY);
			htoun16(&sin->sin_port, port);
			addrlen = sizeof(struct sockaddr_in);
			sol = SOL_IP;
#ifdef IP_PKTINFO
			pktinfo = IP_PKTINFO;
#elif defined(IP_RECVDSTADDR)
			pktinfo = IP_RECVDSTADDR;
#endif
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			htoun16(&sin6->sin6_port, port);
			addrlen = sizeof(struct sockaddr_in6);
			sol = SOL_IPV6;
			pktinfo = IPV6_RECVPKTINFO;
			break;
		}
		default:
			return 0;
	}

	skt = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0)
	{
		DBG1(DBG_NET, "could not open socket: %s", strerror(errno));
		return 0;
	}
	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set SO_REUSEADDR on socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	/* bind the socket */
	if (bind(skt, (struct sockaddr *)&addr, addrlen) < 0)
	{
		DBG1(DBG_NET, "unable to bind socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	/* get additional packet info on receive */
	if (pktinfo > 0)
	{
		if (setsockopt(skt, sol, pktinfo, &on, sizeof(on)) < 0)
		{
			DBG1(DBG_NET, "unable to set IP_PKTINFO on socket: %s", strerror(errno));
			close(skt);
			return 0;
		}
	}

	if (!hydra->kernel_interface->bypass_socket(hydra->kernel_interface,
												skt, family))
	{
		DBG1(DBG_NET, "installing IKE bypass policy failed");
	}

#ifndef __APPLE__
	{
		/* enable UDP decapsulation globally, only for one socket needed */
		int type = UDP_ENCAP_ESPINUDP;
		if (family == AF_INET && port == IKEV2_NATT_PORT &&
			setsockopt(skt, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
		{
			DBG1(DBG_NET, "unable to set UDP_ENCAP: %s", strerror(errno));
		}
	}
#endif
	return skt;
}

METHOD(socket_t, destroy, void,
	private_socket_default_socket_t *this)
{
	if (this->ipv4)
	{
		close(this->ipv4);
	}
	if (this->ipv4_natt)
	{
		close(this->ipv4_natt);
	}
	if (this->ipv6)
	{
		close(this->ipv6);
	}
	if (this->ipv6_natt)
	{
		close(this->ipv6_natt);
	}
	free(this);
}

/*
 * See header for description
 */
socket_default_socket_t *socket_default_socket_create()
{
	private_socket_default_socket_t *this;

	INIT(this,
		.public = {
			.socket = {
				.send = _sender,
				.receive = _receiver,
				.destroy = _destroy,
			},
		},
		.max_packet = lib->settings->get_int(lib->settings,
										"charon.max_packet", MAX_PACKET),
	);

#ifdef __APPLE__
	{
		int natt_port = IKEV2_NATT_PORT;
		if (sysctlbyname("net.inet.ipsec.esp_port", NULL, NULL, &natt_port,
						 sizeof(natt_port)) != 0)
		{
			DBG1(DBG_NET, "could not set net.inet.ipsec.esp_port to %d: %s",
				 natt_port, strerror(errno));
		}
	}
#endif

	this->ipv4 = open_socket(this, AF_INET, IKEV2_UDP_PORT);
	if (this->ipv4 == 0)
	{
		DBG1(DBG_NET, "could not open IPv4 socket, IPv4 disabled");
	}
	else
	{
		this->ipv4_natt = open_socket(this, AF_INET, IKEV2_NATT_PORT);
		if (this->ipv4_natt == 0)
		{
			DBG1(DBG_NET, "could not open IPv4 NAT-T socket");
		}
	}

	this->ipv6 = open_socket(this, AF_INET6, IKEV2_UDP_PORT);
	if (this->ipv6 == 0)
	{
		DBG1(DBG_NET, "could not open IPv6 socket, IPv6 disabled");
	}
	else
	{
		this->ipv6_natt = open_socket(this, AF_INET6, IKEV2_NATT_PORT);
		if (this->ipv6_natt == 0)
		{
			DBG1(DBG_NET, "could not open IPv6 NAT-T socket");
		}
	}

	if (!this->ipv4 && !this->ipv6)
	{
		DBG1(DBG_NET, "could not create any sockets");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

