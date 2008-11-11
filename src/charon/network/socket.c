/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2007 Martin Willi
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
 *
 * $Id$
 */

/* for struct in6_pktinfo */
#define _GNU_SOURCE

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <net/if.h>

#include "socket.h"

#include <daemon.h>

/* length of non-esp marker */
#define MARKER_LEN sizeof(u_int32_t)

/* from linux/udp.h */
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif /*UDP_ENCAP*/

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif /*UDP_ENCAP_ESPINUDP*/

/* needed for older kernel headers */
#ifndef IPV6_2292PKTINFO
#define IPV6_2292PKTINFO 2
#endif /*IPV6_2292PKTINFO*/

/* missing on uclibc */
#ifndef IPV6_IPSEC_POLICY
#define IPV6_IPSEC_POLICY 34
#endif /*IPV6_IPSEC_POLICY*/

typedef struct private_socket_t private_socket_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_t {
	/**
	 * public functions
	 */
	 socket_t public;
	 
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
};

/**
 * enumerator for underlying sockets
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** sockets we enumerate */
	private_socket_t *socket;
	/** counter */
	u_int8_t index;
} socket_enumerator_t;

/**
 * implementation of socket_t.receive
 */
static status_t receiver(private_socket_t *this, packet_t **packet)
{
	char buffer[MAX_PACKET];
	chunk_t data;
	packet_t *pkt;
	host_t *source = NULL, *dest = NULL;
	int bytes_read = 0;
	int data_offset, oldstate;
	fd_set rfds;
	int max_fd = 0, selected = 0;
	u_int16_t port;

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
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	if (select(max_fd + 1, &rfds, NULL, NULL, NULL) <= 0)
	{
		pthread_setcancelstate(oldstate, NULL);
		return FAILED;
	}
	pthread_setcancelstate(oldstate, NULL);
	
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
		iov.iov_len = sizeof(buffer);
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
			
			if (cmsgptr->cmsg_level == SOL_IPV6 &&
				cmsgptr->cmsg_type == IPV6_2292PKTINFO)
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
			if (cmsgptr->cmsg_level == SOL_IP &&
				cmsgptr->cmsg_type == IP_PKTINFO)
			{			
				struct in_pktinfo *pktinfo;
				pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsgptr);
				struct sockaddr_in dst;
				
				memset(&dst, 0, sizeof(dst));
				memcpy(&dst.sin_addr, &pktinfo->ipi_addr, sizeof(dst.sin_addr));
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

/**
 * implementation of socket_t.send
 */
status_t sender(private_socket_t *this, packet_t *packet)
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
			if (data.len > MAX_PACKET - MARKER_LEN)
			{
				DBG1(DBG_NET, "unable to send packet: it's too big (%d bytes)",
					 data.len);
				return FAILED;
			}
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
	
	if (!dst->is_anyaddr(dst))
	{
		if (family == AF_INET)
		{
			char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
			struct in_pktinfo *pktinfo;
			struct sockaddr_in *sin;
			
			msg.msg_control = buf;
			msg.msg_controllen = sizeof(buf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(struct in_pktinfo));
			sin = (struct sockaddr_in*)src->get_sockaddr(src);
			memcpy(&pktinfo->ipi_spec_dst, &sin->sin_addr, sizeof(struct in_addr));
		}
		else
		{
			char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
			struct in6_pktinfo *pktinfo;
			struct sockaddr_in6 *sin;
			
			msg.msg_control = buf;
			msg.msg_controllen = sizeof(buf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_IPV6;
			cmsg->cmsg_type = IPV6_2292PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(struct in6_pktinfo));
			sin = (struct sockaddr_in6*)src->get_sockaddr(src);
			memcpy(&pktinfo->ipi6_addr, &sin->sin6_addr, sizeof(struct in6_addr));
		}
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
 * open a socket to send packets
 */
static int open_socket(private_socket_t *this, int family, u_int16_t port)
{
	int on = TRUE;
	int type = UDP_ENCAP_ESPINUDP;
	struct sockaddr_storage addr;
	u_int sol, pktinfo;
	int skt;
	
	memset(&addr, 0, sizeof(addr));
	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = INADDR_ANY;
			sin->sin_port = htons(port);
			sol = SOL_IP;
			pktinfo = IP_PKTINFO;
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			sin6->sin6_port = htons(port);
			sol = SOL_IPV6;
			pktinfo = IPV6_2292PKTINFO;
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
	
	/* bind the send socket */
	if (bind(skt, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_NET, "unable to bind socket: %s", strerror(errno));
		close(skt);
		return 0;
	}
	
	/* get additional packet info on receive */
	if (setsockopt(skt, sol, pktinfo, &on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set IP_PKTINFO on socket: %s", strerror(errno));
		close(skt);
		return 0;
	}
	
	/* enable UDP decapsulation globally, only for one socket needed */
	if (family == AF_INET && port == IKEV2_NATT_PORT &&
		setsockopt(skt, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
	{
		DBG1(DBG_NET, "unable to set UDP_ENCAP: %s", strerror(errno));
	}
	return skt;
}

/**
 * enumerate function for socket_enumerator_t
 */
static bool enumerate(socket_enumerator_t *this, int *fd, int *family, int *port)
{
	static const struct {
		int fd_offset;
		int family;
		int port;
	} sockets[] = {
		{ 0, 0, 0 },
		{ offsetof(private_socket_t, ipv4), AF_INET, IKEV2_UDP_PORT },
		{ offsetof(private_socket_t, ipv6), AF_INET6, IKEV2_UDP_PORT },
		{ offsetof(private_socket_t, ipv4_natt), AF_INET, IKEV2_NATT_PORT },
		{ offsetof(private_socket_t, ipv6_natt), AF_INET6, IKEV2_NATT_PORT }
	};
	
	while(++this->index <= 4)
	{
		int sock = *(int*)((char*)this->socket + sockets[this->index].fd_offset);
		if (!sock)
		{
			continue;
		}
		*fd = sock;
		*family = sockets[this->index].family;
		*port = sockets[this->index].port;
		return TRUE;
	}
	return FALSE;
}

/**
 * implementation of socket_t.create_enumerator
 */
static enumerator_t *create_enumerator(private_socket_t *this)
{
	socket_enumerator_t *enumerator;
	
	enumerator = malloc_thing(socket_enumerator_t);
	enumerator->index = 0;
	enumerator->socket = this;
	enumerator->public.enumerate = (void*)enumerate;
	enumerator->public.destroy = (void*)free;
	return &enumerator->public;
}

/**
 * implementation of socket_t.destroy
 */
static void destroy(private_socket_t *this)
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
socket_t *socket_create()
{
	private_socket_t *this = malloc_thing(private_socket_t);

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.create_enumerator = (enumerator_t*(*)(socket_t*))create_enumerator;
	this->public.destroy = (void(*)(socket_t*)) destroy;
	
	this->ipv4 = 0;
	this->ipv6 = 0;
	this->ipv4_natt = 0;
	this->ipv6_natt = 0;
	
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
		charon->kill(charon, "socket initialization failed");
	}	
	return (socket_t*)this;
}

