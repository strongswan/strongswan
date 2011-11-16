/*
 * Copyright (C) 2006-2010 Tobias Brunner
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
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

#include "socket_raw_socket.h"

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
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <net/if.h>

#include <hydra.h>
#include <daemon.h>
#include <threading/thread.h>

/* Maximum size of a packet */
#define MAX_PACKET 10000

/* constants for packet handling */
#define IP_LEN sizeof(struct iphdr)
#define IP6_LEN sizeof(struct ip6_hdr)
#define UDP_LEN sizeof(struct udphdr)
#define MARKER_LEN sizeof(u_int32_t)

/* offsets for packet handling */
#define IP_PROTO_OFFSET 9
#define IP6_PROTO_OFFSET 6
#define IKE_VERSION_OFFSET 17
#define IKE_LENGTH_OFFSET 24

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

typedef struct private_socket_raw_socket_t private_socket_raw_socket_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_raw_socket_t {

	/**
	 * public functions
	 */
	 socket_raw_socket_t public;

	/**
	 * regular port
	 */
	int port;

	/**
	 * port used for nat-t
	 */
	int natt_port;

	/**
	 * raw receiver socket for IPv4
	 */
	int recv4;

	/**
	 * raw receiver socket for IPv6
	 */
	int recv6;

	/**
	 * send socket on regular port for IPv4
	 */
	int send4;

	/**
	 * send socket on regular port for IPv6
	 */
	int send6;

	/**
	 * send socket on nat-t port for IPv4
	 */
	int send4_natt;

	/**
	 * send socket on nat-t port for IPv6
	 */
	int send6_natt;

	/**
	 * Maximum packet size to receive
	 */
	int max_packet;
};

METHOD(socket_t, receiver, status_t,
	private_socket_raw_socket_t *this, packet_t **packet)
{
	char buffer[this->max_packet];
	chunk_t data;
	packet_t *pkt;
	struct udphdr *udp;
	host_t *source = NULL, *dest = NULL;
	int bytes_read = 0, data_offset;
	bool oldstate;
	fd_set rfds;

	FD_ZERO(&rfds);

	if (this->recv4)
	{
		FD_SET(this->recv4, &rfds);
	}
	if (this->recv6)
	{
		FD_SET(this->recv6, &rfds);
	}

	DBG2(DBG_NET, "waiting for data on raw sockets");

	oldstate = thread_cancelability(TRUE);
	if (select(max(this->recv4, this->recv6) + 1, &rfds, NULL, NULL, NULL) <= 0)
	{
		thread_cancelability(oldstate);
		return FAILED;
	}
	thread_cancelability(oldstate);

	if (this->recv4 && FD_ISSET(this->recv4, &rfds))
	{
		/* IPv4 raw sockets return the IP header. We read src/dest
		 * information directly from the raw header */
		struct iphdr *ip;
		struct sockaddr_in src, dst;

		bytes_read = recv(this->recv4, buffer, this->max_packet, 0);
		if (bytes_read < 0)
		{
			DBG1(DBG_NET, "error reading from IPv4 socket: %s", strerror(errno));
			return FAILED;
		}
		if (bytes_read == this->max_packet)
		{
			DBG1(DBG_NET, "receive buffer too small, packet discarded");
			return FAILED;
		}
		DBG3(DBG_NET, "received IPv4 packet %b", buffer, bytes_read);

		/* read source/dest from raw IP/UDP header */
		if (bytes_read < IP_LEN + UDP_LEN + MARKER_LEN)
		{
			DBG1(DBG_NET, "received IPv4 packet too short (%d bytes)",
				 bytes_read);
			return FAILED;
		}
		ip = (struct iphdr*) buffer;
		udp = (struct udphdr*) (buffer + IP_LEN);
		src.sin_family = AF_INET;
		src.sin_addr.s_addr = ip->saddr;
		src.sin_port = udp->source;
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = ip->daddr;
		dst.sin_port = udp->dest;
		source = host_create_from_sockaddr((sockaddr_t*)&src);
		dest = host_create_from_sockaddr((sockaddr_t*)&dst);

		pkt = packet_create();
		pkt->set_source(pkt, source);
		pkt->set_destination(pkt, dest);
		DBG2(DBG_NET, "received packet: from %#H to %#H", source, dest);
		data_offset = IP_LEN + UDP_LEN;
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
	else if (this->recv6 && FD_ISSET(this->recv6, &rfds))
	{
		/* IPv6 raw sockets return no IP header. We must query
		 * src/dest via socket options/ancillary data */
		struct msghdr msg;
		struct cmsghdr *cmsgptr;
		struct sockaddr_in6 src, dst;
		struct iovec iov;
		char ancillary[64];

		msg.msg_name = &src;
		msg.msg_namelen = sizeof(src);
		iov.iov_base = buffer;
		iov.iov_len = this->max_packet;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ancillary;
		msg.msg_controllen = sizeof(ancillary);
		msg.msg_flags = 0;

		bytes_read = recvmsg(this->recv6, &msg, 0);
		if (bytes_read < 0)
		{
			DBG1(DBG_NET, "error reading from IPv6 socket: %s", strerror(errno));
			return FAILED;
		}
		DBG3(DBG_NET, "received IPv6 packet %b", buffer, bytes_read);

		if (bytes_read < IP_LEN + UDP_LEN + MARKER_LEN)
		{
			DBG3(DBG_NET, "received IPv6 packet too short (%d bytes)",
				 bytes_read);
			return FAILED;
		}

		/* read ancillary data to get destination address */
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
			 cmsgptr = CMSG_NXTHDR(&msg, cmsgptr))
		{
			if (cmsgptr->cmsg_len == 0)
			{
				DBG1(DBG_NET, "error reading IPv6 ancillary data");
				return FAILED;
			}

#ifdef HAVE_IN6_PKTINFO
			if (cmsgptr->cmsg_level == SOL_IPV6 &&
				cmsgptr->cmsg_type == IPV6_2292PKTINFO)
			{
				struct in6_pktinfo *pktinfo;
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsgptr);

				memset(&dst, 0, sizeof(dst));
				memcpy(&dst.sin6_addr, &pktinfo->ipi6_addr, sizeof(dst.sin6_addr));
				dst.sin6_family = AF_INET6;
				udp = (struct udphdr*) (buffer);
				dst.sin6_port = udp->dest;
				src.sin6_port = udp->source;
				dest = host_create_from_sockaddr((sockaddr_t*)&dst);
			}
#endif /* HAVE_IN6_PKTINFO */
		}
		/* ancillary data missing? */
		if (dest == NULL)
		{
			DBG1(DBG_NET, "error reading IPv6 packet header");
			return FAILED;
		}

		source = host_create_from_sockaddr((sockaddr_t*)&src);

		pkt = packet_create();
		pkt->set_source(pkt, source);
		pkt->set_destination(pkt, dest);
		DBG2(DBG_NET, "received packet: from %#H to %#H", source, dest);
		data_offset = UDP_LEN;
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
	private_socket_raw_socket_t *this, packet_t *packet)
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
			skt = this->send4;
		}
		else
		{
			skt = this->send6;
		}
	}
	else if (sport == IKEV2_NATT_PORT)
	{
		if (family == AF_INET)
		{
			skt = this->send4_natt;
		}
		else
		{
			skt = this->send6_natt;
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
			cmsg->cmsg_type = IPV6_2292PKTINFO;
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
 * open a socket to send packets
 */
static int open_send_socket(private_socket_raw_socket_t *this,
							int family, u_int16_t port)
{
	int on = TRUE;
	int type = UDP_ENCAP_ESPINUDP;
	struct sockaddr_storage addr;
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
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			htoun16(&sin6->sin6_port, port);
			break;
		}
		default:
			return 0;
	}

	skt = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0)
	{
		DBG1(DBG_NET, "could not open send socket: %s", strerror(errno));
		return 0;
	}

	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set SO_REUSEADDR on send socket: %s",
			 strerror(errno));
		close(skt);
		return 0;
	}

	/* bind the send socket */
	if (bind(skt, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_NET, "unable to bind send socket: %s",
			 strerror(errno));
		close(skt);
		return 0;
	}

	if (family == AF_INET)
	{
		/* enable UDP decapsulation globally, only for one socket needed */
		if (setsockopt(skt, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
		{
			DBG1(DBG_NET, "unable to set UDP_ENCAP: %s; NAT-T may fail",
				 strerror(errno));
		}
	}

	if (!hydra->kernel_interface->bypass_socket(hydra->kernel_interface,
												skt, family))
	{
		DBG1(DBG_NET, "installing bypass policy on send socket failed");
	}

	return skt;
}

/**
 * open a socket to receive packets
 */
static int open_recv_socket(private_socket_raw_socket_t *this, int family)
{
	int skt;
	int on = TRUE;
	u_int ip_len, sol, udp_header, ike_header;

	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
			ip_len = IP_LEN;
			sol = SOL_IP;
			break;
		case AF_INET6:
			ip_len = 0; /* IPv6 raw sockets contain no IP header */
			sol = SOL_IPV6;
			break;
		default:
			return 0;
	}
	udp_header = ip_len;
	ike_header = ip_len + UDP_LEN;

	/* This filter code filters out all non-IKEv2 traffic on
	 * a SOCK_RAW IP_PROTP_UDP socket. Handling of other
	 * IKE versions is done in pluto.
	 */
	struct sock_filter ikev2_filter_code[] =
	{
		/* Destination Port must be either port or natt_port */
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, udp_header + 2),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IKEV2_UDP_PORT, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IKEV2_NATT_PORT, 6, 14),
		/* port */
			/* IKE version must be 2.x */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ike_header + IKE_VERSION_OFFSET),
			BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 4),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 2, 0, 11),
			/* packet length is length in IKEv2 header + ip header + udp header */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ike_header + IKE_LENGTH_OFFSET),
			BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, ip_len + UDP_LEN),
			BPF_STMT(BPF_RET+BPF_A, 0),
		/* natt_port */
			/* nat-t: check for marker */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ike_header),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 6),
			/* nat-t: IKE version must be 2.x */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ike_header + MARKER_LEN + IKE_VERSION_OFFSET),
			BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 4),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 2, 0, 3),
			/* nat-t: packet length is length in IKEv2 header + ip header + udp header + non esp marker */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ike_header + MARKER_LEN + IKE_LENGTH_OFFSET),
			BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, ip_len + UDP_LEN + MARKER_LEN),
			BPF_STMT(BPF_RET+BPF_A, 0),
		/* packet doesn't match, ignore */
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

	/* Filter struct to use with setsockopt */
	struct sock_fprog ikev2_filter = {
		sizeof(ikev2_filter_code) / sizeof(struct sock_filter),
		ikev2_filter_code
	};

	/* set up a raw socket */
	skt = socket(family, SOCK_RAW, IPPROTO_UDP);
	if (skt < 0)
	{
		DBG1(DBG_NET, "unable to create raw socket: %s", strerror(errno));
		return 0;
	}

	if (setsockopt(skt, SOL_SOCKET, SO_ATTACH_FILTER,
				   &ikev2_filter, sizeof(ikev2_filter)) < 0)
	{
		DBG1(DBG_NET, "unable to attach IKEv2 filter to raw socket: %s",
			 strerror(errno));
		close(skt);
		return 0;
	}

	if (family == AF_INET6 &&
		/* we use IPV6_2292PKTINFO, as IPV6_PKTINFO is defined as
		 * 2 or 50 depending on kernel header version */
		setsockopt(skt, sol, IPV6_2292PKTINFO, &on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set IPV6_PKTINFO on raw socket: %s",
			 strerror(errno));
		close(skt);
		return 0;
	}

	if (!hydra->kernel_interface->bypass_socket(hydra->kernel_interface,
												skt, family))
	{
		DBG1(DBG_NET, "installing bypass policy on receive socket failed");
	}

	return skt;
}

METHOD(socket_t, destroy, void,
	private_socket_raw_socket_t *this)
{
	if (this->recv4)
	{
		close(this->recv4);
	}
	if (this->recv6)
	{
		close(this->recv6);
	}
	if (this->send4)
	{
		close(this->send4);
	}
	if (this->send6)
	{
		close(this->send6);
	}
	if (this->send4_natt)
	{
		close(this->send4_natt);
	}
	if (this->send6_natt)
	{
		close(this->send6_natt);
	}
	free(this);
}

/*
 * See header for description
 */
socket_raw_socket_t *socket_raw_socket_create()
{
	private_socket_raw_socket_t *this;

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

	this->recv4 = open_recv_socket(this, AF_INET);
	if (this->recv4 == 0)
	{
		DBG1(DBG_NET, "could not open IPv4 receive socket, IPv4 disabled");
	}
	else
	{
		this->send4 = open_send_socket(this, AF_INET, IKEV2_UDP_PORT);
		if (this->send4 == 0)
		{
			DBG1(DBG_NET, "could not open IPv4 send socket, IPv4 disabled");
			close(this->recv4);
		}
		else
		{
			this->send4_natt = open_send_socket(this, AF_INET, IKEV2_NATT_PORT);
			if (this->send4_natt == 0)
			{
				DBG1(DBG_NET, "could not open IPv4 NAT-T send socket");
			}
		}
	}

	this->recv6 = open_recv_socket(this, AF_INET6);
	if (this->recv6 == 0)
	{
		DBG1(DBG_NET, "could not open IPv6 receive socket, IPv6 disabled");
	}
	else
	{
		this->send6 = open_send_socket(this, AF_INET6, IKEV2_UDP_PORT);
		if (this->send6 == 0)
		{
			DBG1(DBG_NET, "could not open IPv6 send socket, IPv6 disabled");
			close(this->recv6);
		}
		else
		{
			this->send6_natt = open_send_socket(this, AF_INET6, IKEV2_NATT_PORT);
			if (this->send6_natt == 0)
			{
				DBG1(DBG_NET, "could not open IPv6 NAT-T send socket");
			}
		}
	}

	if (!(this->send4 || this->send6) || !(this->recv4 || this->recv6))
	{
		DBG1(DBG_NET, "could not create any sockets");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
