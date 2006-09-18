/**
 * @file socket.c
 *
 * @brief Implementation of socket_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
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
#include <linux/ipsec.h>
#include <linux/filter.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "socket.h"

#include <daemon.h>
#include <utils/logger_manager.h>

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

/* from linux/in.h */
#ifndef IP_IPSEC_POLICY
#define IP_IPSEC_POLICY 16
#endif /*IP_IPSEC_POLICY*/

/* from linux/udp.h */
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif /*UDP_ENCAP*/

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif /*UDP_ENCAP_ESPINUDP*/

typedef struct private_socket_t private_socket_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_t{
	/**
	 * public functions
	 */
	 socket_t public;

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
	  * logger for this socket
	  */
	 logger_t *logger;
};

/**
 * implementation of socket_t.receive
 */
static status_t receiver(private_socket_t *this, packet_t **packet)
{
	char buffer[MAX_PACKET];
	chunk_t data;
	packet_t *pkt;
	struct udphdr *udp;
	host_t *source = NULL, *dest = NULL;
	int bytes_read = 0;
	int data_offset, oldstate;
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
	
	this->logger->log(this->logger, CONTROL|LEVEL1,
					  "waiting for data on raw sockets");
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	if (select(max(this->recv4, this->recv6) + 1, &rfds, NULL, NULL, NULL) <= 0)
	{
		pthread_setcancelstate(oldstate, NULL);
		return FAILED;
	}
	pthread_setcancelstate(oldstate, NULL);
	
	if (this->recv4 && FD_ISSET(this->recv4, &rfds))
	{
		/* IPv4 raw sockets return the IP header. We read src/dest
		 * information directly from the raw header */
		struct iphdr *ip;
		struct sockaddr_in src, dst;
		
		bytes_read = recv(this->recv4, buffer, MAX_PACKET, 0);
		if (bytes_read < 0)
		{
			this->logger->log(this->logger, ERROR,
							  "error reading from IPv4 socket: %s", 
							  strerror(errno));
			return FAILED;
		}
		this->logger->log_bytes(this->logger, RAW,
								"received IPv4 packet", buffer, bytes_read);
		
		/* read source/dest from raw IP/UDP header */
		if (bytes_read < IP_LEN + UDP_LEN + MARKER_LEN)
		{
			this->logger->log(this->logger, ERROR,
							  "received IPv4 packet too short");
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
		this->logger->log(this->logger, CONTROL|LEVEL1, 
						  "received packet: from %s[%d] to %s[%d]",
						  source->get_string(source), source->get_port(source),
						  dest->get_string(dest), dest->get_port(dest));
		data_offset = IP_LEN + UDP_LEN;
		/* remove non esp marker */	
		if (dest->get_port(dest) == this->natt_port)
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
		iov.iov_len = sizeof(buffer);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ancillary;
		msg.msg_controllen = sizeof(ancillary);
		msg.msg_flags = 0;
		
		bytes_read = recvmsg(this->recv6, &msg, 0);
		if (bytes_read < 0)
		{
			this->logger->log(this->logger, ERROR, 
							  "error reading from IPv6 socket: %s", 
							  strerror(errno));
			return FAILED;
		}
		this->logger->log_bytes(this->logger, RAW,
								"received IPv6 packet", buffer, bytes_read);
		
		if (bytes_read < IP_LEN + UDP_LEN + MARKER_LEN)
		{
			this->logger->log(this->logger, ERROR,
							  "received IPv6 packet too short");
			return FAILED;
		}
		
		/* read ancillary data to get destination address */
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
			 cmsgptr = CMSG_NXTHDR(&msg, cmsgptr))
		{
			if (cmsgptr->cmsg_len == 0) 
			{
				this->logger->log(this->logger, ERROR, 
								  "error reading IPv6 ancillary data: %s", 
								  strerror(errno));
				return FAILED;
			}	
			if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
				cmsgptr->cmsg_type == IPV6_PKTINFO)
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
		}
		/* ancillary data missing? */
		if (dest == NULL)
		{
			this->logger->log(this->logger, ERROR, 
							  "error reading IPv6 packet header");
			return FAILED;
		}
		
		source = host_create_from_sockaddr((sockaddr_t*)&src);
		
		pkt = packet_create();
		pkt->set_source(pkt, source);
		pkt->set_destination(pkt, dest);
		this->logger->log(this->logger, CONTROL|LEVEL1, 
						  "received packet: from %s[%d] to %s[%d]",
						  source->get_string(source), source->get_port(source),
						  dest->get_string(dest), dest->get_port(dest));
		data_offset = UDP_LEN;
		/* remove non esp marker */	
		if (dest->get_port(dest) == this->natt_port)
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
	
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	data = packet->get_data(packet);

	this->logger->log(this->logger, CONTROL|LEVEL1, "sending packet: from %s[%d] to %s[%d]",
					  src->get_string(src), src->get_port(src),
					  dst->get_string(dst), dst->get_port(dst));
	
	/* send data */
	sport = src->get_port(src);
	family = dst->get_family(dst);
	if (sport == this->port)
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
	else if (sport == this->natt_port)
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
			if (data.len > MAX_PACKET - MARKER_LEN)
			{
				this->logger->log(this->logger, ERROR, 
								  "unable to send packet: it's too big");
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
		this->logger->log(this->logger, ERROR,
						  "unable to locate a send socket for port %d", sport);
		return FAILED;
	}
	
	bytes_sent = sendto(skt, data.ptr, data.len, 0,
						dst->get_sockaddr(dst), *(dst->get_sockaddr_len(dst)));

	if (bytes_sent != data.len)
	{
		this->logger->log(this->logger, ERROR, 
						  "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

/**
 * implements socket_t.is_local_address
 */
static bool is_local_address(private_socket_t *this, host_t *host, char **dev)
{
	struct ifaddrs *list;
	struct ifaddrs *cur;
	bool found = FALSE;
	
	if (getifaddrs(&list) < 0)
	{
		return FALSE;
	}
	
	for (cur = list; cur != NULL; cur = cur->ifa_next)
	{
		if (!(cur->ifa_flags & IFF_UP))
		{
			/* ignore interface which are down */
			continue;
		}
		
		if (cur->ifa_addr == NULL ||
			cur->ifa_addr->sa_family != host->get_family(host))
		{
			/* no match in family */
			continue;
		}
		
		switch (cur->ifa_addr->sa_family)
		{
			case AF_INET:
			{
				struct sockaddr_in *listed, *requested;
				listed = (struct sockaddr_in*)cur->ifa_addr;
				requested = (struct sockaddr_in*)host->get_sockaddr(host);
				if (listed->sin_addr.s_addr == requested->sin_addr.s_addr)
				{
					found = TRUE;
				}
				break;
			}
			case AF_INET6:
			{
				struct sockaddr_in6 *listed, *requested;
				listed = (struct sockaddr_in6*)cur->ifa_addr;
				requested = (struct sockaddr_in6*)host->get_sockaddr(host);
				if (memcmp(&listed->sin6_addr, &requested->sin6_addr,
						   sizeof(listed->sin6_addr)) == 0)
				{
					found = TRUE;
				}
				break;
			}
			default:
				break;
		}
		
		if (found)
		{
			if (dev && cur->ifa_name)
			{
				/* return interface name, if requested */
				*dev = strdup(cur->ifa_name);
			}
			break;
		}
	}
	freeifaddrs(list);
	return found;
}


/**
 * implements socket_t.create_local_address_list
 */
static linked_list_t* create_local_address_list(private_socket_t *this)
{
	struct ifaddrs *list;
	struct ifaddrs *cur;
	host_t *host;
	linked_list_t *result = linked_list_create();
	
	if (getifaddrs(&list) < 0)
	{
		return result;
	}
	
	for (cur = list; cur != NULL; cur = cur->ifa_next)
	{
		if (!(cur->ifa_flags & IFF_UP))
		{
			/* ignore interface which are down */
			continue;
		}
		
		host = host_create_from_sockaddr(cur->ifa_addr);
		if (host)
		{
			/* we use always the IKEv2 port. This is relevant for
			 * natd payload hashing. */
			host->set_port(host, this->port);
			result->insert_last(result, host);
		}
	}
	freeifaddrs(list);
	return result;
}

/**
 * open a socket to send packets
 */
static int open_send_socket(private_socket_t *this, int family, u_int16_t port)
{
	int on = TRUE;
	int type = UDP_ENCAP_ESPINUDP;
	struct sockaddr_storage addr;
	u_int ip_proto, ipsec_policy;
	struct sadb_x_policy policy;
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
			ip_proto = IPPROTO_IP;
			ipsec_policy = IP_IPSEC_POLICY;
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			sin6->sin6_port = htons(port);
			ip_proto = IPPROTO_IPV6;
			ipsec_policy = IPV6_IPSEC_POLICY;
			break;
		}
		default:
			return 0;
	}
	
	skt = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0)
	{
		this->logger->log(this->logger, ERROR, "could not open send socket: %s",
						  strerror(errno));
		return 0;
	}
	
	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "unable to set SO_REUSEADDR on send socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	/* bypass outgoung IKE traffic on send socket */
	policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	policy.sadb_x_policy_reserved = 0;
	policy.sadb_x_policy_id = 0;
	
	if (setsockopt(skt, ip_proto, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "unable to set IPSEC_POLICY on send socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	/* We don't receive packets on the send socket, but we need a INBOUND policy.
	 * Otherwise, UDP decapsulation does not work!!! */
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(skt, ip_proto, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		this->logger->log(this->logger, ERROR,
						  "unable to set IPSEC_POLICY on send socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	/* bind the send socket */
	if (bind(skt, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to bind send socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	if (family == AF_INET)
	{
		/* enable UDP decapsulation globally, only for one socket needed */
		if (setsockopt(skt, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
		{
			this->logger->log(this->logger, ERROR,
							"unable to set UDP_ENCAP: %s; NAT-T may fail",
							strerror(errno));
		}
	}
	
	return skt;
}

/**
 * open a socket to receive packets
 */
static int open_recv_socket(private_socket_t *this, int family)
{
	int skt;
	int on = TRUE;
	u_int proto_offset, ip_len, ip_proto, ipsec_policy, ip_pktinfo, udp_header, ike_header;
	struct sadb_x_policy policy;
	
	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
			proto_offset = IP_PROTO_OFFSET;
			ip_len = IP_LEN;
			ip_proto = IPPROTO_IP;
			ip_pktinfo = IP_PKTINFO;
			ipsec_policy = IP_IPSEC_POLICY;
			break;
		case AF_INET6:
			proto_offset = IP6_PROTO_OFFSET;
			ip_len = 0; /* IPv6 raw sockets contain no IP header */
			ip_proto = IPPROTO_IPV6;
			ip_pktinfo = IPV6_PKTINFO;
			ipsec_policy = IPV6_IPSEC_POLICY;
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
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, this->port, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, this->natt_port, 5, 12),
		/* port */
			/* IKE version must be 2.0 */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ike_header + IKE_VERSION_OFFSET),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x20, 0, 10),
			/* packet length is length in IKEv2 header + ip header + udp header */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ike_header + IKE_LENGTH_OFFSET),
			BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, ip_len + UDP_LEN),
			BPF_STMT(BPF_RET+BPF_A, 0),
		/* natt_port */
			/* nat-t: check for marker */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ike_header),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5),
			/* nat-t: IKE version must be 2.0 */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ike_header + MARKER_LEN + IKE_VERSION_OFFSET),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x20, 0, 3),
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
		this->logger->log(this->logger, ERROR,
						  "unable to create raw socket: %s",
						  strerror(errno));
		return 0;
	}
	
	if (setsockopt(skt, SOL_SOCKET, SO_ATTACH_FILTER,
				   &ikev2_filter, sizeof(ikev2_filter)) < 0)
	{
		this->logger->log(this->logger, ERROR, 
						"unable to attach IKEv2 filter to raw socket: %s",
						strerror(errno));
		close(skt);
		return 0;
	}
	
	if (family == AF_INET6 &&
		setsockopt(skt, ip_proto, ip_pktinfo, &on, sizeof(on)) < 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "unable to set IPV6_PKTINFO on raw socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	/* bypass incomining IKE traffic on this socket */
	policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	policy.sadb_x_policy_reserved = 0;
	policy.sadb_x_policy_id = 0;
	
	if (setsockopt(skt, ip_proto, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "unable to set IPSEC_POLICY on raw socket: %s",
						  strerror(errno));
		close(skt);
		return 0;
	}
	
	return skt;
}

/**
 * implementation of socket_t.destroy
 */
static void destroy(private_socket_t *this)
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
socket_t *socket_create(u_int16_t port, u_int16_t natt_port)
{
	private_socket_t *this = malloc_thing(private_socket_t);

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.is_local_address = (bool(*)(socket_t*, host_t*,char**))is_local_address;
	this->public.create_local_address_list = (linked_list_t*(*)(socket_t*))create_local_address_list;
	this->public.destroy = (void(*)(socket_t*)) destroy;

	this->logger = logger_manager->get_logger(logger_manager, SOCKET);
	
	this->port = port;
	this->natt_port = natt_port;
	this->recv4 = 0;
	this->recv6 = 0;
	this->send4 = 0;
	this->send6 = 0;
	this->send4_natt = 0;
	this->send6_natt = 0;
	
	this->recv4 = open_recv_socket(this, AF_INET);
	if (this->recv4 == 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "could not open IPv4 receive socket, IPv4 disabled");
	}
	else
	{
		this->send4 = open_send_socket(this, AF_INET, this->port);
		if (this->send4 == 0)
		{
			this->logger->log(this->logger, ERROR, 
							  "could not open IPv4 send socket, IPv4 disabled");
			close(this->recv4);
		}
		else
		{
			this->send4_natt = open_send_socket(this, AF_INET, this->natt_port);
			if (this->send4_natt == 0)
			{
				this->logger->log(this->logger, ERROR, 
								  "could not open IPv4 NAT-T send socket");
			}
		}
	}
	
	this->recv6 = open_recv_socket(this, AF_INET6);
	if (this->recv6 == 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "could not open IPv6 receive socket, IPv6 disabled");
	}
	else
	{
		this->send6 = open_send_socket(this, AF_INET6, this->port);
		if (this->send6 == 0)
		{
			this->logger->log(this->logger, ERROR, 
							  "could not open IPv6 send socket, IPv6 disabled");
			close(this->recv6);
		}
		else
		{
			this->send6_natt = open_send_socket(this, AF_INET6, this->natt_port);
			if (this->send6_natt == 0)
			{
				this->logger->log(this->logger, ERROR, 
								  "could not open IPv6 NAT-T send socket");
			}
		}
	}
	
	if (!(this->send4 || this->send6) || !(this->recv4 || this->recv6))
	{
		this->logger->log(this->logger, ERROR,
						  "could not create any sockets");
		destroy(this);
		charon->kill(charon, "socket initialization failed");
	}
	
	return (socket_t*)this;
}
