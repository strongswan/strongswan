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
#include <netinet/udp.h>
#include <linux/ipsec.h>
#include <linux/filter.h>

#include "socket.h"

#include <daemon.h>
#include <utils/logger_manager.h>

/* constants for packet handling */
#define IP_LEN sizeof(struct iphdr)
#define UDP_LEN sizeof(struct udphdr)
#define MARKER_LEN sizeof(u_int32_t)
 
/* offsets for packet handling */
#define IP 0
#define UDP IP + IP_LEN
#define IKE UDP + UDP_LEN

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
	  * raw socket (receiver)
	  */
	 int raw_fd;

	 /**
	  * send socket on regular port
	  */
	 int send_fd;

	 /**
	  * send socket on nat-t port
	  */
	 int natt_fd;
	 
	 /** 
	  * logger for this socket
	  */
	 logger_t *logger;

	 /**
	  * Setup a send socket
	  *
	  * @param this		calling object
	  * @param port		the port
	  * @param send_fd	returns the file descriptor of this new socket
	  */
	 status_t (*setup_send_socket) (private_socket_t *this, u_int16_t port, int *send_fd);

	 /**
	  * Initialize
	  *
	  * @param this 	calling object
	  */
	 status_t (*initialize) (private_socket_t *this);
};

/**
 * implementation of socket_t.receive
 */
static status_t receiver(private_socket_t *this, packet_t **packet)
{
	char buffer[MAX_PACKET];
	chunk_t data;
	packet_t *pkt;
	struct iphdr *ip;
	struct udphdr *udp;
	host_t *source, *dest;
	int bytes_read = 0;
	int data_offset, oldstate;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "receive from raw socket");
	/* allow cancellation while blocking on recv() */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	bytes_read = recv(this->raw_fd, buffer, MAX_PACKET, 0);
	pthread_setcancelstate(oldstate, NULL);

	if (bytes_read < 0)
	{
		this->logger->log(this->logger, ERROR, "error reading from socket: %s", strerror(errno));
		return FAILED;
	}

	/* read source/dest from raw IP/UDP header */
	ip = (struct iphdr*) buffer;
	udp = (struct udphdr*) (buffer + IP_LEN);
	
	source = host_create_from_hdr(ip->saddr, udp->source);
	dest = host_create_from_hdr(ip->daddr, udp->dest);

	pkt = packet_create();
	pkt->set_source(pkt, source);
	pkt->set_destination(pkt, dest);

	this->logger->log(this->logger, CONTROL|LEVEL1, "received packet: from %s:%d to %s:%d",
					  source->get_address(source), source->get_port(source),
					  dest->get_address(dest), dest->get_port(dest));

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

	/* return packet */
	*packet = pkt;

	return SUCCESS;
}

/**
 * implementation of socket_t.send
 */
status_t sender(private_socket_t *this, packet_t *packet)
{
	int sport, fd;
	ssize_t bytes_sent;
	chunk_t data, marked;
	host_t *src, *dst;
	
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	data = packet->get_data(packet);

	this->logger->log(this->logger, CONTROL|LEVEL1, "sending packet: from %s:%d to %s:%d",
					  src->get_address(src), src->get_port(src),
					  dst->get_address(dst), dst->get_port(dst));
	
	/* send data */
	sport = src->get_port(src);
	if (sport == this->port)
	{
		fd = this->send_fd;
	}
	else if (sport == this->natt_port)
	{
		fd = this->natt_fd;
		/* NAT keepalives without marker */
		if (data.len != 1 || data.ptr[0] != 0xFF)
		{
			/* add non esp marker to packet */
			if (data.len > MAX_PACKET - MARKER_LEN)
			{
				this->logger->log(this->logger, ERROR, "unable to send packet: it's too big");
				return FAILED;
			}
			marked = chunk_alloc(data.len + MARKER_LEN);
			memset(marked.ptr, 0, MARKER_LEN);
			memcpy(marked.ptr + MARKER_LEN, data.ptr, data.len);
			packet->set_data(packet, marked); /* let the packet do the clean up for us */
			data = marked;
		}
	}
	else
	{
		this->logger->log(this->logger, ERROR, "unable to locate a send socket for port: %d", sport);
		return FAILED;
	}
	
	bytes_sent = sendto(fd, data.ptr, data.len, 0,
						dst->get_sockaddr(dst), *(dst->get_sockaddr_len(dst)));

	if (bytes_sent != data.len)
	{
		this->logger->log(this->logger, ERROR, "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	
	return SUCCESS;
}

/**
 * setup a send socket on a specified port
 */
static status_t setup_send_socket(private_socket_t *this, u_int16_t port, int *send_fd) 
{
	int on = TRUE;
	struct sockaddr_in addr;
	struct sadb_x_policy policy;
	int fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		this->logger->log(this->logger, ERROR, "could not open IPv4 send socket!");
		return FAILED;
	}
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to set SO_REUSEADDR on send socket!");
		close(fd);
		return FAILED;
	}
	
	/* bypass outgoung IKE traffic on send socket */
	policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	policy.sadb_x_policy_reserved = 0;
	policy.sadb_x_policy_id = 0;
	/* TODO: use IPPROTO_IPV6/IPV6_IPSEC_POLICY for IPv6 sockets */
	if (setsockopt(fd, IPPROTO_IP, IP_IPSEC_POLICY, &policy, sizeof(policy)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to set IPSEC_POLICY on send socket!");
		close(fd);
		return FAILED;
	}
	
	/* bind the send socket */
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to bind send socket: %s!", strerror(errno));
		return FAILED;
	}

	*send_fd = fd;
	return SUCCESS;
}

/**
 * Initialize all sub sockets
 */
static status_t initialize(private_socket_t *this)
{
	struct sadb_x_policy policy;
	
	/* This filter code filters out all non-IKEv2 traffic on
	 * a SOCK_RAW IP_PROTP_UDP socket. Handling of other
	 * IKE versions is done in pluto.
	 */
	struct sock_filter ikev2_filter_code[] =
	{
		/* Protocol must be UDP */
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, IP + 9),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 0, 15),
		/* Destination Port must be either port or natt_port */
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, UDP + 2),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, this->port, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, this->natt_port, 5, 12),
		/* port */
			/* IKE version must be 2.0 */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, IKE + 17),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x20, 0, 10),
			/* packet length is length in IKEv2 header + ip header + udp header */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, IKE + 24),
			BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, IP_LEN + UDP_LEN),
			BPF_STMT(BPF_RET+BPF_A, 0),
		/* natt_port */
			/* nat-t: check for marker */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, IKE),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5),
			/* nat-t: IKE version must be 2.0 */
			BPF_STMT(BPF_LD+BPF_B+BPF_ABS, IKE + MARKER_LEN + 17),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x20, 0, 3),
			/* nat-t: packet length is length in IKEv2 header + ip header + udp header + non esp marker */
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, IKE + MARKER_LEN + 24),
			BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, IP_LEN + UDP_LEN + MARKER_LEN),
			BPF_STMT(BPF_RET+BPF_A, 0),
		/* packet doesn't match, ignore */
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

	/* Filter struct to use with setsockopt */
	struct sock_fprog ikev2_filter = {
		sizeof(ikev2_filter_code) / sizeof(struct sock_filter),
		ikev2_filter_code
	};

	/* set up raw socket */
	this->raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (this->raw_fd < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to create raw socket!");
		return FAILED;
	}
	
	if (setsockopt(this->raw_fd, SOL_SOCKET, SO_ATTACH_FILTER, &ikev2_filter, sizeof(ikev2_filter)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to attach IKEv2 filter to raw socket!");
		close(this->raw_fd);
		return FAILED;
	}
	
	/* bypass incomining IKE traffic on this socket */
	policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	policy.sadb_x_policy_reserved = 0;
	policy.sadb_x_policy_id = 0;
	/* TODO: use IPPROTO_IPV6/IPV6_IPSEC_POLICY for IPv6 sockets */
	if (setsockopt(this->raw_fd, IPPROTO_IP, IP_IPSEC_POLICY, &policy, sizeof(policy)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to set IPSEC_POLICY on raw socket!");
		close(this->raw_fd);
		return FAILED;
	}
	
	/* setup the send sockets */
	if (this->setup_send_socket(this, this->port, &this->send_fd) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "unable to setup send socket on port %d!", this->port);
		return FAILED;
	}

	if (this->setup_send_socket(this, this->natt_port, &this->natt_fd) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "unable to setup send socket on port %d!", this->natt_port);
		return FAILED;
	}
	else
	{
		int type = UDP_ENCAP_ESPINUDP;
		if (setsockopt(this->natt_fd, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
		{
			this->logger->log(this->logger, ERROR,
							  "unable to set UDP_ENCAP on natt send socket! NAT-T may fail! error: %s",
							  strerror(errno));
		}
	}

	return SUCCESS;
}

/**
 * implementation of socket_t.destroy
 */
static void destroy(private_socket_t *this)
{
	close(this->natt_fd);
	close(this->send_fd);
	close(this->raw_fd);
	free(this);
}

/*
 * See header for description
 */
socket_t *socket_create(u_int16_t port, u_int16_t natt_port)
{
	private_socket_t *this = malloc_thing(private_socket_t);

	/* private functions */
	this->initialize = (status_t(*)(private_socket_t*))initialize;
	this->setup_send_socket = (status_t(*)(private_socket_t*,u_int16_t, int*))setup_send_socket;

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.destroy = (void(*)(socket_t*)) destroy;

	this->logger = logger_manager->get_logger(logger_manager, SOCKET);
	
	this->port = port;
	this->natt_port = natt_port;
	
	if (this->initialize(this) != SUCCESS)
	{
		free(this);
		charon->kill(charon, "could not init socket!");
	}

	return (socket_t*)this;
}
