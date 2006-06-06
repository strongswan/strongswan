/**
 * @file socket.c
 *
 * @brief Implementation of socket_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 1997 Angelos D. Keromytis.
 *
 * Some parts of interface lookup code from pluto.
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/filter.h>

#include "socket.h"

#include <daemon.h>
#include <utils/logger_manager.h>


#define IP_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8


/**
 * This filter code filters out all non-IKEv2 traffic on 
 * a SOCK_RAW IP_PROTP_UDP socket. Handling of other
 * IKE versions is done in pluto.
 */
struct sock_filter ikev2_filter_code[] = 
{
	/* Protocol must be UDP */
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 9),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 0, 7),
	/* Destination Port must be 500 */
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 22),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 500, 0, 5),
	/* IKE version must be 2.0 */
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 45),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x20, 0, 3),
	/* packet length is length in IKEv2 header + ip header + udp header */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 52),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, IP_HEADER_LENGTH + UDP_HEADER_LENGTH),
	BPF_STMT(BPF_RET+BPF_A, 0),
	/* packet doesn't match IKEv2, ignore */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

/**
 * Filter struct to use with setsockopt
 */
struct sock_fprog ikev2_filter = {
	sizeof(ikev2_filter_code) / sizeof(struct sock_filter),
	ikev2_filter_code
};


typedef struct interface_t interface_t;

/**
 * An interface on which we listen.
 */
struct interface_t {
	
	/**
	 * Name of the interface
	 */
	char name[IFNAMSIZ];
	
	/**
	 * Associated socket
	 */
	int socket_fd;
	
	/**
	 * Host with listening address
	 */
	host_t *address;
};

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
	  * Master socket
	  */
	 int master_fd;
	 
	 /**
	  * List of all socket to listen
	  */
	 linked_list_t* interfaces;
	 
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
	host_t *source, *dest;
	int bytes_read = 0;
	
	
	while (bytes_read >= 0)
	{
		int max_fd = 1;
		fd_set readfds;
		iterator_t *iterator;
		int oldstate;
		interface_t *interface;
		
		/* build fd_set */
		FD_ZERO(&readfds);
		iterator = this->interfaces->create_iterator(this->interfaces, TRUE);
		while (iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&interface);
			FD_SET(interface->socket_fd, &readfds);
			if (interface->socket_fd > max_fd)
			{
				max_fd = interface->socket_fd + 1;
			}
		}
		iterator->destroy(iterator);
		
		this->logger->log(this->logger, CONTROL|LEVEL1, "waiting on sockets");
		
		/* allow cancellation while select()-ing */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		bytes_read = select(max_fd, &readfds, NULL, NULL, NULL);
		pthread_setcancelstate(oldstate, NULL);
		
		/* read on the first nonblocking socket */
		bytes_read = 0;
		iterator = this->interfaces->create_iterator(this->interfaces, TRUE);
		while (iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&interface);
			if (FD_ISSET(interface->socket_fd, &readfds))
			{
				/* do the read */
				bytes_read = recv(interface->socket_fd, buffer, MAX_PACKET, 0);
				break;
			}
		}
		iterator->destroy(iterator);
		
		if (bytes_read  < 0)
		{
			this->logger->log(this->logger, ERROR, "error reading from socket: %s", strerror(errno));
			continue;
		}
		if (bytes_read > IP_HEADER_LENGTH + UDP_HEADER_LENGTH)
		{
			/* read source/dest from raw IP/UDP header */
			chunk_t source_chunk = {buffer + 12, 4};
			chunk_t dest_chunk = {buffer + 16, 4};
			u_int16_t source_port = ntohs(*(u_int16_t*)(buffer + 20));
			u_int16_t dest_port = ntohs(*(u_int16_t*)(buffer + 22));
			source = host_create_from_chunk(AF_INET, source_chunk, source_port);
			dest = host_create_from_chunk(AF_INET, dest_chunk, dest_port);
			pkt = packet_create();
			pkt->set_source(pkt, source);
			pkt->set_destination(pkt, dest);
			break;
		}
		this->logger->log(this->logger, ERROR|LEVEL1, "too short packet received");
	}
	
	this->logger->log(this->logger, CONTROL, "received packet: from %s:%d to %s:%d",
					  source->get_address(source), source->get_port(source),
					  dest->get_address(dest), dest->get_port(dest));

	/* fill in packet */
	data.len = bytes_read - IP_HEADER_LENGTH - UDP_HEADER_LENGTH;
	data.ptr = malloc(data.len);
	memcpy(data.ptr, buffer + IP_HEADER_LENGTH + UDP_HEADER_LENGTH, data.len);
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
	ssize_t bytes_sent;
	chunk_t data;
	host_t *src, *dst;
	
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	data = packet->get_data(packet);

	this->logger->log(this->logger, CONTROL, "sending packet: from %s:%d to %s:%d",
					  src->get_address(src), src->get_port(src),
					  dst->get_address(dst), dst->get_port(dst));
	
	/* send data */
	/* TODO: should we send via the interface we received the packet? */
	bytes_sent = sendto(this->master_fd, data.ptr, data.len, 0, 
						dst->get_sockaddr(dst), *(dst->get_sockaddr_len(dst)));

	if (bytes_sent != data.len)
	{
		this->logger->log(this->logger, ERROR, "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Find all suitable interfaces, bind them and add them to the list
 */
static status_t build_interface_list(private_socket_t *this, u_int16_t port)
{
	int on = TRUE;
	int i;
	struct sockaddr_in addr;
	struct ifconf ifconf;
	struct ifreq buf[300];
	
	/* master socket for querying socket for a specific interfaces */
	this->master_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (this->master_fd == -1)
	{
		this->logger->log(this->logger, ERROR, "could not open IPv4 master socket!");
		return FAILED;
	}
	
	/* allow binding of multiplo sockets */
	if (setsockopt(this->master_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to set SO_REUSEADDR on master socket!");
		return FAILED;
	}
	
	/* bind the master socket */
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(this->master_fd,(struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "unable to bind master socket: %s!", strerror(errno));
		return FAILED;
	}

	/* get all interfaces */
	ifconf.ifc_len = sizeof(buf);
	ifconf.ifc_buf = (void*) buf;
	memset(buf, 0, sizeof(buf));
	if (ioctl(this->master_fd, SIOCGIFCONF, &ifconf) == -1)
	{
		this->logger->log(this->logger, ERROR, "unable to get interfaces!");
		return FAILED;
	}

	/* add every interesting interfaces to our interface list */
	for (i = 0; (i+1) * sizeof(*buf) <= (size_t)ifconf.ifc_len; i++)
	{
		struct sockaddr_in *current = (struct sockaddr_in*) &buf[i].ifr_addr;
		struct ifreq auxinfo;
		int skt;
		interface_t *interface;

		if (current->sin_family != AF_INET && current->sin_family != AF_INET6)
		{
			/* ignore all but IPv4 and IPv6 interfaces */
			continue;
		}

		/* get auxilary info about socket */
		memset(&auxinfo, 0, sizeof(auxinfo));
		memcpy(auxinfo.ifr_name, buf[i].ifr_name, IFNAMSIZ);
		if (ioctl(this->master_fd, SIOCGIFFLAGS, &auxinfo) == -1)
		{
			this->logger->log(this->logger, ERROR, "unable to SIOCGIFFLAGS master socket!");
			continue;
		}
		if (!(auxinfo.ifr_flags & IFF_UP))
		{
			/* ignore an interface that isn't up */
			continue;
		}
		if (current->sin_addr.s_addr == 0)
		{
			/* ignore unconfigured interfaces */
			continue;
		}
		
		/* set up interface socket */
		skt = socket(current->sin_family, SOCK_RAW, IPPROTO_UDP);
		if (socket < 0)
		{
			this->logger->log(this->logger, ERROR, "unable to open interface socket!");
			continue;
		}
		if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
		{
			this->logger->log(this->logger, ERROR, "unable to set SO_REUSEADDR on interface socket!");
			close(skt);
			continue;
		}
		current->sin_port = htons(port);

		if (bind(skt, (struct sockaddr*)current, sizeof(struct sockaddr_in)) < 0)
		{
			this->logger->log(this->logger, ERROR, "unable to bind interface socket!");
			close(skt);
			continue;
		}
			
		if (setsockopt(skt, SOL_SOCKET, SO_ATTACH_FILTER, &ikev2_filter, sizeof(ikev2_filter)) < 0)
		{
			this->logger->log(this->logger, ERROR, "unable to attack IKEv2 filter to interface socket!");
			close(skt);
			continue;
		}
		
		/* add socket with interface name to list */
		interface = malloc_thing(interface_t);
 		strncpy(interface->name, buf[i].ifr_name, IFNAMSIZ);
		interface->socket_fd = skt;
		interface->address = host_create_from_sockaddr((struct sockaddr*)current);
		this->logger->log(this->logger, CONTROL, "listening on %s (%s)",
						  interface->name, interface->address->get_address(interface->address));
		this->interfaces->insert_last(this->interfaces, (void*)interface);
	}
	
	if (this->interfaces->get_count(this->interfaces) == 0)
	{
		this->logger->log(this->logger, ERROR, "unable to find any usable interface!");
		return FAILED;
	}
	return SUCCESS;
}

/**
 * implementation of socket_t.is_listening_on
 */
static bool is_listening_on(private_socket_t *this, host_t *host)
{
	iterator_t *iterator;
	
	/* listening on wildcard 0.0.0.0 is always FALSE */
	if (host->is_anyaddr(host))
		return FALSE;
	
	/* compare host with all interfaces */
	iterator = this->interfaces->create_iterator(this->interfaces, TRUE);
	while (iterator->has_next(iterator))
	{
		interface_t *interface;
		iterator->current(iterator, (void**)&interface);
		if (host->equals(host, interface->address))
		{
			iterator->destroy(iterator);
			return TRUE;
		}
	}
	iterator->destroy(iterator);
	return FALSE;
}

/**
 * implementation of socket_t.destroy
 */
static void destroy(private_socket_t *this)
{
	interface_t *interface;
	while (this->interfaces->remove_last(this->interfaces, (void**)&interface) == SUCCESS)
	{
		interface->address->destroy(interface->address);
		close(interface->socket_fd);
		free(interface);
	}
	this->interfaces->destroy(this->interfaces);
	close(this->master_fd);
	free(this);
}

/*
 * See header for description
 */
socket_t *socket_create(u_int16_t port)
{
	private_socket_t *this = malloc_thing(private_socket_t);

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.is_listening_on = (bool (*)(socket_t*,host_t*))is_listening_on;
	this->public.destroy = (void(*)(socket_t*)) destroy;
	
	this->logger = logger_manager->get_logger(logger_manager, SOCKET);
	this->interfaces = linked_list_create();
	
	if (build_interface_list(this, port) != SUCCESS)
	{
		this->interfaces->destroy(this->interfaces);
		free(this);
		charon->kill(charon, "could not bind any interface!");
	}

	return (socket_t*)this;
}
