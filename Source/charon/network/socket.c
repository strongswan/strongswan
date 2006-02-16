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

#include "socket.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>


typedef struct interface_t interface_t;

/**
 * An interface on which we listen.
 */
struct interface_t {
	
	/**
	 * Name of the interface
	 */
	char name[IFNAMSIZ+1];
	
	/**
	 * Associated socket
	 */
	int socket_fd;
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
status_t receiver(private_socket_t *this, packet_t **packet)
{
	char buffer[MAX_PACKET];
	chunk_t data;
	packet_t *pkt = packet_create();
	host_t *source, *dest;
	int bytes_read = 0;
	
	source = host_create(AF_INET, "0.0.0.0", 0);
	dest = host_create(AF_INET, "0.0.0.0", 0);
	pkt->set_source(pkt, source);
	pkt->set_destination(pkt, dest);
	
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
	
		/* add packet destroy handler for cancellation, enable cancellation */
		pthread_cleanup_push((void(*)(void*))pkt->destroy, (void*)pkt);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		
		this->logger->log(this->logger, CONTROL|LEVEL1, "waiting on sockets");
		bytes_read = select(max_fd, &readfds, NULL, NULL, NULL);
		
		/* reset cancellation, remove packet destroy handler (without executing) */
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
		
		if (bytes_read  < 0)
		{
			this->logger->log(this->logger, ERROR, "error reading from socket: %s", strerror(errno));
			continue;
		}
	
		/* read on the first nonblocking socket */
		bytes_read = 0;
		iterator = this->interfaces->create_iterator(this->interfaces, TRUE);
		while (iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&interface);
			if (FD_ISSET(interface->socket_fd, &readfds))
			{
				/* do the read */
				bytes_read = recvfrom(interface->socket_fd, buffer, MAX_PACKET, 0,
									source->get_sockaddr(source), 
									source->get_sockaddr_len(source));
				getsockname(interface->socket_fd, dest->get_sockaddr(dest), dest->get_sockaddr_len(dest));
				break;
			}
		}
		iterator->destroy(iterator);
		if (bytes_read > 0)
		{
			break;
		}
	}
	
	this->logger->log(this->logger, CONTROL, "received packet from %s:%d",
						source->get_address(source), 
						source->get_port(source));

	/* fill in packet */
	data.len = bytes_read;
	data.ptr = allocator_alloc(data.len);
	memcpy(data.ptr, buffer, data.len);
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
	host_t *source, *dest;
	
	source = packet->get_source(packet);
	dest = packet->get_destination(packet);
	data = packet->get_data(packet);

	this->logger->log(this->logger, CONTROL, "sending packet to %s:%d",
						dest->get_address(dest),
						dest->get_port(dest));
	
	/* send data */
	/* TODO: should we send via the interface we received the packet? */
	bytes_sent = sendto(this->master_fd, data.ptr, data.len, 0, 
						dest->get_sockaddr(dest), *(dest->get_sockaddr_len(dest)));

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
		this->logger->log(this->logger, ERROR, "unable to bind master socket!");
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

		if (current->sin_family != AF_INET)
		{
			/* ignore all but AF_INET interfaces */
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
		skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
		current->sin_family = AF_INET;
		if (bind(skt, (struct sockaddr*)current, sizeof(struct sockaddr_in)) < 0)
		{
			this->logger->log(this->logger, ERROR, "unable to bind interface socket!");
			close(skt);
			continue;
		}
		
		/* add socket with interface name to list */
		interface = allocator_alloc_thing(interface_t);
 		memcpy(interface->name, buf[i].ifr_name, IFNAMSIZ);
 		interface->name[IFNAMSIZ] = '\0';
		interface->socket_fd = skt;
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
 * implementation of socket_t.destroy
 */
void destroy(private_socket_t *this)
{
	interface_t *interface;
	while (this->interfaces->remove_last(this->interfaces, (void**)&interface) == SUCCESS)
	{
		close(interface->socket_fd);
		allocator_free(interface);
	}
	this->interfaces->destroy(this->interfaces);
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
	close(this->master_fd);
	allocator_free(this);
}

/*
 * See header for description
 */
socket_t *socket_create(u_int16_t port)
{
	private_socket_t *this = allocator_alloc_thing(private_socket_t);

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.destroy = (void(*)(socket_t*)) destroy;
	
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, SOCKET, NULL);
	this->interfaces = linked_list_create();
	
	if (build_interface_list(this, port) != SUCCESS)
	{
		charon->kill(charon, "could not bind any interface!");
	}

	return (socket_t*)this;
}
