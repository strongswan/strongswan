/**
 * @file socket.c
 *
 * @brief Implementation of socket_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "socket.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>


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
	  * currently we only have one socket, maybe more in the future ?
	  */
	 int socket_fd;
	 
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
	int oldstate;
	packet_t *pkt = packet_create();

	/* add packet destroy handler for cancellation, enable cancellation */
	pthread_cleanup_push((void(*)(void*))pkt->destroy, (void*)pkt);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	
	pkt->source = host_create(AF_INET, "0.0.0.0", 0);
	pkt->destination = host_create(AF_INET, "0.0.0.0", 0);


	this->logger->log(this->logger, CONTROL|MORE, "going to read from socket");
	/* do the read */
	pkt->data.len = recvfrom(this->socket_fd, buffer, MAX_PACKET, 0,
							pkt->source->get_sockaddr(pkt->source), 
							pkt->source->get_sockaddr_len(pkt->source));

	/* reset cancellation, remove packet destroy handler (without executing) */
	pthread_setcancelstate(oldstate, NULL);
	pthread_cleanup_pop(0);


	/* TODO: get senders destination address, using
	 * IP_PKTINFO and recvmsg */

	if (pkt->data.len < 0)
	{
		pkt->destroy(pkt);
		this->logger->log(this->logger, ERROR, "error reading from socket: %s", strerror(errno));
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL, "received packet from %s:%d",
						pkt->source->get_address(pkt->source), 
						pkt->source->get_port(pkt->source));

	/* fill in packet */
	pkt->data.ptr = allocator_alloc(pkt->data.len);
	memcpy(pkt->data.ptr, buffer, pkt->data.len);

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


	this->logger->log(this->logger, CONTROL, "sending packet to %s:%d",
						packet->destination->get_address(packet->destination), 
						packet->destination->get_port(packet->destination));
	/* send data */
	bytes_sent = sendto(this->socket_fd, packet->data.ptr, packet->data.len,
						0, packet->destination->get_sockaddr(packet->destination), 
						*(packet->destination->get_sockaddr_len(packet->destination)));

	if (bytes_sent != packet->data.len)
	{
		this->logger->log(this->logger, ERROR, "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

/**
 * implementation of socket_t.destroy
 */
void destroy(private_socket_t *this)
{
	close(this->socket_fd);
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
	allocator_free(this);
}

socket_t *socket_create(u_int16_t port)
{
	private_socket_t *this = allocator_alloc_thing(private_socket_t);
	struct sockaddr_in addr;

	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.destroy = (void(*)(socket_t*))destroy;
	
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, SOCKET, NULL);
	
	/* create default ipv4 socket */
	this->socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (this->socket_fd < 0) 
	{
		this->logger->log(this->logger, ERROR, "unable to open socket: %s", strerror(errno));
		charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
		allocator_free(this);
		charon->kill(charon, "socket could not be opened");
	}

	/* bind socket to all interfaces */
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(this->socket_fd,(struct sockaddr*)&addr, sizeof(addr)) < 0) 
    {
		this->logger->log(this->logger, ERROR, "unable to bind socket to port %d: %s", port, strerror(errno));
		charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
		allocator_free(this);
		charon->kill(charon, "socket could not be opened");
    }

	return (socket_t*)this;
}
