/**
 * @file socket.c
 * 
 * @brief management of sockets
 * 
 * receiver reads from here, sender writes to here
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

#include "socket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>



typedef struct {
	/**
	 * public functions
	 */
	 socket_t public;
	 
	 /**
	  * currently we only have one socket, maybe more in the future ?
	  */
	  int socket_fd;
} private_socket_t;

/**
 * implementation of socket_t.receive
 */
status_t receiver(private_socket_t *this, packet_t **packet)
{
	char buffer[MAX_PACKET];
	
	packet_t *pkt = packet_create(AF_INET);
	
	/* do the read */
	pkt->data.len = recvfrom(this->socket_fd, buffer, MAX_PACKET, 0, 
							&(pkt->source), &(pkt->sockaddr_len));
	/* TODO: get senders destination address, using 
	 * IP_PKTINFO and recvmsg */
							
	if (pkt->data.len < 0)
	{
		pkt->destroy(pkt);
		/* TODO: log detailed error */
		return FAILED;
	}
	
	/* fill in packet */
	pkt->data.ptr = alloc_bytes(pkt->data.len, "data in packet_t");
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
	
	/* send data */
	bytes_sent = sendto(this->socket_fd, packet->data.ptr, packet->data.len, 
						0, &(packet->destination), packet->sockaddr_len);
					
	if (bytes_sent != packet->data.len) 
	{
		/* TODO: log detailed error */
		return FAILED;
	}
	return SUCCESS;
}
	
/**
 * implementation of socket_t.destroy
 */
status_t destroy(private_socket_t *this)
{
	close(this->socket_fd);
	pfree(this);
	
	return SUCCESS;
}

socket_t *socket_create(u_int16_t port)
{
	private_socket_t *this = alloc_thing(socket_t, "private_socket_t");
	struct sockaddr_in addr;
	
	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.destroy = (status_t(*)(socket_t*))destroy;
	
	/* create default ipv4 socket */
	this->socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (this->socket_fd < 0) {
		pfree(this);
		/* TODO: log detailed error */
		return NULL;
	}	
	
	/* bind socket to all interfaces */
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(this->socket_fd,(struct sockaddr*)&addr, sizeof(addr)) < 0) {
		pfree(this);
		/* TODO: log detailed error */
        return NULL;
    }
	
	return (socket_t*)this;
}
