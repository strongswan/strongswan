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


status_t receiver(private_socket_t *this, packet_t **packet)
{
	
	char buffer[MAX_PACKET];
	packet_t *pkt = packet_create();
	
	/* do the read */
	pkt->sender.len = sizeof(pkt->sender.addr);
	pkt->data.len = recvfrom(this->socket_fd, buffer, MAX_PACKET, 0, 
							&(pkt->sender.addr), &(pkt->sender.len));
	if (pkt->data.len < 0)
	{
		pkt->destroy(pkt);
		return FAILED;
	}
	
	/* fill in packet */
	pkt->data.ptr = alloc_bytes(pkt->data.len, "data in packet_t");
	memcpy(pkt->data.ptr, buffer, pkt->data.len);
	
	/* return packet */
	*packet = pkt;
	
	return SUCCESS;	
}
	
status_t sender(private_socket_t *this, packet_t *packet) 
{
	ssize_t bytes_sent;
	
	printf("@%d\n", __LINE__);
	/* send data */
	bytes_sent = sendto(this->socket_fd, packet->data.ptr, packet->data.len, 
						0, &(packet->receiver.addr), packet->receiver.len);
				
	printf("bytes: %d\n", bytes_sent);		
	if (bytes_sent != packet->data.len) 
	{
		return FAILED;
	}
	return SUCCESS;
}
	
status_t destroyer(private_socket_t *this)
{
	close(this->socket_fd);
	pfree(this);
	
	return SUCCESS;
}

socket_t *socket_create()
{
	private_socket_t *this = alloc_thing(socket_t, "private_socket_t");
	struct sockaddr_in addr;
	
	/* public functions */
	this->public.send = (status_t(*)(socket_t*, packet_t*))sender;
	this->public.receive = (status_t(*)(socket_t*, packet_t**))receiver;
	this->public.destroy = (status_t(*)(socket_t*))destroyer;
	
	printf("@%d\n", __LINE__);
	/* create default ipv4 socket */
	this->socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (this->socket_fd < 0) {
		pfree(this);
		return NULL;
	}	
	
	printf("@%d\n", __LINE__);
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 500;
    if (bind(this->socket_fd,(struct sockaddr*)&addr, sizeof(addr)) < 0) {
		pfree(this);
        return NULL;
    }
	
	printf("@%d\n", __LINE__);
	return (socket_t*)this;
}
