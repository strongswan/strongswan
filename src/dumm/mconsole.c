/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2001-2004 Jeff Dike
 *
 * Based on the "uml_mconsole" utilty from Jeff Dike.
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

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <debug.h>

#include "mconsole.h"

#define MCONSOLE_MAGIC 0xcafebabe
#define MCONSOLE_VERSION 2
#define MCONSOLE_MAX_DATA 512

typedef struct private_mconsole_t private_mconsole_t;

struct private_mconsole_t {
	/** public interface */
	mconsole_t public;
	/** mconsole socket */
	int socket;
	/** address of uml socket */
	struct sockaddr_un uml;
};

/**
 * send a request to UML using mconsole
 */
static bool request(private_mconsole_t *this, char *command)
{
	struct {
		u_int32_t magic;
		u_int32_t version;
		u_int32_t len;
		char data[MCONSOLE_MAX_DATA];
	} request;
	struct {
		u_int32_t err;
		u_int32_t more;
		u_int32_t len;
		char data[MCONSOLE_MAX_DATA];
	} reply;
	bool first = TRUE, good = TRUE;
	int len;
	
	memset(&request, 0, sizeof(request));
	request.magic = MCONSOLE_MAGIC;
	request.version = MCONSOLE_VERSION;
	request.len = min(strlen(command), sizeof(reply.data) - 1);
	strncpy(request.data, command, request.len);

	if (sendto(this->socket, &request, sizeof(request), 0,
		(struct sockaddr*)&this->uml, sizeof(this->uml)) < 0)
	{
		DBG1("sending mconsole command to UML failed: %m");
		return FALSE;
	}
	do 
	{
		len = recvfrom(this->socket, &reply, sizeof(reply), 0, NULL, 0);
		if (len < 0)
		{
			DBG1("receiving from mconsole failed: %m");
	    	return FALSE;
		}
		if (first && reply.err)
		{
			good = FALSE;
			DBG1("received error from UML mconsole: %s", reply.data);
		}
		first = FALSE;
	}
	while (reply.more);
	return good;
}

/**
 * Implementation of mconsole_t.add_iface.
 */
static bool add_iface(private_mconsole_t *this, char *guest, char *host)
{
	char buf[128];
	int len;
	
	len = snprintf(buf, sizeof(buf), "config %s=tuntap,%s", guest, host);
	if (len < 0 || len >= sizeof(buf))
	{
		return FALSE;
	}
	return request(this, buf);
}

/**
 * Implementation of mconsole_t.del_iface.
 */
static bool del_iface(private_mconsole_t *this, char *guest)
{
	char buf[128];
	int len;
	
	len = snprintf(buf, sizeof(buf), "remove %s", guest);
	if (len < 0 || len >= sizeof(buf))
	{
		return FALSE;
	}
	return request(this, buf);
}

/**
 * Implementation of mconsole_t.destroy.
 */
static void destroy(private_mconsole_t *this)
{
	close(this->socket);
	free(this);
}

/**
 * create the mconsole instance
 */
mconsole_t *mconsole_create(char *sock)
{
	struct sockaddr_un addr;
	private_mconsole_t *this = malloc_thing(private_mconsole_t);
	
	this->public.add_iface = (bool(*)(mconsole_t*, char *guest, char *host))add_iface;
	this->public.del_iface = (bool(*)(mconsole_t*, char *guest))del_iface;
	this->public.destroy = (void*)destroy;
	
	this->socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (this->socket < 0)
	{
		DBG1("opening mconsole socket failed: %m");
		free(this);
		return NULL;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], "%5d", getpid());
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1("binding mconsole socket failed: %m");
		destroy(this);
		return NULL;
	}
	memset(&this->uml, 0, sizeof(this->uml));
	this->uml.sun_family = AF_UNIX;
	strncpy(this->uml.sun_path, sock, sizeof(this->uml.sun_path));
	
	return &this->public;
}

