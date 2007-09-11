/**
 * @file gateway.c
 *
 * @brief Implementation of gateway_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include "gateway.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

typedef struct private_gateway_t private_gateway_t;

/**
 * private data of gateway
 */
struct private_gateway_t {

	/**
	 * public functions
	 */
	gateway_t public;
	
	/**
	 * name of the gateway
	 */
	char *name;
	
	/**
	 * connection information
	 */
	host_t *host;
	
	/**
	 * socket file descriptor, > 0 if connected
	 */
	int fd;
};

/**
 * establish connection to gateway
 */
static bool connect_(private_gateway_t *this)
{
	if (this->fd >= 0)
	{
		close(this->fd);
	}
	this->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (this->fd < 0)
	{
		return FALSE;
	}
	if (connect(this->fd, this->host->get_sockaddr(this->host),
				*this->host->get_sockaddr_len(this->host)) != 0)
	{
		close(this->fd);
		this->fd = -1;
		return FALSE;
	}
	return TRUE;
}


/**
 * Implementation of gateway_t.request.
 */
static char* request(private_gateway_t *this, char *xml)
{
	if (this->fd < 0)
	{
		if (!connect_(this))
		{
			return NULL;
		}
	}
	while (TRUE)
	{
		char buf[8096];
		ssize_t len;
		
		len = strlen(xml);
		if (send(this->fd, xml, len, 0) != len)
		{
			return NULL;
		}
		len = recv(this->fd, buf, sizeof(buf) - 1, 0);
		if (len < 0)
		{
			return NULL;
		}
		if (len == 0)
		{
			if (!connect_(this))
			{
				return NULL;
			}
			continue;
		}
		buf[len] = 0;
		return strdup(buf);
	}
}
	
/**
 * Implementation of gateway_t.destroy
 */
static void destroy(private_gateway_t *this)
{
	if (this->fd >= 0)
	{
		close(this->fd);
	}
	this->host->destroy(this->host);
	free(this->name);
	free(this);
}

/*
 * see header file
 */
gateway_t *gateway_create(char *name, host_t *host)
{
	private_gateway_t *this = malloc_thing(private_gateway_t);
	
	this->public.request = (char*(*)(gateway_t*, char *xml))request;
	this->public.destroy = (void(*)(gateway_t*))destroy;
	
	this->name = strdup(name);
	this->host = host;
	this->fd = -1;
	
	return &this->public;
}

