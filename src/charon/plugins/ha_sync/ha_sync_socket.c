/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "ha_sync_socket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <daemon.h>
#include <utils/host.h>

typedef struct private_ha_sync_socket_t private_ha_sync_socket_t;

/**
 * Private data of an ha_sync_socket_t object.
 */
struct private_ha_sync_socket_t {

	/**
	 * Public ha_sync_socket_t interface.
	 */
	ha_sync_socket_t public;

	/**
	 * UDP communication socket fd
	 */
	int fd;
};

/**
 * Implementation of ha_sync_socket_t.push
 */
static void push(private_ha_sync_socket_t *this, ha_sync_message_t *message)
{
	chunk_t data;

	data = message->get_encoding(message);
	if (send(this->fd, data.ptr, data.len, 0) < data.len)
	{
		DBG1(DBG_CFG, "pushing HA sync message failed: %s", strerror(errno));
	}
}

/**
 * Implementation of ha_sync_socket_t.pull
 */
static ha_sync_message_t *pull(private_ha_sync_socket_t *this)
{
	while (TRUE)
	{
		ha_sync_message_t *message;
		char buf[1024];
		int oldstate;
		ssize_t len;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		len = recv(this->fd, buf, sizeof(buf), 0);
		pthread_setcancelstate(oldstate, NULL);
		if (len <= 0)
		{
			if (errno != EINTR)
			{
				DBG1(DBG_CFG, "pulling HA sync message failed: %s",
					 strerror(errno));
				sleep(1);
			}
			continue;
		}
		message = ha_sync_message_parse(chunk_create(buf, len));
		if (message)
		{
			return message;
		}
	}
}

/**
 * read local/remote node address from config
 */
static host_t *get_host_config(char *key)
{
	char *value;
	host_t *host;

	value = lib->settings->get_str(lib->settings,
								   "charon.plugins.ha_sync.%s", NULL, key);
	if (!value)
	{
		DBG1(DBG_CFG, "no %s node specified for HA sync", key);
		return NULL;
	}
	host = host_create_from_dns(value, 0, HA_SYNC_PORT);
	if (!host)
	{
		DBG1(DBG_CFG, "%s node '%s' is invalid", key, value);
	}
	return host;
}

/**
 * Open and connect the HA sync socket
 */
static bool open_socket(private_ha_sync_socket_t *this)
{
	host_t *local, *remote;
	bool success = TRUE;

	local = get_host_config("local");
	remote = get_host_config("remote");
	if (!local || !remote)
	{
		DESTROY_IF(local);
		DESTROY_IF(remote);
		return FALSE;
	}

	this->fd = socket(local->get_family(local), SOCK_DGRAM, 0);
	if (!this->fd)
	{
		DESTROY_IF(local);
		DESTROY_IF(remote);
		DBG1(DBG_CFG, "opening HA sync socket failed: %s", strerror(errno));
		return FALSE;
	}

	if (bind(this->fd, local->get_sockaddr(local),
			 *local->get_sockaddr_len(local)) == -1)
	{
		DBG1(DBG_CFG, "binding HA sync socket failed: %s", strerror(errno));
		close(this->fd);
		success = FALSE;
	}
	if (connect(this->fd, remote->get_sockaddr(remote),
				*remote->get_sockaddr_len(remote)) == -1)
	{
		DBG1(DBG_CFG, "connecting HA sync socket failed: %s", strerror(errno));
		close(this->fd);
		success = FALSE;
	}
	local->destroy(local);
	remote->destroy(remote);
	return success;
}

/**
 * Implementation of ha_sync_socket_t.destroy.
 */
static void destroy(private_ha_sync_socket_t *this)
{
	close(this->fd);
	free(this);
}

/**
 * See header
 */
ha_sync_socket_t *ha_sync_socket_create()
{
	private_ha_sync_socket_t *this = malloc_thing(private_ha_sync_socket_t);

	this->public.push = (void(*)(ha_sync_socket_t*, ha_sync_message_t*))push;
	this->public.pull = (ha_sync_message_t*(*)(ha_sync_socket_t*))pull;
	this->public.destroy = (void(*)(ha_sync_socket_t*))destroy;

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

