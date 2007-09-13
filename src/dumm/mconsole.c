/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2001-2004 Jeff Dike
 *
 * Based on the "uml_mconsole" utility from Jeff Dike.
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
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
	int console;
	/** notify socket */
	int notify;
	/** address of uml socket */
	struct sockaddr_un uml;
};

/**
 * mconsole message format from "arch/um/include/mconsole.h"
 */
typedef struct mconsole_request mconsole_request;
/** mconsole request message */
struct mconsole_request {
	u_int32_t magic;
	u_int32_t version;
	u_int32_t len;
	char data[MCONSOLE_MAX_DATA];
};


typedef struct mconsole_reply mconsole_reply;
/** mconsole reply message */
struct mconsole_reply {
	u_int32_t err;
	u_int32_t more;
	u_int32_t len;
	char data[MCONSOLE_MAX_DATA];
};

typedef struct mconsole_notify mconsole_notify;
/** mconsole notify message */
struct mconsole_notify {
    u_int32_t magic;
    u_int32_t version;
    enum {
		MCONSOLE_SOCKET,
		MCONSOLE_PANIC,
		MCONSOLE_HANG,
		MCONSOLE_USER_NOTIFY,
    } type;
    u_int32_t len;
    char data[MCONSOLE_MAX_DATA];
};

/**
 * send a request to UML using mconsole
 */
static int request(private_mconsole_t *this, char *command,
				   char buf[], size_t *size)
{
	mconsole_request request;
	mconsole_reply reply;
	int len, total = 0;
	
	memset(&request, 0, sizeof(request));
	request.magic = MCONSOLE_MAGIC;
	request.version = MCONSOLE_VERSION;
	request.len = min(strlen(command), sizeof(reply.data) - 1);
	strncpy(request.data, command, request.len);
	*buf = '\0';
	(*size)--;

	if (sendto(this->console, &request, sizeof(request), 0,
		(struct sockaddr*)&this->uml, sizeof(this->uml)) < 0)
	{
		snprintf(buf, *size, "sending mconsole command to UML failed: %m");
		return -1;
	}
	do 
	{
		len = recv(this->console, &reply, sizeof(reply), 0);
		if (len < 0)
		{
			snprintf(buf, *size, "receiving from mconsole failed: %m");
	    	return -1;
		}
		if (len > 0)
		{
			strncat(buf, reply.data, min(reply.len, *size - total));
			total += reply.len;
		}
	}
	while (reply.more);
	
	*size = total;
	return reply.err;
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
	len = sizeof(buf);
	if (request(this, buf, buf, &len) != 0)
	{
		DBG1("adding interface failed: %.*s", len, buf);
		return FALSE;
	}
	return TRUE;
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
	if (request(this, buf, buf, &len) != 0)
	{
		DBG1("removing interface failed: %.*s", len, buf);
		return FALSE;
	}
	return TRUE;
}
	
/**
 * Implementation of mconsole_t.get_console_pts.
 */
static char* get_console_pts(private_mconsole_t *this, int con)
{
	char buf[128];
	char *pos;
	int len;
	
	len = snprintf(buf, sizeof(buf), "config con%d", con);
	if (len < 0 || len >= sizeof(buf))
	{
		return NULL;
	}
	len = sizeof(buf);
	if (request(this, buf, buf, &len) != 0)
	{
		DBG1("getting console pts failed: %.*s", len, buf);
		return NULL;
	}
	pos = memchr(buf, ':', len);
	if (pos == NULL)
	{
		return NULL;
	}
	pos++;
	return strndup(pos, len - (pos - buf));
}

/**
 * Poll until guest is ready
 */
static bool wait_bootup(private_mconsole_t *this)
{
	char *cmd, buf[128];
	int len, res;
	
	cmd = "config con0";
	while (TRUE)
	{
		len = sizeof(buf);
		res = request(this, cmd, buf, &len);
		if (res < 0)
		{
			return FALSE;
		}
		if (res == 0)
		{
			return TRUE;
		}
		usleep(50000);
	}
}

/**
 * Implementation of mconsole_t.destroy.
 */
static void destroy(private_mconsole_t *this)
{
	close(this->console);
	close(this->notify);
	free(this);
}

/**
 * setup the mconsole notify connection and wait for its readyness
 */
static bool wait_for_notify(private_mconsole_t *this, char *nsock)
{
	struct sockaddr_un addr;
	mconsole_notify notify;
	int len;

	this->notify = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (this->notify < 0)
	{
		DBG1("opening mconsole notify socket failed: %m");
		return FALSE;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, nsock, sizeof(addr));
	if (bind(this->notify, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1("binding mconsole notify socket to '%s' failed: %m", nsock);
		close(this->notify);
		return FALSE;
	}
	do
	{
		len = recvfrom(this->notify, &notify, sizeof(notify), 0, NULL, 0);
	} while (len < 0 && errno == EINTR);
	if (len < 0 || len >= sizeof(notify))
	{
		DBG1("reading from mconsole notify socket failed: %m");
		close(this->notify);
		unlink(nsock);
		return FALSE;
	}
	if (notify.magic != MCONSOLE_MAGIC ||
		notify.version != MCONSOLE_VERSION ||
		notify.type != MCONSOLE_SOCKET)
	{
		DBG1("received unexpected message from mconsole notify socket: %b",
			 &notify, sizeof(notify));
		close(this->notify);
		unlink(nsock);
		return FALSE;
	}
	memset(&this->uml, 0, sizeof(this->uml));
	this->uml.sun_family = AF_UNIX;
	strncpy(this->uml.sun_path, (char*)&notify.data, sizeof(this->uml.sun_path));
	return TRUE;
}

/**
 * setup the mconsole console connection
 */
static bool setup_console(private_mconsole_t *this)
{
	struct sockaddr_un addr;
	
	this->console = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (this->console < 0)
	{
		DBG1("opening mconsole socket failed: %m");
		return FALSE;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(&addr.sun_path[1], sizeof(addr.sun_path), "%5d-%d",
			 getpid(), this->console);
	if (bind(this->console, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1("binding mconsole socket to '%s' failed: %m", &addr.sun_path[1]);
		close(this->console);
		return FALSE;
	}
	return TRUE;
}

/**
 * create the mconsole instance
 */
mconsole_t *mconsole_create(char *notify)
{
	private_mconsole_t *this = malloc_thing(private_mconsole_t);
	
	this->public.add_iface = (bool(*)(mconsole_t*, char *guest, char *host))add_iface;
	this->public.del_iface = (bool(*)(mconsole_t*, char *guest))del_iface;
	this->public.get_console_pts = (char*(*)(mconsole_t*, int con))get_console_pts;
	this->public.destroy = (void*)destroy;
	
	if (!wait_for_notify(this, notify))
	{
		free(this);
		return NULL;
	}
	
	if (!setup_console(this))
	{
		close(this->notify);
		unlink(notify);
		free(this);
		return NULL;
	}
	unlink(notify);
	
	if (!wait_bootup(this))
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

