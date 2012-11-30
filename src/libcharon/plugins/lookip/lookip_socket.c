/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "lookip_socket.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>

#include "lookip_msg.h"

typedef struct private_lookip_socket_t private_lookip_socket_t;

/**
 * Private data of an lookip_socket_t object.
 */
struct private_lookip_socket_t {

	/**
	 * Public lookip_socket_t interface.
	 */
	lookip_socket_t public;

	/**
	 * lookip
	 */
	lookip_listener_t *listener;

	/**
	 * lookip unix socket file descriptor
	 */
	int socket;

	/**
	 * List of registered listeners, as entry_t
	 */
	linked_list_t *registered;

	/**
	 * List of connected clients, as uintptr_t FD
	 */
	linked_list_t *connected;

	/**
	 * Mutex to lock clients list
	 */
	mutex_t *mutex;
};

/**
 * Open lookip unix socket
 */
static bool open_socket(private_lookip_socket_t *this)
{
	struct sockaddr_un addr;
	mode_t old;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, LOOKIP_SOCKET);

	this->socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "creating lookip socket failed");
		return FALSE;
	}
	unlink(addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_CFG, "binding lookip socket failed: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(addr.sun_path, charon->caps->get_uid(charon->caps),
			  charon->caps->get_gid(charon->caps)) != 0)
	{
		DBG1(DBG_CFG, "changing lookip socket permissions failed: %s",
			 strerror(errno));
	}
	if (listen(this->socket, 10) < 0)
	{
		DBG1(DBG_CFG, "listening on lookip socket failed: %s", strerror(errno));
		close(this->socket);
		unlink(addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Listener callback entry
 */
typedef struct {
	/* FD to write to */
	int fd;
	/* message type to send */
	int type;
	/* back pointer to socket, only for subscriptions */
	private_lookip_socket_t *this;
} entry_t;

/**
 * Destroy entry
 */
static void entry_destroy(entry_t *this)
{
	close(this->fd);
	free(this);
}

/**
 * Callback function for listener
 */
static bool listener_cb(entry_t *entry, bool up, host_t *vip,
						host_t *other, identification_t *id,
						char *name, u_int unique_id)
{
	lookip_response_t resp = {
		.type = entry->type,
		.unique_id = unique_id,
	};

	/* filter events */
	if (up && entry->type == LOOKIP_NOTIFY_DOWN)
	{
		return TRUE;
	}
	if (!up && entry->type == LOOKIP_NOTIFY_UP)
	{
		return TRUE;
	}

	snprintf(resp.vip, sizeof(resp.vip), "%H", vip);
	snprintf(resp.ip, sizeof(resp.ip), "%H", other);
	snprintf(resp.id, sizeof(resp.id), "%Y", id);
	snprintf(resp.name, sizeof(resp.name), "%s", name);

	switch (send(entry->fd, &resp, sizeof(resp), 0))
	{
		case sizeof(resp):
			return TRUE;
		case 0:
			/* client disconnected, adios */
			break;
		default:
			DBG1(DBG_CFG, "sending lookip response failed: %s", strerror(errno));
			break;
	}
	if (entry->this)
	{	/* unregister listener */
		entry->this->mutex->lock(entry->this->mutex);
		entry->this->registered->remove(entry->this->registered, entry, NULL);
		entry->this->mutex->unlock(entry->this->mutex);

		entry_destroy(entry);
	}
	return FALSE;
}

/**
 * Perform a entry lookup
 */
static void query(private_lookip_socket_t *this, int fd, lookip_request_t *req)
{
	entry_t entry = {
		.fd = fd,
		.type = LOOKIP_ENTRY,
	};
	host_t *vip = NULL;
	int matches = 0;

	if (req)
	{	/* lookup */
		req->vip[sizeof(req->vip) - 1] = 0;
		vip = host_create_from_string(req->vip, 0);
		if (vip)
		{
			matches = this->listener->lookup(this->listener, vip,
											 (void*)listener_cb, &entry);
			vip->destroy(vip);
		}
		if (matches == 0)
		{
			lookip_response_t resp = {
				.type = LOOKIP_NOT_FOUND,
			};

			snprintf(resp.vip, sizeof(resp.vip), "%s", req->vip);
			if (send(fd, &resp, sizeof(resp), 0) < 0)
			{
				DBG1(DBG_CFG, "sending lookip not-found failed: %s",
					 strerror(errno));
			}
		}
	}
	else
	{	/* dump */
		this->listener->lookup(this->listener, NULL,
							   (void*)listener_cb, &entry);
	}
}

/**
 * Subscribe to virtual IP events
 */
static void subscribe(private_lookip_socket_t *this, int fd, int type)
{
	entry_t *entry;

	INIT(entry,
		.fd = fd,
		.type = type,
		.this = this,
	);

	this->mutex->lock(this->mutex);
	this->registered->insert_last(this->registered, entry);
	this->mutex->unlock(this->mutex);

	this->listener->add_listener(this->listener, (void*)listener_cb, entry);
}

/**
 * Check if a client is subscribed for notifications
 */
static bool subscribed(private_lookip_socket_t *this, int fd)
{
	enumerator_t *enumerator;
	bool subscribed = FALSE;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->registered->create_enumerator(this->registered);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->fd == fd)
		{
			subscribed = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return subscribed;
}

/**
 * Create a fd_set from all bound sockets
 */
static int build_fds(private_lookip_socket_t *this, fd_set *fds)
{
	enumerator_t *enumerator;
	uintptr_t fd;
	int maxfd;

	FD_ZERO(fds);
	FD_SET(this->socket, fds);
	maxfd = this->socket;

	this->mutex->lock(this->mutex);
	enumerator = this->connected->create_enumerator(this->connected);
	while (enumerator->enumerate(enumerator, &fd))
	{
		FD_SET(fd, fds);
		maxfd = max(maxfd, fd);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return maxfd + 1;
}

/**
 * Find the socket select()ed
 */
static int scan_fds(private_lookip_socket_t *this, fd_set *fds)
{
	enumerator_t *enumerator;
	uintptr_t fd;
	int selected = -1;

	this->mutex->lock(this->mutex);
	enumerator = this->connected->create_enumerator(this->connected);
	while (enumerator->enumerate(enumerator, &fd))
	{
		if (FD_ISSET(fd, fds))
		{
			selected = fd;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return selected;
}

/**
 * Dispatch from a socket, return TRUE to end communication
 */
static bool dispatch(private_lookip_socket_t *this, int fd)
{
	lookip_request_t req;
	int len;

	len = recv(fd, &req, sizeof(req), 0);
	if (len != sizeof(req))
	{
		if (len != 0)
		{
			DBG1(DBG_CFG, "receiving lookip request failed: %s",
				 strerror(errno));
		}
		return TRUE;
	}
	switch (req.type)
	{
		case LOOKIP_LOOKUP:
			query(this, fd, &req);
			return FALSE;
		case LOOKIP_DUMP:
			query(this, fd, NULL);
			return FALSE;
		case LOOKIP_REGISTER_UP:
			subscribe(this, fd, LOOKIP_NOTIFY_UP);
			return FALSE;
		case LOOKIP_REGISTER_DOWN:
			subscribe(this, fd, LOOKIP_NOTIFY_DOWN);
			return FALSE;
		case LOOKIP_END:
			return TRUE;
		default:
			DBG1(DBG_CFG, "received unknown lookip command");
			return TRUE;
	}
}

/**
 * Accept client connections, dispatch
 */
static job_requeue_t receive(private_lookip_socket_t *this)
{
	struct sockaddr_un addr;
	int fd, maxfd, len;
	bool oldstate;
	fd_set fds;

	while (TRUE)
	{
		maxfd = build_fds(this, &fds);
		oldstate = thread_cancelability(TRUE);
		if (select(maxfd, &fds, NULL, NULL, NULL) <= 0)
		{
			thread_cancelability(oldstate);
			DBG1(DBG_CFG, "selecting lookip sockets failed: %s",
				 strerror(errno));
			break;
		}
		thread_cancelability(oldstate);

		if (FD_ISSET(this->socket, &fds))
		{	/* new connection, accept() */
			len = sizeof(addr);
			fd = accept(this->socket, (struct sockaddr*)&addr, &len);
			if (fd != -1)
			{
				this->mutex->lock(this->mutex);
				this->connected->insert_last(this->connected,
											 (void*)(uintptr_t)fd);
				this->mutex->unlock(this->mutex);
			}
			else
			{
				DBG1(DBG_CFG, "accepting lookip connection failed: %s",
					 strerror(errno));
			}
			continue;
		}

		fd = scan_fds(this, &fds);
		if (fd == -1)
		{
			continue;
		}
		if (dispatch(this, fd))
		{
			this->mutex->lock(this->mutex);
			this->connected->remove(this->connected, (void*)(uintptr_t)fd, NULL);
			this->mutex->unlock(this->mutex);
			if (!subscribed(this, fd))
			{
				close(fd);
			}
		}
	}
	return JOB_REQUEUE_FAIR;
}

METHOD(lookip_socket_t, destroy, void,
	private_lookip_socket_t *this)
{
	this->registered->destroy_function(this->registered, (void*)entry_destroy);
	this->connected->destroy(this->connected);
	this->mutex->destroy(this->mutex);
	close(this->socket);
	free(this);
}

/**
 * See header
 */
lookip_socket_t *lookip_socket_create(lookip_listener_t *listener)
{
	private_lookip_socket_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.listener = listener,
		.registered = linked_list_create(),
		.connected = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio((callback_job_cb_t)receive, this,
				NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

	return &this->public;
}
