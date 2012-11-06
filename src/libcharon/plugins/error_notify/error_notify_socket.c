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

#include "error_notify_socket.h"

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

#include "error_notify_msg.h"

typedef struct private_error_notify_socket_t private_error_notify_socket_t;

/**
 * Private data of an error_notify_socket_t object.
 */
struct private_error_notify_socket_t {

	/**
	 * Public error_notify_socket_t interface.
	 */
	error_notify_socket_t public;

	/**
	 * Unix socket file descriptor
	 */
	int socket;

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
 * Open error notify unix socket
 */
static bool open_socket(private_error_notify_socket_t *this)
{
	struct sockaddr_un addr;
	mode_t old;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, ERROR_NOTIFY_SOCKET);

	this->socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "creating notify socket failed");
		return FALSE;
	}
	unlink(addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_CFG, "binding notify socket failed: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(addr.sun_path, charon->caps->get_uid(charon->caps),
			  charon->caps->get_gid(charon->caps)) != 0)
	{
		DBG1(DBG_CFG, "changing notify socket permissions failed: %s",
			 strerror(errno));
	}
	if (listen(this->socket, 10) < 0)
	{
		DBG1(DBG_CFG, "listening on notify socket failed: %s", strerror(errno));
		close(this->socket);
		unlink(addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

METHOD(error_notify_socket_t, has_listeners, bool,
	private_error_notify_socket_t *this)
{
	int count;

	this->mutex->lock(this->mutex);
	count = this->connected->get_count(this->connected);
	this->mutex->unlock(this->mutex);

	return count != 0;
}

METHOD(error_notify_socket_t, notify, void,
	private_error_notify_socket_t *this, error_notify_msg_t *msg)
{
	enumerator_t *enumerator;
	uintptr_t fd;

	this->mutex->lock(this->mutex);
	enumerator = this->connected->create_enumerator(this->connected);
	while (enumerator->enumerate(enumerator, (void*)&fd))
	{
		while (send(fd, msg, sizeof(*msg), 0) <= 0)
		{
			switch (errno)
			{
				case EINTR:
					continue;
				case ECONNRESET:
				case EPIPE:
					/* disconnect, remove this listener */
					this->connected->remove_at(this->connected, enumerator);
					close(fd);
					break;
				default:
					DBG1(DBG_CFG, "sending notify failed: %s", strerror(errno));
					break;
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Accept client connections, dispatch
 */
static job_requeue_t accept_(private_error_notify_socket_t *this)
{
	struct sockaddr_un addr;
	int fd, len;
	bool oldstate;

	len = sizeof(addr);
	oldstate = thread_cancelability(TRUE);
	fd = accept(this->socket, (struct sockaddr*)&addr, &len);
	thread_cancelability(oldstate);

	if (fd != -1)
	{
		this->mutex->lock(this->mutex);
		this->connected->insert_last(this->connected, (void*)(uintptr_t)fd);
		this->mutex->unlock(this->mutex);
	}
	else
	{
		DBG1(DBG_CFG, "accepting notify connection failed: %s",
			 strerror(errno));
	}
	return JOB_REQUEUE_DIRECT;
}

METHOD(error_notify_socket_t, destroy, void,
	private_error_notify_socket_t *this)
{
	this->connected->destroy(this->connected);
	this->mutex->destroy(this->mutex);
	close(this->socket);
	free(this);
}

/**
 * See header
 */
error_notify_socket_t *error_notify_socket_create()
{
	private_error_notify_socket_t *this;

	INIT(this,
		.public = {
			.notify = _notify,
			.has_listeners = _has_listeners,
			.destroy = _destroy,
		},
		.connected = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio((callback_job_cb_t)accept_, this,
				NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

	return &this->public;
}
