/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "duplicheck_notify.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>

#define DUPLICHECK_SOCKET IPSEC_PIDDIR "/charon.dck"

typedef struct private_duplicheck_notify_t private_duplicheck_notify_t;

/**
 * Private data of an duplicheck_notify_t object.
 */
struct private_duplicheck_notify_t {

	/**
	 * Public duplicheck_notify_t interface.
	 */
	duplicheck_notify_t public;

	/**
	 * Mutex to lock list
	 */
	mutex_t *mutex;

	/**
	 * List of connected sockets
	 */
	linked_list_t *connected;

	/**
	 * Socket dispatching connections
	 */
	int socket;
};

/**
 * Open duplicheck unix socket
 */
static bool open_socket(private_duplicheck_notify_t *this)
{
	struct sockaddr_un addr;
	mode_t old;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, DUPLICHECK_SOCKET);

	this->socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "creating duplicheck socket failed");
		return FALSE;
	}
	unlink(addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_CFG, "binding duplicheck socket failed: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(addr.sun_path, charon->caps->get_uid(charon->caps),
			  charon->caps->get_gid(charon->caps)) != 0)
	{
		DBG1(DBG_CFG, "changing duplicheck socket permissions failed: %s",
			 strerror(errno));
	}
	if (listen(this->socket, 3) < 0)
	{
		DBG1(DBG_CFG, "listening on duplicheck socket failed: %s",
			 strerror(errno));
		close(this->socket);
		unlink(addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Accept duplicheck notification connections
 */
static job_requeue_t receive(private_duplicheck_notify_t *this)
{
	struct sockaddr_un addr;
	int len = sizeof(addr);
	uintptr_t fd;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	fd = accept(this->socket, (struct sockaddr*)&addr, &len);
	thread_cancelability(oldstate);

	if (fd != -1)
	{
		this->mutex->lock(this->mutex);
		this->connected->insert_last(this->connected, (void*)fd);
		this->mutex->unlock(this->mutex);
	 }
	 else
	 {
		 DBG1(DBG_CFG, "accepting duplicheck connection failed: %s",
			  strerror(errno));
	 }
	 return JOB_REQUEUE_FAIR;
}

METHOD(duplicheck_notify_t, send_, void,
	private_duplicheck_notify_t *this, identification_t *id)
{
	char buf[128];
	enumerator_t *enumerator;
	uintptr_t fd;
	int len;

	len = snprintf(buf, sizeof(buf), "%Y", id);
	if (len > 0 && len < sizeof(buf))
	{
		this->mutex->lock(this->mutex);
		enumerator = this->connected->create_enumerator(this->connected);
		while (enumerator->enumerate(enumerator, &fd))
		{
			if (send(fd, &buf, len + 1, 0) != len + 1)
			{
				DBG1(DBG_CFG, "sending duplicheck notify failed: %s",
					 strerror(errno));
				this->connected->remove_at(this->connected, enumerator);
				close(fd);
			}
		}
		enumerator->destroy(enumerator);
		this->mutex->unlock(this->mutex);
	}
}

METHOD(duplicheck_notify_t, destroy, void,
	private_duplicheck_notify_t *this)
{
	enumerator_t *enumerator;
	uintptr_t fd;

	enumerator = this->connected->create_enumerator(this->connected);
	while (enumerator->enumerate(enumerator, &fd))
	{
		close(fd);
	}
	enumerator->destroy(enumerator);
	this->connected->destroy(this->connected);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
duplicheck_notify_t *duplicheck_notify_create()
{
	private_duplicheck_notify_t *this;

	INIT(this,
		.public = {
			.send = _send_,
			.destroy = _destroy,
		},
		.connected = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (!open_socket(this))
	{
		destroy(this);
		return NULL;
	}
	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio((callback_job_cb_t)receive, this,
				NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

	return &this->public;
}
