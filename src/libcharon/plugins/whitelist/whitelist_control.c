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

#include "whitelist_control.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

#include "whitelist_msg.h"

typedef struct private_whitelist_control_t private_whitelist_control_t;

/**
 * Private data of an whitelist_control_t object.
 */
struct private_whitelist_control_t {

	/**
	 * Public whitelist_control_t interface.
	 */
	whitelist_control_t public;

	/**
	 * Whitelist
	 */
	whitelist_listener_t *listener;

	/**
	 * Whitelist unix socket file descriptor
	 */
	int socket;

	/**
	 * Callback job dispatching commands
	 */
	callback_job_t *job;
};

/**
 * Open whitelist unix socket
 */
static bool open_socket(private_whitelist_control_t *this)
{
	struct sockaddr_un addr;
	mode_t old;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, WHITELIST_SOCKET);

	this->socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "creating whitelist socket failed");
		return FALSE;
	}
	unlink(addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_CFG, "binding whitelist socket failed: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(addr.sun_path, charon->uid, charon->gid) != 0)
	{
		DBG1(DBG_CFG, "changing whitelist socket permissions failed: %s",
			 strerror(errno));
	}
	if (listen(this->socket, 10) < 0)
	{
		DBG1(DBG_CFG, "listening on whitelist socket failed: %s", strerror(errno));
		close(this->socket);
		unlink(addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Dispatch a received message
 */
static void dispatch(private_whitelist_control_t *this,
					 int fd, whitelist_msg_t *msg)
{
	identification_t *id, *current;
	enumerator_t *enumerator;

	msg->id[sizeof(msg->id)-1] = 0;
	id = identification_create_from_string(msg->id);
	switch (msg->type)
	{
		case WHITELIST_ADD:
			this->listener->add(this->listener, id);
			break;
		case WHITELIST_REMOVE:
			this->listener->remove(this->listener, id);
			break;
		case WHITELIST_LIST:
			enumerator = this->listener->create_enumerator(this->listener);
			while (enumerator->enumerate(enumerator, &current))
			{
				if (current->matches(current, id))
				{
					snprintf(msg->id, sizeof(msg->id), "%Y", current);
					if (send(fd, msg, sizeof(*msg), 0) != sizeof(*msg))
					{
						DBG1(DBG_CFG, "listing whitelist failed");
						break;
					}
				}
			}
			enumerator->destroy(enumerator);
			msg->type = WHITELIST_END;
			memset(msg->id, 0, sizeof(msg->id));
			send(fd, msg, sizeof(*msg), 0);
			break;
		case WHITELIST_FLUSH:
			this->listener->flush(this->listener, id);
			break;
		case WHITELIST_ENABLE:
			this->listener->set_active(this->listener, TRUE);
			break;
		case WHITELIST_DISABLE:
			this->listener->set_active(this->listener, FALSE);
			break;
		default:
			DBG1(DBG_CFG, "received unknown whitelist command");
			break;
	}
	id->destroy(id);
}

/**
 * Accept whitelist control connections, dispatch
 */
static job_requeue_t receive(private_whitelist_control_t *this)
{
	struct sockaddr_un addr;
	int fd, len = sizeof(addr);
	whitelist_msg_t msg;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	fd = accept(this->socket, (struct sockaddr*)&addr, &len);
	thread_cancelability(oldstate);

	if (fd != -1)
	{
		while (TRUE)
		{
			oldstate = thread_cancelability(TRUE);
			len = recv(fd, &msg, sizeof(msg), 0);
			thread_cancelability(oldstate);

			if (len == sizeof(msg))
			{
				dispatch(this, fd, &msg);
			}
			else
			{
				if (len != 0)
				{
					DBG1(DBG_CFG, "receiving whitelist msg failed: %s",
						 strerror(errno));
				}
				break;
			}
		}
		close(fd);
	}
	else
	{
		DBG1(DBG_CFG, "accepting whitelist connection failed: %s",
			 strerror(errno));
	}
	return JOB_REQUEUE_FAIR;
}

METHOD(whitelist_control_t, destroy, void,
	private_whitelist_control_t *this)
{
	this->job->cancel(this->job);
	close(this->socket);
	free(this);
}

/**
 * See header
 */
whitelist_control_t *whitelist_control_create(whitelist_listener_t *listener)
{
	private_whitelist_control_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.listener = listener,
	);

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}

	this->job = callback_job_create_with_prio((callback_job_cb_t)receive,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->job);

	return &this->public;
}
