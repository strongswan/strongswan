/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include <library.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <processing/jobs/callback_job.h>

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

typedef struct private_stream_service_t private_stream_service_t;

/**
 * Private data of an stream_service_t object.
 */
struct private_stream_service_t {

	/**
	 * Public stream_service_t interface.
	 */
	stream_service_t public;

	/**
	 * Underlying socket
	 */
	int fd;

	/**
	 * Accept callback
	 */
	stream_service_cb_t cb;

	/**
	 * Accept callback data
	 */
	void *data;

	/**
	 * Job priority to invoke callback with
	 */
	job_priority_t prio;

	/**
	 * Maximum number of parallel callback invocations
	 */
	u_int cncrncy;

	/**
	 * Currently active jobs
	 */
	u_int active;

	/**
	 * mutex to lock active counter
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for callback termination
	 */
	condvar_t *condvar;
};

/**
 * Data to pass to async accept job
 */
typedef struct {
	/** callback function */
	stream_service_cb_t cb;
	/** callback data */
	void *data;
	/** accepted connection */
	int fd;
	/** reference to stream service */
	private_stream_service_t *this;
} async_data_t;

/**
 * Clean up accept data
 */
static void destroy_async_data(async_data_t *data)
{
	private_stream_service_t *this = data->this;

	this->mutex->lock(this->mutex);
	if (this->active-- == this->cncrncy)
	{
		/* leaving concurrency limit, restart accept()ing. */
		this->public.on_accept(&this->public, this->cb, this->data,
							   this->prio, this->cncrncy);
	}
	this->condvar->signal(this->condvar);
	this->mutex->unlock(this->mutex);

	if (data->fd != -1)
	{
		close(data->fd);
	}
	free(data);
}

/**
 * Async processing of accepted connection
 */
static job_requeue_t accept_async(async_data_t *data)
{
	stream_t *stream;

	stream = stream_create_from_fd(data->fd);
	if (stream)
	{
		/* FD is now owned by stream, don't close it during cleanup */
		data->fd = -1;
		thread_cleanup_push((void*)stream->destroy, stream);
		thread_cleanup_pop(!data->cb(data->data, stream));
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Watcher callback function
 */
static bool watch(private_stream_service_t *this, int fd, watcher_event_t event)
{
	async_data_t *data;
	bool keep = TRUE;

	INIT(data,
		.cb = this->cb,
		.data = this->data,
		.fd = accept(fd, NULL, NULL),
		.this = this,
	);

	if (data->fd != -1)
	{
		this->mutex->lock(this->mutex);
		if (++this->active == this->cncrncy)
		{
			/* concurrency limit reached, stop accept()ing new connections */
			keep = FALSE;
		}
		this->mutex->unlock(this->mutex);

		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio((void*)accept_async, data,
				(void*)destroy_async_data, (callback_job_cancel_t)return_false,
				this->prio));
	}
	else
	{
		free(data);
	}
	return keep;
}

METHOD(stream_service_t, on_accept, void,
	private_stream_service_t *this, stream_service_cb_t cb, void *data,
	job_priority_t prio, u_int cncrncy)
{
	this->mutex->lock(this->mutex);

	/* wait for all callbacks to return */
	while (this->active)
	{
		this->condvar->wait(this->condvar, this->mutex);
	}

	if (this->cb)
	{
		lib->watcher->remove(lib->watcher, this->fd);
	}

	this->cb = cb;
	this->data = data;
	if (prio <= JOB_PRIO_MAX)
	{
		this->prio = prio;
	}
	this->cncrncy = cncrncy;

	if (this->cb)
	{
		lib->watcher->add(lib->watcher, this->fd,
						  WATCHER_READ, (watcher_cb_t)watch, this);
	}

	this->mutex->unlock(this->mutex);
}

METHOD(stream_service_t, destroy, void,
	private_stream_service_t *this)
{
	on_accept(this, NULL, NULL, this->prio, this->cncrncy);
	close(this->fd);
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	free(this);
}

/**
 * See header
 */
stream_service_t *stream_service_create_from_fd(int fd)
{
	private_stream_service_t *this;

	INIT(this,
		.public = {
			.on_accept = _on_accept,
			.destroy = _destroy,
		},
		.fd = fd,
		.prio = JOB_PRIO_MEDIUM,
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
	);

	return &this->public;
}

/**
 * See header
 */
stream_service_t *stream_service_create_unix(char *uri, int backlog)
{
	struct sockaddr_un addr;
	mode_t old;
	int fd, len;

	len = stream_parse_uri_unix(uri, &addr);
	if (len == -1)
	{
		DBG1(DBG_NET, "invalid stream URI: '%s'", uri);
		return NULL;
	}
	if (!lib->caps->check(lib->caps, CAP_CHOWN))
	{	/* required to chown(2) service socket */
		DBG1(DBG_NET, "socket '%s' requires CAP_CHOWN capability", uri);
		return NULL;
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
	{
		DBG1(DBG_NET, "opening socket '%s' failed: %s", uri, strerror(errno));
		return NULL;
	}
	unlink(addr.sun_path);

	old = umask(S_IRWXO);
	if (bind(fd, (struct sockaddr*)&addr, len) < 0)
	{
		DBG1(DBG_NET, "binding socket '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	umask(old);
	if (chown(addr.sun_path, lib->caps->get_uid(lib->caps),
			  lib->caps->get_gid(lib->caps)) != 0)
	{
		DBG1(DBG_NET, "changing socket permissions for '%s' failed: %s",
			 uri, strerror(errno));
	}
	if (listen(fd, backlog) < 0)
	{
		DBG1(DBG_NET, "listen on socket '%s' failed: %s", uri, strerror(errno));
		unlink(addr.sun_path);
		close(fd);
		return NULL;
	}
	return stream_service_create_from_fd(fd);
}

/**
 * See header
 */
stream_service_t *stream_service_create_tcp(char *uri, int backlog)
{
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr sa;
	} addr;
	int fd, len, on = 1;

	len = stream_parse_uri_tcp(uri, &addr.sa);
	if (len == -1)
	{
		DBG1(DBG_NET, "invalid stream URI: '%s'", uri);
		return NULL;
	}
	fd = socket(addr.sa.sa_family, SOCK_STREAM, 0);
	if (fd < 0)
	{
		DBG1(DBG_NET, "opening socket '%s' failed: %s", uri, strerror(errno));
		return NULL;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
	{
		DBG1(DBG_NET, "SO_REUSADDR on '%s' failed: %s", uri, strerror(errno));
	}
	if (bind(fd, &addr.sa, len) < 0)
	{
		DBG1(DBG_NET, "binding socket '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	if (listen(fd, backlog) < 0)
	{
		DBG1(DBG_NET, "listen on socket '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	return stream_service_create_from_fd(fd);
}
