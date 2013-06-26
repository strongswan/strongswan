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

#include "stream_service.h"

#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

#include <unistd.h>

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
} async_data_t;

/**
 * Clean up accept data
 */
static void destroy_async_data(async_data_t *data)
{
	close(data->fd);
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
		thread_cleanup_push((void*)stream->destroy, stream);
		data->cb(data->data, stream);
		thread_cleanup_pop(TRUE);
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Watcher callback function
 */
static bool watch(private_stream_service_t *this, int fd, watcher_event_t event)
{
	async_data_t *data;

	INIT(data,
		.cb = this->cb,
		.data = this->data,
		.fd = accept(fd, NULL, NULL),
	);

	if (data->fd != -1)
	{
		lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio((void*)accept_async, data,
							(void*)destroy_async_data, NULL, JOB_PRIO_HIGH));
	}
	else
	{
		free(data);
	}
	return TRUE;
}

METHOD(stream_service_t, on_accept, void,
	private_stream_service_t *this, stream_service_cb_t cb, void *data)
{
	if (this->cb)
	{
		lib->watcher->remove(lib->watcher, this->fd);
	}

	this->cb = cb;
	this->data = data;

	if (this->cb)
	{
		lib->watcher->add(lib->watcher, this->fd,
						  WATCHER_READ, (watcher_cb_t)watch, this);
	}
}

METHOD(stream_service_t, destroy, void,
	private_stream_service_t *this)
{
	on_accept(this, NULL, NULL);
	close(this->fd);
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
	);

	return &this->public;
}
