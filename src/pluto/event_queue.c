/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <unistd.h>
#include <fcntl.h>

#include "event_queue.h"

#include <debug.h>
#include <threading/mutex.h>
#include <utils/linked_list.h>

typedef struct private_event_queue_t private_event_queue_t;

/**
 * Private data of event_queue_t class.
 */
struct private_event_queue_t {
	/**
	 * Public event_queue_t interface.
	 */
	event_queue_t public;

	/**
	 * List of queued events (event_t*).
	 */
	linked_list_t *events;

	/**
	 * Mutex for event list.
	 */
	mutex_t *mutex;

	/**
	 * Read end of the notification pipe.
	 */
	int read_fd;

	/**
	 * Write end of the notification pipe.
	 */
	int write_fd;

};

typedef struct event_t event_t;

struct event_t {
	/**
	 * Callback function.
	 */
	void (*callback)(void *data);

	/**
	 * Data to supply to the callback.
	 */
	void *data;

	/**
	 * Cleanup function.
	 */
	void (*cleanup)(void *data);
};

static event_t *event_create(void (*callback)(void *data), void *data,
							 void (*cleanup)(void *data))
{
	event_t *this;
	INIT(this,
		.callback = callback,
		.data = data,
		.cleanup = cleanup,
	);
	return this;
}

static void event_destroy(event_t *this)
{
	if (this->cleanup)
	{
		this->cleanup(this->data);
	}
	free(this);
}

METHOD(event_queue_t, get_event_fd, int,
	   private_event_queue_t *this)
{
	return this->read_fd;
}

METHOD(event_queue_t, handle, void,
	   private_event_queue_t *this)
{
	char buf[10];
	linked_list_t *events;
	event_t *event;
	this->mutex->lock(this->mutex);
	/* flush pipe */
	while (read(this->read_fd, &buf, sizeof(buf)) == sizeof(buf));
	/* replace the list, so we can unlock the mutex while executing the jobs */
	events = this->events;
	this->events = linked_list_create();
	this->mutex->unlock(this->mutex);

	while (events->remove_first(events, (void**)&event) == SUCCESS)
	{
		event->callback(event->data);
		event_destroy(event);
	}
	events->destroy(events);
}

METHOD(event_queue_t, queue, void,
	   private_event_queue_t *this, void (*callback)(void *data), void *data,
	   void (*cleanup)(void *data))
{
	event_t *event = event_create(callback, data, cleanup);
	char c = 0;
	this->mutex->lock(this->mutex);
	this->events->insert_last(this->events, event);
	ignore_result(write(this->write_fd, &c, 1));
	this->mutex->unlock(this->mutex);
}

METHOD(event_queue_t, destroy, void,
	   private_event_queue_t *this)
{
	this->mutex->lock(this->mutex);
	this->events->destroy_function(this->events, (void*)event_destroy);
	this->mutex->unlock(this->mutex);
	this->mutex->destroy(this->mutex);
	close(this->read_fd);
	close(this->write_fd);
	free(this);
}

static bool set_nonblock(int socket)
{
	int flags = fcntl(socket, F_GETFL);
	return flags != -1 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) != -1;
}

static bool set_cloexec(int socket)
{
	int flags = fcntl(socket, F_GETFD);
	return flags != -1 && fcntl(socket, F_SETFD, flags | FD_CLOEXEC) != -1;
}

/*
 * Described in header.
 */
event_queue_t *event_queue_create()
{
	private_event_queue_t *this;
	int fd[2];

	INIT(this,
		.public = {
			.get_event_fd = _get_event_fd,
			.handle = _handle,
			.queue = _queue,
			.destroy = _destroy,
		},
		.events = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (pipe(fd) == -1 ||
		!set_nonblock(fd[0]) || !set_cloexec(fd[0]) ||
		!set_nonblock(fd[1]) || !set_cloexec(fd[1]))
	{
		DBG1(DBG_JOB, "failed to create pipe for job queue");
		_destroy(this);
		return NULL;
	}

	this->read_fd = fd[0];
	this->write_fd = fd[1];

	return &this->public;
}

