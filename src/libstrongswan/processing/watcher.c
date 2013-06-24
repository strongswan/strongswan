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

#include "watcher.h"

#include <library.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>

#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

typedef struct private_watcher_t private_watcher_t;

/**
 * Private data of an watcher_t object.
 */
struct private_watcher_t {

	/**
	 * Public watcher_t interface.
	 */
	watcher_t public;

	/**
	 * List of registered FDs, as entry_t
	 */
	linked_list_t *fds;

	/**
	 * Lock to access FD list
	 */
	mutex_t *mutex;

	/**
	 * Condvar to signal completion of callback
	 */
	condvar_t *condvar;

	/**
	 * Notification pipe to signal watcher thread
	 */
	int notify[2];
};

/**
 * Entry for a registered file descriptor
 */
typedef struct {
	/** file descriptor */
	int fd;
	/** events to watch */
	watcher_event_t events;
	/** registered callback function */
	watcher_cb_t cb;
	/** user data to pass to callback */
	void *data;
	/** callback currently active? */
	bool active;
} entry_t;

/**
 * Data we pass on for an async notification
 */
typedef struct {
	/** file descriptor */
	int fd;
	/** event type */
	watcher_event_t event;
	/** registered callback function */
	watcher_cb_t cb;
	/** user data to pass to callback */
	void *data;
	/** keep registered? */
	bool keep;
	/** reference to watcher */
	private_watcher_t *this;
} notify_data_t;

/**
 * Notify watcher thread about changes
 */
static void update(private_watcher_t *this)
{
	char buf[1] = { 'u' };

	if (this->notify[1] != -1)
	{
		ignore_result(write(this->notify[1], buf, sizeof(buf)));
	}
}

 /**
 * Execute callback of registered FD, asynchronous
 */
static job_requeue_t notify_async(notify_data_t *data)
{
	data->keep = data->cb(data->data, data->fd, data->event);
	return JOB_REQUEUE_NONE;
}

/**
 * Clean up notification data, reactivate FD
 */
static void notify_end(notify_data_t *data)
{
	private_watcher_t *this = data->this;
	enumerator_t *enumerator;
	entry_t *entry;

	/* reactivate the disabled entry */
	this->mutex->lock(this->mutex);
	enumerator = this->fds->create_enumerator(this->fds);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->fd == data->fd)
		{
			if (!data->keep)
			{
				entry->events &= ~data->event;
				if (!entry->events)
				{
					this->fds->remove_at(this->fds, enumerator);
					free(entry);
					break;
				}
			}
			entry->active = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	update(this);
	this->condvar->broadcast(this->condvar);
	this->mutex->unlock(this->mutex);

	free(data);
}

/**
 * Execute the callback for a registered FD
 */
static bool notify(private_watcher_t *this, entry_t *entry,
				   watcher_event_t event)
{
	notify_data_t *data;

	/* get a copy of entry for async job, but with specific event */
	INIT(data,
		.fd = entry->fd,
		.event = event,
		.cb = entry->cb,
		.data = entry->data,
		.keep = TRUE,
		.this = this,
	);

	/* deactivate entry, so we can select() other FDs even if the async
	 * processing did not handle the event yet */
	entry->active = FALSE;

	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio((void*)notify_async, data,
						(void*)notify_end, (callback_job_cancel_t)return_false,
						JOB_PRIO_CRITICAL));
	return TRUE;
}

/**
 * Dispatching function
 */
static job_requeue_t watch(private_watcher_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;
	fd_set rd, wr, ex;
	int maxfd = 0, res;

	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);

	this->mutex->lock(this->mutex);
	if (this->fds->get_count(this->fds) == 0)
	{
		this->mutex->unlock(this->mutex);
		return JOB_REQUEUE_NONE;
	}

	if (this->notify[0] != -1)
	{
		FD_SET(this->notify[0], &rd);
		maxfd = this->notify[0];
	}

	enumerator = this->fds->create_enumerator(this->fds);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->active)
		{
			if (entry->events & WATCHER_READ)
			{
				FD_SET(entry->fd, &rd);
			}
			if (entry->events & WATCHER_WRITE)
			{
				FD_SET(entry->fd, &wr);
			}
			if (entry->events & WATCHER_EXCEPT)
			{
				FD_SET(entry->fd, &ex);
			}
			maxfd = max(maxfd, entry->fd);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	while (TRUE)
	{
		char buf[1];
		bool old, notified = FALSE;

		old = thread_cancelability(TRUE);
		res = select(maxfd + 1, &rd, &wr, &ex, NULL);
		thread_cancelability(old);
		if (res > 0)
		{
			if (this->notify[0] != -1 && FD_ISSET(this->notify[0], &rd))
			{
				ignore_result(read(this->notify[0], buf, sizeof(buf)));
				return JOB_REQUEUE_DIRECT;
			}

			this->mutex->lock(this->mutex);
			enumerator = this->fds->create_enumerator(this->fds);
			while (enumerator->enumerate(enumerator, &entry))
			{
				if (FD_ISSET(entry->fd, &rd))
				{
					notified = notify(this, entry, WATCHER_READ);
					break;
				}
				if (FD_ISSET(entry->fd, &wr))
				{
					notified = notify(this, entry, WATCHER_WRITE);
					break;
				}
				if (FD_ISSET(entry->fd, &ex))
				{
					notified = notify(this, entry, WATCHER_EXCEPT);
					break;
				}
			}
			enumerator->destroy(enumerator);
			this->mutex->unlock(this->mutex);

			if (notified)
			{
				/* we temporarily disable a notified FD, rebuild FDSET */
				return JOB_REQUEUE_DIRECT;
			}
		}
	}
}

METHOD(watcher_t, add, void,
	private_watcher_t *this, int fd, watcher_event_t events,
	watcher_cb_t cb, void *data)
{
	entry_t *entry;

	INIT(entry,
		.fd = fd,
		.events = events,
		.cb = cb,
		.data = data,
		.active = TRUE,
	);

	this->mutex->lock(this->mutex);
	this->fds->insert_last(this->fds, entry);
	if (this->fds->get_count(this->fds) == 1)
	{
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio((void*)watch, this,
				NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	}
	else
	{
		update(this);
	}
	this->mutex->unlock(this->mutex);
}

METHOD(watcher_t, remove_, void,
	private_watcher_t *this, int fd)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	while (TRUE)
	{
		bool is_in_callback = FALSE;

		enumerator = this->fds->create_enumerator(this->fds);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->fd == fd)
			{
				if (entry->active)
				{
					this->fds->remove_at(this->fds, enumerator);
					free(entry);
				}
				else
				{
					is_in_callback = TRUE;
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
		if (!is_in_callback)
		{
			break;
		}
		this->condvar->wait(this->condvar, this->mutex);
	}

	update(this);
	this->mutex->unlock(this->mutex);
}

METHOD(watcher_t, destroy, void,
	private_watcher_t *this)
{
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	this->fds->destroy(this->fds);
	if (this->notify[0] != -1)
	{
		close(this->notify[0]);
	}
	if (this->notify[1] != -1)
	{
		close(this->notify[1]);
	}
	free(this);
}

/**
 * See header
 */
watcher_t *watcher_create()
{
	private_watcher_t *this;

	INIT(this,
		.public = {
			.add = _add,
			.remove = _remove_,
			.destroy = _destroy,
		},
		.fds = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.notify[0] = -1,
		.notify[1] = -1,
	);

	if (pipe(this->notify) != 0)
	{
		DBG1(DBG_LIB, "creating watcher notify pipe failed: %s",
			 strerror(errno));
	}
	return &this->public;
}
