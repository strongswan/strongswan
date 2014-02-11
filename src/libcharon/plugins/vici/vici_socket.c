/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "vici_socket.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <threading/rwlock.h>
#include <threading/thread.h>
#include <collections/array.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>

#include <errno.h>
#include <string.h>

typedef struct private_vici_socket_t private_vici_socket_t;

/**
 * Private members of vici_socket_t
 */
struct private_vici_socket_t {

	/**
	 * public functions
	 */
	vici_socket_t public;

	/**
	 * Inbound message callback
	 */
	vici_inbound_cb_t inbound;

	/**
	 * Client connect callback
	 */
	vici_connect_cb_t connect;

	/**
	 * Client disconnect callback
	 */
	vici_disconnect_cb_t disconnect;

	/**
	 * Next client connection identifier
	 */
	u_int nextid;

	/**
	 * User data for callbacks
	 */
	void *user;

	/**
	 * Service accepting vici connections
	 */
	stream_service_t *service;

	/**
	 * Client connections, as entry_t
	 */
	linked_list_t *connections;

	/**
	 * rwlock for client connection list
	 */
	rwlock_t *lock;
};

/**
 * Data to securely reference an entry
 */
typedef struct {
	/* reference to socket instance */
	private_vici_socket_t *this;
	/** connection identifier to disconnect */
	u_int id;
} entry_data_t;

/**
 * Partially processed message
 */
typedef struct {
	/** bytes of length header sent/received */
	u_char hdrlen;
	/** bytes of length header */
	char hdr[sizeof(u_int16_t)];
	/** send/receive buffer on heap */
	chunk_t buf;
	/** bytes sent/received in buffer */
	u_int16_t done;
} msg_buf_t;

/**
 * Client connection entry
 */
typedef struct {
	/** reference to socket */
	private_vici_socket_t *this;
	/** mutex to lock this entry in/out buffers */
	mutex_t *mutex;
	/** associated stream */
	stream_t *stream;
	/** queued messages to send, as msg_buf_t pointers */
	array_t *out;
	/** input message buffer */
	msg_buf_t in;
	/** client connection identifier */
	u_int id;
} entry_t;

/**
 * Destroy an connection entry
 */
CALLBACK(destroy_entry, void,
	entry_t *entry)
{
	msg_buf_t *out;

	entry->stream->destroy(entry->stream);

	entry->this->disconnect(entry->this->user, entry->id);

	entry->mutex->destroy(entry->mutex);
	while (array_remove(entry->out, ARRAY_TAIL, &out))
	{
		chunk_clear(&out->buf);
		free(out);
	}
	array_destroy(entry->out);
	chunk_clear(&entry->in.buf);
	free(entry);
}

/**
 * Find/remove entry by id, requires proper locking
 */
static entry_t* find_entry(private_vici_socket_t *this, u_int id, bool remove)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;

	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id == id)
		{
			if (remove)
			{
				this->connections->remove_at(this->connections, enumerator);
			}
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

/**
 * Asynchronous callback to disconnect client
 */
CALLBACK(disconnect_async, job_requeue_t,
	entry_data_t *data)
{
	entry_t *entry;

	data->this->lock->write_lock(data->this->lock);
	entry = find_entry(data->this, data->id, TRUE);
	data->this->lock->unlock(data->this->lock);
	if (entry)
	{
		destroy_entry(entry);
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Disconnect a connected client
 */
static void disconnect(private_vici_socket_t *this, u_int id)
{
	entry_data_t *data;

	INIT(data,
		.this = this,
		.id = id,
	);

	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create(disconnect_async, data, free, NULL));
}

/**
 * Write queued output data
 */
static bool do_write(private_vici_socket_t *this, entry_t *entry,
					 stream_t *stream)
{
	msg_buf_t *out;
	ssize_t len;

	while (array_get(entry->out, ARRAY_HEAD, &out))
	{
		/* write header */
		while (out->hdrlen < sizeof(out->hdr))
		{
			len = stream->write(stream, out->hdr + out->hdrlen,
								sizeof(out->hdr) - out->hdrlen, FALSE);
			if (len == 0)
			{
				return FALSE;
			}
			if (len < 0)
			{
				if (errno == EWOULDBLOCK)
				{
					return TRUE;
				}
				DBG1(DBG_CFG, "vici header write error: %s", strerror(errno));
				return FALSE;
			}
			out->hdrlen += len;
		}

		/* write buffer buffer */
		while (out->buf.len > out->done)
		{
			len = stream->write(stream, out->buf.ptr + out->done,
								out->buf.len - out->done, FALSE);
			if (len == 0)
			{
				DBG1(DBG_CFG, "premature vici disconnect");
				return FALSE;
			}
			if (len < 0)
			{
				if (errno == EWOULDBLOCK)
				{
					return TRUE;
				}
				DBG1(DBG_CFG, "vici write error: %s", strerror(errno));
				return FALSE;
			}
			out->done += len;
		}

		if (array_remove(entry->out, ARRAY_HEAD, &out))
		{
			chunk_clear(&out->buf);
			free(out);
		}
	}
	return TRUE;
}

/**
 * Send pending messages
 */
CALLBACK(on_write, bool,
	entry_t *entry, stream_t *stream)
{
	bool ret;

	entry->mutex->lock(entry->mutex);
	ret = do_write(entry->this, entry, stream);
	if (ret)
	{
		/* unregister if we have no more messages to send */
		ret = array_count(entry->out) != 0;
	}
	else
	{
		disconnect(entry->this, entry->id);
	}
	entry->mutex->unlock(entry->mutex);

	return ret;
}

/**
 * Read in available header with data, non-blocking cumulating to buffer
 */
static bool do_read(private_vici_socket_t *this, entry_t *entry,
					stream_t *stream)
{
	ssize_t len;

	/* assemble the length header first */
	while (entry->in.hdrlen < sizeof(entry->in.hdr))
	{
		len = stream->read(stream, entry->in.hdr + entry->in.hdrlen,
						   sizeof(entry->in.hdr) - entry->in.hdrlen, FALSE);
		if (len == 0)
		{
			return FALSE;
		}
		if (len < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				return TRUE;
			}
			DBG1(DBG_CFG, "vici header read error: %s", strerror(errno));
			return FALSE;
		}
		entry->in.hdrlen += len;
		if (entry->in.hdrlen == sizeof(entry->in.hdr))
		{
			/* header complete, continue with data */
			entry->in.buf = chunk_alloc(untoh16(entry->in.hdr));
		}
	}

	/* assemble buffer */
	while (entry->in.buf.len > entry->in.done)
	{
		len = stream->read(stream, entry->in.buf.ptr + entry->in.done,
						   entry->in.buf.len - entry->in.done, FALSE);
		if (len == 0)
		{
			DBG1(DBG_CFG, "premature vici disconnect");
			return FALSE;
		}
		if (len < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				return TRUE;
			}
			DBG1(DBG_CFG, "vici read error: %s", strerror(errno));
			return FALSE;
		}
		entry->in.done += len;
	}

	return TRUE;
}

/**
 * Process incoming messages
 */
CALLBACK(on_read, bool,
	entry_t *entry, stream_t *stream)
{
	chunk_t data = chunk_empty;
	bool ret;

	entry->mutex->lock(entry->mutex);
	ret = do_read(entry->this, entry, stream);
	if (!ret)
	{
		disconnect(entry->this, entry->id);
	}
	if (entry->in.buf.len == entry->in.done)
	{
		data = entry->in.buf;
		entry->in.buf = chunk_empty;
		entry->in.hdrlen = entry->in.done = 0;
	}
	entry->mutex->unlock(entry->mutex);

	if (data.len)
	{
		thread_cleanup_push(free, data.ptr);
		entry->this->inbound(entry->this->user, entry->id, data);
		thread_cleanup_pop(TRUE);
	}

	return ret;
}

/**
 * Process connection request
 */
static bool on_accept(private_vici_socket_t *this, stream_t *stream)
{
	entry_t *entry;
	u_int id;

	id = ref_get(&this->nextid);

	INIT(entry,
		.this = this,
		.stream = stream,
		.id = id,
		.out = array_create(0, 0),
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
	);

	this->lock->write_lock(this->lock);
	this->connections->insert_last(this->connections, entry);
	stream->on_read(stream, on_read, entry);
	this->lock->unlock(this->lock);

	this->connect(this->user, id);

	return TRUE;
}

/**
 * Enable on_write callback to send data
 */
CALLBACK(on_write_async, job_requeue_t,
	entry_data_t *data)
{
	private_vici_socket_t *this = data->this;
	entry_t *entry;

	this->lock->read_lock(this->lock);
	entry = find_entry(this, data->id, FALSE);
	if (entry)
	{
		entry->stream->on_write(entry->stream, on_write, entry);
	}
	this->lock->unlock(this->lock);

	return JOB_REQUEUE_NONE;
}

METHOD(vici_socket_t, send_, void,
	private_vici_socket_t *this, u_int id, chunk_t msg)
{
	if (msg.len <= (u_int16_t)~0)
	{
		entry_data_t *data;
		msg_buf_t *out;
		entry_t *entry;

		this->lock->read_lock(this->lock);
		entry = find_entry(this, id, FALSE);
		if (entry)
		{
			INIT(out,
				.buf = msg,
			);
			htoun16(out->hdr, msg.len);

			entry->mutex->lock(entry->mutex);
			array_insert(entry->out, ARRAY_TAIL, out);
			entry->mutex->unlock(entry->mutex);

			if (array_count(entry->out) == 1)
			{
				INIT(data,
					.this = this,
					.id = entry->id,
				);
				/* asynchronously enable writing, as this might be called
				 * from the on_read() callback. */
				lib->processor->queue_job(lib->processor,
							(job_t*)callback_job_create(on_write_async,
														data, free, NULL));
			}
		}
		else
		{
			DBG1(DBG_CFG, "vici connection %u unknown", id);
		}
		this->lock->unlock(this->lock);
	}
	else
	{
		DBG1(DBG_CFG, "vici message exceeds maximum size, discarded");
		chunk_clear(&msg);
	}
}

METHOD(vici_socket_t, destroy, void,
	private_vici_socket_t *this)
{
	DESTROY_IF(this->service);
	this->connections->destroy_function(this->connections, destroy_entry);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
vici_socket_t *vici_socket_create(char *uri, vici_inbound_cb_t inbound,
								  vici_connect_cb_t connect,
								  vici_disconnect_cb_t disconnect, void *user)
{
	private_vici_socket_t *this;

	INIT(this,
		.public = {
			.send = _send_,
			.destroy = _destroy,
		},
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.connections = linked_list_create(),
		.inbound = inbound,
		.connect = connect,
		.disconnect = disconnect,
		.user = user,
	);

	this->service = lib->streams->create_service(lib->streams, uri, 3);
	if (!this->service)
	{
		DBG1(DBG_CFG, "creating vici socket failed");
		destroy(this);
		return NULL;
	}
	this->service->on_accept(this->service, (stream_service_cb_t)on_accept,
							 this, JOB_PRIO_CRITICAL, 0);

	return &this->public;
}
