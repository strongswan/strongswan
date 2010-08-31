/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "tls_socket.h"

#include <unistd.h>

#include <debug.h>

typedef struct private_tls_socket_t private_tls_socket_t;
typedef struct private_tls_application_t private_tls_application_t;

struct private_tls_application_t {

	/**
	 * Implements tls_application layer.
	 */
	tls_application_t application;

	/**
	 * Chunk of data to send
	 */
	chunk_t out;

	/**
	 * Chunk of data received
	 */
	chunk_t in;
};

/**
 * Private data of an tls_socket_t object.
 */
struct private_tls_socket_t {

	/**
	 * Public tls_socket_t interface.
	 */
	tls_socket_t public;

	/**
	 * TLS application implementation
	 */
	private_tls_application_t app;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * Underlying OS socket
	 */
	int fd;
};

METHOD(tls_application_t, process, status_t,
	private_tls_application_t *this, tls_reader_t *reader)
{
	chunk_t data;

	if (!reader->read_data(reader, reader->remaining(reader), &data))
	{
		return FAILED;
	}
	this->in = chunk_cat("mc", this->in, data);
	return NEED_MORE;
}

METHOD(tls_application_t, build, status_t,
	private_tls_application_t *this, tls_writer_t *writer)
{
	if (this->out.len)
	{
		writer->write_data(writer, this->out);
		this->out = chunk_empty;
		return NEED_MORE;
	}
	return INVALID_STATE;
}

/**
 * TLS data exchange loop
 */
static bool exchange(private_tls_socket_t *this, bool wr)
{
	char buf[1024];
	ssize_t len;
	int round = 0;

	for (round = 0; TRUE; round++)
	{
		while (TRUE)
		{
			len = sizeof(buf);
			switch (this->tls->build(this->tls, buf, &len, NULL))
			{
				case NEED_MORE:
				case ALREADY_DONE:
					len = write(this->fd, buf, len);
					if (len == -1)
					{
						return FALSE;
					}
					continue;
				case INVALID_STATE:
					break;
				default:
					return FALSE;
			}
			break;
		}
		if (wr)
		{
			if (this->app.out.len == 0)
			{	/* all data written */
				return TRUE;
			}
		}
		else
		{
			if (this->app.in.len)
			{	/* some data received */
				return TRUE;
			}
			if (round > 0)
			{	/* did some handshaking, return empty chunk to not block */
				return TRUE;
			}
		}
		len = read(this->fd, buf, sizeof(buf));
		if (len <= 0)
		{
			return FALSE;
		}
		if (this->tls->process(this->tls, buf, len) != NEED_MORE)
		{
			return FALSE;
		}
	}
}

METHOD(tls_socket_t, read_, bool,
	private_tls_socket_t *this, chunk_t *buf)
{
	if (exchange(this, FALSE))
	{
		*buf = this->app.in;
		this->app.in = chunk_empty;
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_socket_t, write_, bool,
	private_tls_socket_t *this, chunk_t buf)
{
	this->app.out = buf;
	if (exchange(this, TRUE))
	{
		return TRUE;
	}
	return FALSE;
}

METHOD(tls_socket_t, destroy, void,
	private_tls_socket_t *this)
{
	this->tls->destroy(this->tls);
	free(this->app.in.ptr);
	free(this);
}

/**
 * See header
 */
tls_socket_t *tls_socket_create(bool is_server, identification_t *server,
								identification_t *peer, int fd)
{
	private_tls_socket_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.write = _write_,
			.destroy = _destroy,
		},
		.app = {
			.application = {
				.build = _build,
				.process = _process,
				.destroy = (void*)nop,
			},
		},
		.fd = fd,
	);

	this->tls = tls_create(is_server, server, peer, TLS_PURPOSE_GENERIC,
						   &this->app.application);
	if (!this->tls)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
