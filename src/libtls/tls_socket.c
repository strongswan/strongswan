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
#include <errno.h>

#include <debug.h>
#include <threading/thread.h>

/**
 * Buffer size for plain side I/O
 */
#define PLAIN_BUF_SIZE 4096

/**
 * Buffer size for encrypted side I/O
 */
#define CRYPTO_BUF_SIZE 4096

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
	private_tls_application_t *this, bio_reader_t *reader)
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
	private_tls_application_t *this, bio_writer_t *writer)
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
	char buf[CRYPTO_BUF_SIZE], *pos;
	ssize_t len, out;
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
					pos = buf;
					while (len)
					{
						out = write(this->fd, pos, len);
						if (out == -1)
						{
							DBG1(DBG_TLS, "TLS crypto write error: %s",
								 strerror(errno));
							return FALSE;
						}
						len -= out;
						pos += out;
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

METHOD(tls_socket_t, splice, bool,
	private_tls_socket_t *this, int rfd, int wfd)
{
	char buf[PLAIN_BUF_SIZE], *pos;
	fd_set set;
	chunk_t data;
	ssize_t len;
	bool old;

	while (TRUE)
	{
		FD_ZERO(&set);
		FD_SET(rfd, &set);
		FD_SET(this->fd, &set);

		old = thread_cancelability(TRUE);
		len = select(max(rfd, this->fd) + 1, &set, NULL, NULL, NULL);
		thread_cancelability(old);
		if (len == -1)
		{
			DBG1(DBG_TLS, "TLS select error: %s", strerror(errno));
			return FALSE;
		}
		if (FD_ISSET(this->fd, &set))
		{
			if (!read_(this, &data))
			{
				DBG2(DBG_TLS, "TLS read error/disconnect");
				return TRUE;
			}
			pos = data.ptr;
			while (data.len)
			{
				len = write(wfd, pos, data.len);
				if (len == -1)
				{
					free(data.ptr);
					DBG1(DBG_TLS, "TLS plain write error: %s", strerror(errno));
					return FALSE;
				}
				data.len -= len;
				pos += len;
			}
			free(data.ptr);
		}
		if (FD_ISSET(rfd, &set))
		{
			len = read(rfd, buf, sizeof(buf));
			if (len > 0)
			{
				if (!write_(this, chunk_create(buf, len)))
				{
					DBG1(DBG_TLS, "TLS write error");
					return FALSE;
				}
			}
			else
			{
				if (len < 0)
				{
					DBG1(DBG_TLS, "TLS plain read error: %s", strerror(errno));
					return FALSE;
				}
				return TRUE;
			}
		}
	}
}

METHOD(tls_socket_t, get_fd, int,
	private_tls_socket_t *this)
{
	return this->fd;
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
							identification_t *peer, int fd, tls_cache_t *cache)
{
	private_tls_socket_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.write = _write_,
			.splice = _splice,
			.get_fd = _get_fd,
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
						   &this->app.application, cache);
	if (!this->tls)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
