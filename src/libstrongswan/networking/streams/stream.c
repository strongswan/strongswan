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

#include "stream.h"

#include <errno.h>
#include <unistd.h>

typedef struct private_stream_t private_stream_t;

/**
 * Private data of an stream_t object.
 */
struct private_stream_t {

	/**
	 * Public stream_t interface.
	 */
	stream_t public;

	/**
	 * Underlying socket
	 */
	int fd;
};

METHOD(stream_t, read_, ssize_t,
	private_stream_t *this, void *buf, size_t len, bool block)
{
	while (TRUE)
	{
		ssize_t ret;

		if (block)
		{
			ret = read(this->fd, buf, len);
		}
		else
		{
			ret = recv(this->fd, buf, len, MSG_DONTWAIT);
			if (ret == -1 && errno == EAGAIN)
			{
				/* unify EGAIN and EWOULDBLOCK */
				errno = EWOULDBLOCK;
			}
		}
		if (ret == -1 && errno == EINTR)
		{	/* interrupted, try again */
			continue;
		}
		return ret;
	}
}

METHOD(stream_t, write_, ssize_t,
	private_stream_t *this, void *buf, size_t len, bool block)
{
	ssize_t ret;

	while (TRUE)
	{
		if (block)
		{
			ret = write(this->fd, buf, len);
		}
		else
		{
			ret = send(this->fd, buf, len, MSG_DONTWAIT);
			if (ret == -1 && errno == EAGAIN)
			{
				/* unify EGAIN and EWOULDBLOCK */
				errno = EWOULDBLOCK;
			}
		}
		if (ret == -1 && errno == EINTR)
		{	/* interrupted, try again */
			continue;
		}
		return ret;
	}
}

METHOD(stream_t, destroy, void,
	private_stream_t *this)
{
	close(this->fd);
	free(this);
}

/**
 * See header
 */
stream_t *stream_create_from_fd(int fd)
{
	private_stream_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.write = _write_,
			.destroy = _destroy,
		},
		.fd = fd,
	);

	return &this->public;
}
