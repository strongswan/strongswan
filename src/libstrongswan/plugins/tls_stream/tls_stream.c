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

#define _GNU_SOURCE
#include <stdio.h>

#include "tls_stream.h"

#include <tls_socket.h>

#include <errno.h>
#include <unistd.h>
#include <limits.h>

typedef struct private_tls_stream_t private_tls_stream_t;

/**
 * Private data of an tls_stream_t object.
 */
struct private_tls_stream_t {

	/**
	 * Public tls_stream_t interface.
	 */
	stream_t public;

	/**
	 * Underlying TLS socket.
	 */
	tls_socket_t *tls;

	/**
	 * FD for encrypted data
	 */
	int fd;

	/**
	 * Callback if data is ready to read
	 */
	stream_cb_t read_cb;

	/**
	 * Data for read-ready callback
	 */
	void *read_data;

	/**
	 * Callback if write is non-blocking
	 */
	stream_cb_t write_cb;

	/**
	 * Data for write-ready callback
	 */
	void *write_data;
};

METHOD(stream_t, read_, ssize_t,
	private_tls_stream_t *this, void *buf, size_t len, bool block)
{
	return this->tls->read(this->tls, buf, len, block);
}

METHOD(stream_t, read_all, bool,
	private_tls_stream_t *this, void *buf, size_t len)
{
	ssize_t ret;

	while (len)
	{
		ret = read_(this, buf, len, TRUE);
		if (ret < 0)
		{
			return FALSE;
		}
		if (ret == 0)
		{
			errno = ECONNRESET;
			return FALSE;
		}
		len -= ret;
		buf += ret;
	}
	return TRUE;
}

METHOD(stream_t, write_, ssize_t,
	private_tls_stream_t *this, void *buf, size_t len, bool block)
{
	return this->tls->write(this->tls, buf, len);
}

METHOD(stream_t, write_all, bool,
	private_tls_stream_t *this, void *buf, size_t len)
{
	ssize_t ret;

	while (len)
	{
		ret = write_(this, buf, len, TRUE);
		if (ret < 0)
		{
			return FALSE;
		}
		if (ret == 0)
		{
			errno = ECONNRESET;
			return FALSE;
		}
		len -= ret;
		buf += ret;
	}
	return TRUE;
}

/**
 * Remove a registered watcher
 */
static void remove_watcher(private_tls_stream_t *this)
{
	if (this->read_cb || this->write_cb)
	{
		lib->watcher->remove(lib->watcher, this->fd);
	}
}

/**
 * Watcher callback
 */
static bool watch(private_tls_stream_t *this, int fd, watcher_event_t event)
{
	bool keep = FALSE;
	stream_cb_t cb;

	switch (event)
	{
		case WATCHER_READ:
			cb = this->read_cb;
			this->read_cb = NULL;
			keep = cb(this->read_data, &this->public);
			if (keep)
			{
				this->read_cb = cb;
			}
			break;
		case WATCHER_WRITE:
			cb = this->write_cb;
			this->write_cb = NULL;
			keep = cb(this->write_data, &this->public);
			if (keep)
			{
				this->write_cb = cb;
			}
			break;
		case WATCHER_EXCEPT:
			break;
	}
	return keep;
}

/**
 * Register watcher for stream callbacks
 */
static void add_watcher(private_tls_stream_t *this)
{
	watcher_event_t events = 0;

	if (this->read_cb)
	{
		events |= WATCHER_READ;
	}
	if (this->write_cb)
	{
		events |= WATCHER_WRITE;
	}
	if (events)
	{
		lib->watcher->add(lib->watcher, this->fd, events,
						  (watcher_cb_t)watch, this);
	}
}

METHOD(stream_t, on_read, void,
	private_tls_stream_t *this, stream_cb_t cb, void *data)
{
	remove_watcher(this);

	this->read_cb = cb;
	this->read_data = data;

	add_watcher(this);
}

METHOD(stream_t, on_write, void,
	private_tls_stream_t *this, stream_cb_t cb, void *data)
{
	remove_watcher(this);

	this->write_cb = cb;
	this->write_data = data;

	add_watcher(this);
}

#if defined(HAVE_FOPENCOOKIE)

/**
 * Read callback for fopencookie()
 */
static ssize_t cookie_read(private_tls_stream_t *this, char *buf, size_t len)
{
	return this->tls->read(this->tls, buf, len, TRUE);
}

/**
 * Write callback for fopencookie()
 */
static ssize_t cookie_write(private_tls_stream_t *this, char *buf, size_t len)
{
	return this->tls->write(this->tls, buf, len);
}

METHOD(stream_t, get_file, FILE*,
	private_tls_stream_t *this)
{
	static cookie_io_functions_t cookie_funcs = {
		.read = (void*)cookie_read,
		.write = (void*)cookie_write,
		.seek = NULL,
		.close = NULL,
	};
	return fopencookie(this, "r+", cookie_funcs);
}

#elif defined(HAVE_FUNOPEN)

/**
 * Read callback for funopen()
 */
static int fun_read(private_tls_stream_t *this, char *buf, int len)
{
	return this->tls->read(this->tls, buf, len, TRUE);
}

/**
 * Write callback for funopen()
 */
static int fun_write(private_tls_stream_t *this, char *buf, int len)
{
	return this->tls->write(this->tls, buf, len);
}

METHOD(stream_t, get_file, FILE*,
	private_tls_stream_t *this)
{
	return funopen(this, (void*)fun_read, (void*)fun_write, NULL, NULL);
}

#else /* !HAVE_FOPENCOOKIE && !HAVE_FUNOPEN */

METHOD(stream_t, get_file, FILE*,
	private_tls_stream_t *this)
{
	return NULL;
}

#endif /* HAVE_FOPENCOOKIE/HAVE_FUNOPEN */

METHOD(stream_t, destroy, void,
	private_tls_stream_t *this)
{
	this->tls->destroy(this->tls);
	close(this->fd);
	free(this);
}

/**
 * See header
 */
stream_t *tls_stream_create_from_fd(int fd, bool is_server,
									identification_t *server,
									tls_cache_t *cache)
{
	private_tls_stream_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.read_all = _read_all,
			.on_read = _on_read,
			.write = _write_,
			.write_all = _write_all,
			.on_write = _on_write,
			.get_file = _get_file,
			.destroy = _destroy,
		},
		.tls = tls_socket_create(is_server, server, NULL, fd, cache),
		.fd = fd,
	);

	if (!this->tls)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

/**
 * See header.
 */
int tls_stream_parse_uri(char *uri, struct sockaddr *addr,
						 identification_t **server)
{
	identification_t *id;
	char *pos, buf[256];
	host_t *host;
	u_long port;
	int len;

	if (!strncaseeq(uri, "tcp+tls://", strlen("tcp+tls://")))
	{
		return -1;
	}
	uri += strlen("tcp+tls://");
	pos = strrchr(uri, '@');
	if (!pos)
	{
		return -1;
	}
	id = identification_create_from_data(chunk_create(uri, pos - uri));
	uri = pos + 1;
	pos = strrchr(uri, ':');
	if (!pos)
	{
		id->destroy(id);
		return -1;
	}
	if (*uri == '[' && pos > uri && *(pos - 1) == ']')
	{
		/* IPv6 URI */
		snprintf(buf, sizeof(buf), "%.*s", (int)(pos - uri - 2), uri + 1);
	}
	else
	{
		snprintf(buf, sizeof(buf), "%.*s", (int)(pos - uri), uri);
	}
	port = strtoul(pos + 1, &pos, 10);
	if (port == ULONG_MAX || *pos || port > 65535)
	{
		id->destroy(id);
		return -1;
	}
	host = host_create_from_dns(buf, AF_UNSPEC, port);
	if (!host)
	{
		id->destroy(id);
		return -1;
	}
	len = *host->get_sockaddr_len(host);
	memcpy(addr, host->get_sockaddr(host), len);
	host->destroy(host);
	*server = id;
	return len;
}

/**
 * See header
 */
stream_t *tls_stream_create(char *uri)
{
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr sa;
	} addr;
	int fd, len;
	identification_t *server;
	stream_t *stream;

	len = tls_stream_parse_uri(uri, &addr.sa, &server);
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
	if (connect(fd, &addr.sa, len))
	{
		DBG1(DBG_NET, "connecting to '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	stream = tls_stream_create_from_fd(fd, FALSE, server, NULL);
	server->destroy(server);
	if (!stream)
	{
		close(fd);
	}
	return stream;
}
