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
#include <errno.h>
#include <unistd.h>
#include <limits.h>

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

METHOD(stream_t, read_all, bool,
	private_stream_t *this, void *buf, size_t len)
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

METHOD(stream_t, write_all, bool,
	private_stream_t *this, void *buf, size_t len)
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
static void remove_watcher(private_stream_t *this)
{
	if (this->read_cb || this->write_cb)
	{
		lib->watcher->remove(lib->watcher, this->fd);
	}
}

/**
 * Watcher callback
 */
static bool watch(private_stream_t *this, int fd, watcher_event_t event)
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
static void add_watcher(private_stream_t *this)
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
	private_stream_t *this, stream_cb_t cb, void *data)
{
	remove_watcher(this);

	this->read_cb = cb;
	this->read_data = data;

	add_watcher(this);
}

METHOD(stream_t, on_write, void,
	private_stream_t *this, stream_cb_t cb, void *data)
{
	remove_watcher(this);

	this->write_cb = cb;
	this->write_data = data;

	add_watcher(this);
}

METHOD(stream_t, get_file, FILE*,
	private_stream_t *this)
{
	FILE *file;
	int fd;

	/* fclose() closes the FD passed to fdopen(), so dup() it */
	fd = dup(this->fd);
	if (fd == -1)
	{
		return NULL;
	}
	file = fdopen(fd, "w+");
	if (!file)
	{
		close(fd);
	}
	return file;
}

METHOD(stream_t, destroy, void,
	private_stream_t *this)
{
	remove_watcher(this);
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
			.read_all = _read_all,
			.on_read = _on_read,
			.write = _write_,
			.write_all = _write_all,
			.on_write = _on_write,
			.get_file = _get_file,
			.destroy = _destroy,
		},
		.fd = fd,
	);

	return &this->public;
}

/**
 * See header
 */
int stream_parse_uri_unix(char *uri, struct sockaddr_un *addr)
{
	if (!strpfx(uri, "unix://"))
	{
		return -1;
	}
	uri += strlen("unix://");

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, uri, sizeof(addr->sun_path));
	addr->sun_path[sizeof(addr->sun_path)-1] = '\0';

	return offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path);
}

/**
 * See header
 */
stream_t *stream_create_unix(char *uri)
{
	struct sockaddr_un addr;
	int len, fd;

	len = stream_parse_uri_unix(uri, &addr);
	if (len == -1)
	{
		DBG1(DBG_NET, "invalid stream URI: '%s'", uri);
		return NULL;
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
	{
		DBG1(DBG_NET, "opening socket '%s' failed: %s", uri, strerror(errno));
		return NULL;
	}
	if (connect(fd, (struct sockaddr*)&addr, len) < 0)
	{
		DBG1(DBG_NET, "connecting to '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	return stream_create_from_fd(fd);
}

/**
 * See header.
 */
int stream_parse_uri_tcp(char *uri, struct sockaddr *addr)
{
	char *pos, buf[128];
	host_t *host;
	u_long port;
	int len;

	if (!strpfx(uri, "tcp://"))
	{
		return -1;
	}
	uri += strlen("tcp://");
	pos = strrchr(uri, ':');
	if (!pos)
	{
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
		return -1;
	}
	host = host_create_from_dns(buf, AF_UNSPEC, port);
	if (!host)
	{
		return -1;
	}
	len = *host->get_sockaddr_len(host);
	memcpy(addr, host->get_sockaddr(host), len);
	host->destroy(host);
	return len;
}

/**
 * See header
 */
stream_t *stream_create_tcp(char *uri)
{
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr sa;
	} addr;
	int fd, len;

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
	if (connect(fd, &addr.sa, len))
	{
		DBG1(DBG_NET, "connecting to '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	return stream_create_from_fd(fd);
}
