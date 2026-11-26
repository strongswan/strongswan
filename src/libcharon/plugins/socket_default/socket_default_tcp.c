/*
 * Copyright (C) 2026 Simone Tilia
 *
 * Copyright (C) secunet Security Networks AG
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

#include "socket_default_tcp.h"

#ifdef __linux__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <daemon.h>
#include <collections/hashtable.h>
#include <collections/array.h>
#include <threading/mutex.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

/**
 * Stream prefix sent by the TCP Originator (RFC 9329, section 4)
 */
#define IKETCP_PREFIX "IKETCP"
#define IKETCP_PREFIX_LEN 6

/**
 * Close accepted connections without references after this many seconds of
 * inactivity (RFC 9329, section 6.3.1 suggests 5-10 seconds for half-open
 * connections, we allow some more for slow peers)
 */
#define IDLE_TIMEOUT 15

/**
 * Close our own connections this many seconds after the last IKE_SA released
 * them, so queued messages (e.g. a DELETE response) are still sent
 * (RFC 9329, section 6.1: the TCP Originator closes the connection)
 */
#define RELEASE_GRACE 2

/**
 * Maximum number of packets queued while a connection is being established
 */
#define MAX_QUEUED 16

typedef struct private_socket_default_tcp_t private_socket_default_tcp_t;
typedef struct tcp_conn_t tcp_conn_t;

/**
 * State of a TCP connection
 */
typedef enum {
	/** originator, connect() in progress */
	CONN_CONNECTING,
	/** responder, waiting for the stream prefix */
	CONN_PREFIX,
	/** espintcp attached, messages can be exchanged */
	CONN_ESTABLISHED,
	/** socket closed, originators reconnect when sending */
	CONN_CLOSED,
} tcp_state_t;

ENUM(tcp_state_names, CONN_CONNECTING, CONN_CLOSED,
	"CONNECTING",
	"PREFIX",
	"ESTABLISHED",
	"CLOSED",
);

/**
 * A TCP connection
 */
struct tcp_conn_t {

	/** unique identifier */
	uint32_t id;

	/** socket, -1 if closed */
	int fd;

	/** current state */
	tcp_state_t state;

	/** TRUE if we opened the connection (TCP Originator) */
	bool originator;

	/** local address the connection is bound to, NULL if unknown */
	host_t *local;

	/** remote address of the connection */
	host_t *remote;

	/** number of references held by IKE_SAs */
	u_int refs;

	/** time of the last activity, for idle connections without references */
	time_t last_use;

	/** number of prefix bytes received (responder) */
	u_int prefix_len;

	/** prefix bytes received (responder) */
	char prefix[IKETCP_PREFIX_LEN];

	/** packet data (chunk_t*) queued while connecting */
	array_t *queue;
};

/**
 * Private data
 */
struct private_socket_default_tcp_t {

	/** public interface */
	socket_default_tcp_t public;

	/** listening sockets, -1 if not used */
	int listen4, listen6;

	/** listening port */
	uint16_t port;

	/** maximum message size */
	int max_packet;

	/** connections, tcp_conn_t indexed by identifier */
	hashtable_t *conns;

	/** next connection identifier to assign */
	uint32_t next_id;

	/** lock for conns and the connection objects */
	mutex_t *mutex;

	/** pipe to wake up the receiving thread [read, write] */
	int notify[2];

	/** connection identifiers matching the last prepared poll entries */
	uint32_t *poll_ids;

	/** allocated size of poll_ids */
	u_int poll_ids_size;
};

/**
 * Wake up the receiving thread to update the poll set
 */
static void notify_receiver(private_socket_default_tcp_t *this)
{
	char c = 0;

	if (write(this->notify[1], &c, 1) < 0 && errno != EAGAIN)
	{
		DBG1(DBG_NET, "waking up TCP receiver failed: %s", strerror(errno));
	}
}

/**
 * Destroy a queued chunk
 */
static void destroy_queued(void *data, int idx, void *user)
{
	chunk_t *chunk = data;

	chunk_free(chunk);
	free(chunk);
}

/**
 * Close the socket of a connection, mutex must be held
 */
static void close_conn(tcp_conn_t *conn, const char *reason)
{
	if (conn->fd != -1)
	{
		DBG1(DBG_NET, "closing TCP connection %u %#H - %#H (%s)", conn->id,
			 conn->local, conn->remote, reason);
		close(conn->fd);
		conn->fd = -1;
	}
	conn->state = CONN_CLOSED;
	array_destroy_function(conn->queue, destroy_queued, NULL);
	conn->queue = NULL;
}

/**
 * Destroy a connection object, mutex must be held, socket must be closed
 */
static void destroy_conn(private_socket_default_tcp_t *this, tcp_conn_t *conn)
{
	this->conns->remove(this->conns, (void*)(uintptr_t)conn->id);
	array_destroy_function(conn->queue, destroy_queued, NULL);
	DESTROY_IF(conn->local);
	DESTROY_IF(conn->remote);
	free(conn);
}

/**
 * Get a connection by identifier, mutex must be held
 */
static tcp_conn_t *get_conn(private_socket_default_tcp_t *this, uint32_t id)
{
	return this->conns->get(this->conns, (void*)(uintptr_t)id);
}

/**
 * Register a new connection, mutex must be held
 */
static tcp_conn_t *add_conn(private_socket_default_tcp_t *this, int fd,
							tcp_state_t state, bool originator, host_t *local,
							host_t *remote)
{
	tcp_conn_t *conn;

	do
	{
		this->next_id++;
	}
	while (!this->next_id || get_conn(this, this->next_id));

	INIT(conn,
		.id = this->next_id,
		.fd = fd,
		.state = state,
		.originator = originator,
		.local = local,
		.remote = remote,
		.last_use = time_monotonic(NULL),
	);
	this->conns->put(this->conns, (void*)(uintptr_t)conn->id, conn);
	return conn;
}

/**
 * Apply common socket options
 */
static void setup_socket(int fd, int family)
{
	int on = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set TCP_NODELAY: %s", strerror(errno));
	}
#ifdef SO_MARK
	{	/* set optional MARK on socket (requires CAP_NET_ADMIN) */
		char *fwmark;
		mark_t mark;

		fwmark = lib->settings->get_str(lib->settings,
							"%s.plugins.socket-default.fwmark", NULL, lib->ns);
		if (fwmark && mark_from_string(fwmark, MARK_OP_NONE, &mark))
		{
			if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark.value,
						   sizeof(mark.value)) < 0)
			{
				DBG1(DBG_NET, "unable to set SO_MARK on TCP socket: %s",
					 strerror(errno));
			}
		}
	}
#endif
	if (!charon->kernel->bypass_socket(charon->kernel, fd, family))
	{
		DBG1(DBG_NET, "installing IKE bypass policy on TCP socket failed");
	}
}

/**
 * Attach the espintcp ULP to a connected socket
 */
static bool attach_espintcp(tcp_conn_t *conn)
{
	if (setsockopt(conn->fd, IPPROTO_TCP, TCP_ULP, "espintcp",
				   sizeof("espintcp")) < 0)
	{
		DBG1(DBG_NET, "enabling espintcp on TCP connection %u failed: %s "
			 "(kernel without CONFIG_INET_ESPINTCP?)", conn->id,
			 strerror(errno));
		return FALSE;
	}
	conn->state = CONN_ESTABLISHED;
	DBG1(DBG_NET, "TCP connection %u %#H - %#H established", conn->id,
		 conn->local, conn->remote);
	return TRUE;
}

/**
 * Write a message to an established connection, mutex must be held
 */
static bool write_conn(tcp_conn_t *conn, chunk_t data)
{
	ssize_t len;

	len = send(conn->fd, data.ptr, data.len, MSG_DONTWAIT);
	if (len != data.len)
	{
		DBG1(DBG_NET, "error writing to TCP connection %u: %s", conn->id,
			 len < 0 ? strerror(errno) : "short write");
		return FALSE;
	}
	return TRUE;
}

/**
 * Open a socket and start connecting, mutex must be held
 */
static bool start_connect(private_socket_default_tcp_t *this, tcp_conn_t *conn,
						  host_t *src)
{
	host_t *local;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
	socklen_t addrlen = sizeof(addr);
	int fd, family;

	family = conn->remote->get_family(conn->remote);
	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				IPPROTO_TCP);
	if (fd < 0)
	{
		DBG1(DBG_NET, "could not open TCP socket: %s", strerror(errno));
		return FALSE;
	}
	setup_socket(fd, family);

	if (src && !src->is_anyaddr(src) && src->get_family(src) == family)
	{
		local = src->clone(src);
		local->set_port(local, 0);
		if (bind(fd, local->get_sockaddr(local),
				 *local->get_sockaddr_len(local)) < 0)
		{
			DBG1(DBG_NET, "unable to bind TCP socket to %H: %s", local,
				 strerror(errno));
		}
		local->destroy(local);
	}
	if (connect(fd, conn->remote->get_sockaddr(conn->remote),
				*conn->remote->get_sockaddr_len(conn->remote)) < 0 &&
		errno != EINPROGRESS)
	{
		DBG1(DBG_NET, "connecting to %#H over TCP failed: %s", conn->remote,
			 strerror(errno));
		close(fd);
		return FALSE;
	}
	if (getsockname(fd, &addr.sa, &addrlen) < 0)
	{
		DBG1(DBG_NET, "unable to get local TCP address: %s", strerror(errno));
		close(fd);
		return FALSE;
	}
	DESTROY_IF(conn->local);
	conn->local = host_create_from_sockaddr(&addr.sa);
	conn->fd = fd;
	conn->state = CONN_CONNECTING;
	conn->queue = array_create(0, 0);
	conn->last_use = time_monotonic(NULL);
	DBG1(DBG_NET, "connecting TCP connection %u %#H - %#H", conn->id,
		 conn->local, conn->remote);
	notify_receiver(this);
	return TRUE;
}

METHOD(socket_default_tcp_t, connect_, bool,
	private_socket_default_tcp_t *this, host_t *src, host_t *dst,
	host_t **local, uint32_t *id)
{
	tcp_conn_t *conn;

	this->mutex->lock(this->mutex);
	conn = add_conn(this, -1, CONN_CLOSED, TRUE, NULL, dst->clone(dst));
	conn->refs = 1;
	if (!start_connect(this, conn, src))
	{
		destroy_conn(this, conn);
		this->mutex->unlock(this->mutex);
		return FALSE;
	}
	*local = conn->local->clone(conn->local);
	*id = conn->id;
	this->mutex->unlock(this->mutex);
	return TRUE;
}

METHOD(socket_default_tcp_t, acquire, bool,
	private_socket_default_tcp_t *this, uint32_t id)
{
	tcp_conn_t *conn;

	this->mutex->lock(this->mutex);
	conn = get_conn(this, id);
	if (conn)
	{
		conn->refs++;
	}
	this->mutex->unlock(this->mutex);
	return conn != NULL;
}

METHOD(socket_default_tcp_t, release, void,
	private_socket_default_tcp_t *this, uint32_t id)
{
	tcp_conn_t *conn;

	this->mutex->lock(this->mutex);
	conn = get_conn(this, id);
	if (conn && conn->refs && --conn->refs == 0)
	{
		conn->last_use = time_monotonic(NULL);
		if (conn->fd == -1)
		{
			destroy_conn(this, conn);
		}
		else
		{	/* closed by the receiving thread after a grace period, so queued
			 * messages (e.g. errors or the DELETE response) are still sent */
			notify_receiver(this);
		}
	}
	this->mutex->unlock(this->mutex);
}

METHOD(socket_default_tcp_t, send_, status_t,
	private_socket_default_tcp_t *this, packet_t *packet, uint32_t id)
{
	tcp_conn_t *conn;
	chunk_t data, *queued;
	status_t status = FAILED;

	data = packet->get_data(packet);
	if (data.len > 0xFFFF - 2)
	{
		DBG1(DBG_NET, "message too large for TCP encapsulation (%zu bytes)",
			 data.len);
		return FAILED;
	}

	this->mutex->lock(this->mutex);
	conn = get_conn(this, id);
	if (!conn)
	{
		DBG1(DBG_NET, "TCP connection %u not found, dropping packet to %#H",
			 id, packet->get_destination(packet));
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	conn->last_use = time_monotonic(NULL);
	if (conn->state == CONN_CLOSED && conn->originator)
	{	/* RFC 9329, section 6.1: only the TCP Originator re-establishes */
		DBG1(DBG_NET, "re-establishing TCP connection %u to %#H", conn->id,
			 conn->remote);
		start_connect(this, conn, conn->local);
	}
	DBG2(DBG_NET, "sending packet over TCP connection %u (%s): from %#H to "
		 "%#H", conn->id, enum_to_name(tcp_state_names, conn->state),
		 conn->local, conn->remote);
	switch (conn->state)
	{
		case CONN_ESTABLISHED:
			if (write_conn(conn, data))
			{
				status = SUCCESS;
			}
			break;
		case CONN_CONNECTING:
			if (array_count(conn->queue) < MAX_QUEUED)
			{
				INIT(queued);
				*queued = chunk_clone(data);
				array_insert(conn->queue, ARRAY_TAIL, queued);
				status = SUCCESS;
			}
			break;
		case CONN_PREFIX:
		case CONN_CLOSED:
			DBG1(DBG_NET, "TCP connection %u to %#H is not established, "
				 "dropping packet", conn->id, conn->remote);
			break;
	}
	this->mutex->unlock(this->mutex);
	return status;
}

/**
 * Accept a connection on a listening socket
 */
static void accept_conn(private_socket_default_tcp_t *this, int listener)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} local, remote;
	socklen_t len = sizeof(remote);
	tcp_conn_t *conn;
	int fd;

	fd = accept4(listener, &remote.sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			DBG1(DBG_NET, "accepting TCP connection failed: %s",
				 strerror(errno));
		}
		return;
	}
	len = sizeof(local);
	if (getsockname(fd, &local.sa, &len) < 0)
	{
		DBG1(DBG_NET, "unable to get local TCP address: %s", strerror(errno));
		close(fd);
		return;
	}
	setup_socket(fd, remote.sa.sa_family);

	this->mutex->lock(this->mutex);
	conn = add_conn(this, fd, CONN_PREFIX, FALSE,
					host_create_from_sockaddr(&local.sa),
					host_create_from_sockaddr(&remote.sa));
	DBG1(DBG_NET, "accepted TCP connection %u %#H - %#H", conn->id,
		 conn->local, conn->remote);
	this->mutex->unlock(this->mutex);
}

/**
 * Complete a pending connect() as originator, mutex must be held
 */
static void complete_connect(tcp_conn_t *conn)
{
	chunk_t *queued;
	socklen_t len = sizeof(int);
	int err = 0;

	if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
	{
		err = errno;
	}
	if (err)
	{
		DBG1(DBG_NET, "connecting to %#H over TCP failed: %s", conn->remote,
			 strerror(err));
		close_conn(conn, "connect failed");
		return;
	}
	/* RFC 9329, section 4: the stream starts with the prefix, it is sent
	 * before espintcp takes over the framing */
	if (send(conn->fd, IKETCP_PREFIX, IKETCP_PREFIX_LEN, MSG_DONTWAIT) !=
			IKETCP_PREFIX_LEN)
	{
		DBG1(DBG_NET, "sending TCP stream prefix failed: %s", strerror(errno));
		close_conn(conn, "prefix failed");
		return;
	}
	if (!attach_espintcp(conn))
	{
		close_conn(conn, "espintcp failed");
		return;
	}
	while (array_remove(conn->queue, ARRAY_HEAD, &queued))
	{
		write_conn(conn, *queued);
		chunk_free(queued);
		free(queued);
	}
}

/**
 * Read the stream prefix as responder, mutex must be held
 */
static void read_prefix(tcp_conn_t *conn)
{
	ssize_t len;

	len = recv(conn->fd, conn->prefix + conn->prefix_len,
			   IKETCP_PREFIX_LEN - conn->prefix_len, MSG_DONTWAIT);
	if (len == 0)
	{
		close_conn(conn, "closed by peer");
		return;
	}
	if (len < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			close_conn(conn, strerror(errno));
		}
		return;
	}
	conn->prefix_len += len;
	if (!memeq(conn->prefix, IKETCP_PREFIX, conn->prefix_len))
	{
		close_conn(conn, "invalid stream prefix");
		return;
	}
	if (conn->prefix_len == IKETCP_PREFIX_LEN && !attach_espintcp(conn))
	{
		close_conn(conn, "espintcp failed");
	}
}

/**
 * Read a message from an established connection, mutex must be held
 */
static packet_t *read_message(private_socket_default_tcp_t *this,
							  tcp_conn_t *conn)
{
	char buffer[this->max_packet];
	struct msghdr msg = {};
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = sizeof(buffer),
	};
	packet_t *packet;
	ssize_t len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	len = recvmsg(conn->fd, &msg, MSG_DONTWAIT);
	if (len == 0)
	{
		close_conn(conn, "closed by peer");
		return NULL;
	}
	if (len < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			close_conn(conn, strerror(errno));
		}
		return NULL;
	}
	if (msg.msg_flags & MSG_TRUNC)
	{
		DBG1(DBG_NET, "receive buffer too small, TCP message discarded");
		return NULL;
	}
	conn->last_use = time_monotonic(NULL);

	packet = packet_create();
	packet->set_source(packet, conn->remote->clone(conn->remote));
	packet->set_destination(packet, conn->local->clone(conn->local));
	packet->set_data(packet, chunk_clone(chunk_create(buffer, len)));
	packet_set_tcp_conn(packet, conn->id);
	DBG2(DBG_NET, "received packet over TCP connection %u: from %#H to %#H",
		 conn->id, conn->remote, conn->local);
	return packet;
}

/**
 * Add an entry to the poll array
 */
static void add_pollfd(private_socket_default_tcp_t *this, struct pollfd **pfd,
					   u_int *size, u_int *count, u_int *ids, int fd,
					   short events, uint32_t id)
{
	if (*count >= *size)
	{
		*size = max(*size * 2, 16);
		*pfd = realloc(*pfd, *size * sizeof(struct pollfd));
	}
	if (*ids >= this->poll_ids_size)
	{
		this->poll_ids_size = max(this->poll_ids_size * 2, 16);
		this->poll_ids = realloc(this->poll_ids,
								 this->poll_ids_size * sizeof(uint32_t));
	}
	(*pfd)[*count] = (struct pollfd){
		.fd = fd,
		.events = events,
	};
	this->poll_ids[*ids] = id;
	(*count)++;
	(*ids)++;
}

METHOD(socket_default_tcp_t, prepare_poll, int,
	private_socket_default_tcp_t *this, struct pollfd **pfd, u_int *size,
	u_int *count)
{
	enumerator_t *enumerator;
	tcp_conn_t *conn;
	time_t now;
	u_int ids = 0;
	int timeout = -1;

	/* listening sockets and the notification pipe use identifier 0 */
	add_pollfd(this, pfd, size, count, &ids, this->notify[0], POLLIN, 0);
	if (this->listen4 != -1)
	{
		add_pollfd(this, pfd, size, count, &ids, this->listen4, POLLIN, 0);
	}
	if (this->listen6 != -1)
	{
		add_pollfd(this, pfd, size, count, &ids, this->listen6, POLLIN, 0);
	}

	now = time_monotonic(NULL);
	this->mutex->lock(this->mutex);
	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, NULL, &conn))
	{
		if (!conn->refs && now - conn->last_use >=
				(conn->originator ? RELEASE_GRACE : IDLE_TIMEOUT))
		{
			close_conn(conn, "idle without IKE_SA");
			this->conns->remove_at(this->conns, enumerator);
			DESTROY_IF(conn->local);
			DESTROY_IF(conn->remote);
			free(conn);
			continue;
		}
		if (!conn->refs)
		{	/* check again once the connection might be idle */
			timeout = 1000;
		}
		switch (conn->state)
		{
			case CONN_CONNECTING:
				add_pollfd(this, pfd, size, count, &ids, conn->fd, POLLOUT,
						   conn->id);
				break;
			case CONN_PREFIX:
			case CONN_ESTABLISHED:
				add_pollfd(this, pfd, size, count, &ids, conn->fd, POLLIN,
						   conn->id);
				break;
			case CONN_CLOSED:
				break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return timeout;
}

METHOD(socket_default_tcp_t, process_poll, packet_t*,
	private_socket_default_tcp_t *this, struct pollfd *pfd, u_int count)
{
	packet_t *packet = NULL;
	tcp_conn_t *conn;
	char buf[32];
	u_int i;

	for (i = 0; i < count; i++)
	{
		if (!pfd[i].revents)
		{
			continue;
		}
		if (!this->poll_ids[i])
		{
			if (pfd[i].fd == this->notify[0])
			{
				while (read(this->notify[0], buf, sizeof(buf)) > 0)
				{
					/* drain */
				}
			}
			else
			{
				accept_conn(this, pfd[i].fd);
			}
			continue;
		}
		this->mutex->lock(this->mutex);
		conn = get_conn(this, this->poll_ids[i]);
		if (conn && conn->fd == pfd[i].fd)
		{
			switch (conn->state)
			{
				case CONN_CONNECTING:
					complete_connect(conn);
					break;
				case CONN_PREFIX:
					read_prefix(conn);
					break;
				case CONN_ESTABLISHED:
					if (!packet)
					{	/* return one message per call, others are received
						 * in the next round */
						packet = read_message(this, conn);
					}
					break;
				case CONN_CLOSED:
					break;
			}
			if (conn->state == CONN_CLOSED && !conn->refs)
			{
				destroy_conn(this, conn);
			}
		}
		this->mutex->unlock(this->mutex);
	}
	return packet;
}

/**
 * Open a listening socket
 */
static int open_listener(private_socket_default_tcp_t *this, int family)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr = {};
	socklen_t addrlen;
	int fd, on = 1;

	switch (family)
	{
		case AF_INET:
			if (!lib->settings->get_bool(lib->settings,
						"%s.plugins.socket-default.use_ipv4", TRUE, lib->ns))
			{
				return -1;
			}
			addr.sin.sin_family = AF_INET;
			addr.sin.sin_port = htons(this->port);
			addrlen = sizeof(addr.sin);
			break;
		case AF_INET6:
			if (!lib->settings->get_bool(lib->settings,
						"%s.plugins.socket-default.use_ipv6", TRUE, lib->ns))
			{
				return -1;
			}
			addr.sin6.sin6_family = AF_INET6;
			addr.sin6.sin6_port = htons(this->port);
			addrlen = sizeof(addr.sin6);
			break;
		default:
			return -1;
	}
	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				IPPROTO_TCP);
	if (fd < 0)
	{
		DBG1(DBG_NET, "could not open TCP socket: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 ||
		(family == AF_INET6 &&
		 setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0))
	{
		DBG1(DBG_NET, "unable to set TCP socket options: %s", strerror(errno));
		close(fd);
		return -1;
	}
	if (bind(fd, &addr.sa, addrlen) < 0 || listen(fd, 64) < 0)
	{
		DBG1(DBG_NET, "unable to listen on TCP port %u: %s", this->port,
			 strerror(errno));
		close(fd);
		return -1;
	}
	setup_socket(fd, family);
	DBG1(DBG_NET, "listening for TCP encapsulated IKE on %s port %u",
		 family == AF_INET ? "IPv4" : "IPv6", this->port);
	return fd;
}

METHOD(socket_default_tcp_t, destroy, void,
	private_socket_default_tcp_t *this)
{
	enumerator_t *enumerator;
	tcp_conn_t *conn;

	enumerator = this->conns->create_enumerator(this->conns);
	while (enumerator->enumerate(enumerator, NULL, &conn))
	{
		close_conn(conn, "shutdown");
		DESTROY_IF(conn->local);
		DESTROY_IF(conn->remote);
		free(conn);
	}
	enumerator->destroy(enumerator);
	this->conns->destroy(this->conns);
	if (this->listen4 != -1)
	{
		close(this->listen4);
	}
	if (this->listen6 != -1)
	{
		close(this->listen6);
	}
	close(this->notify[0]);
	close(this->notify[1]);
	this->mutex->destroy(this->mutex);
	free(this->poll_ids);
	free(this);
}

/*
 * Described in header
 */
socket_default_tcp_t *socket_default_tcp_create(uint16_t port, int max_packet)
{
	private_socket_default_tcp_t *this;

	INIT(this,
		.public = {
			.prepare_poll = _prepare_poll,
			.process_poll = _process_poll,
			.send = _send_,
			.connect = _connect_,
			.acquire = _acquire,
			.release = _release,
			.destroy = _destroy,
		},
		.listen4 = -1,
		.listen6 = -1,
		.port = port,
		.max_packet = max_packet,
		.conns = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 8),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (pipe2(this->notify, O_NONBLOCK | O_CLOEXEC) < 0)
	{
		DBG1(DBG_NET, "unable to create TCP notification pipe: %s",
			 strerror(errno));
		this->conns->destroy(this->conns);
		this->mutex->destroy(this->mutex);
		free(this);
		return NULL;
	}
	if (this->port)
	{
		this->listen4 = open_listener(this, AF_INET);
		this->listen6 = open_listener(this, AF_INET6);
	}
	return &this->public;
}

#else /* __linux__ */

socket_default_tcp_t *socket_default_tcp_create(uint16_t port, int max_packet)
{
	return NULL;
}

#endif /* __linux__ */
