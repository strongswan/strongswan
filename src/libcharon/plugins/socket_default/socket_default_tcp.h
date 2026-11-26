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

/**
 * @defgroup socket_default_tcp socket_default_tcp
 * @{ @ingroup socket_default
 */

#ifndef SOCKET_DEFAULT_TCP_H_
#define SOCKET_DEFAULT_TCP_H_

typedef struct socket_default_tcp_t socket_default_tcp_t;

#include <poll.h>

#include <library.h>
#include <networking/packet.h>

/**
 * TCP encapsulation of IKE and ESP packets (RFC 9329) using the Linux
 * espintcp upper layer protocol.
 *
 * The object is driven by the receive loop of the default socket: it adds
 * its file descriptors to the poll set and handles the events on them.
 * File descriptors are only closed from that loop, other threads only open
 * new connections and change reference counts.
 */
struct socket_default_tcp_t {

	/**
	 * Append poll descriptors for all TCP sockets to the given array.
	 *
	 * Must only be called by the receiving thread, together with
	 * process_poll().
	 *
	 * @param pfd			poll array, reallocated if necessary
	 * @param size			allocated number of entries in pfd
	 * @param count			used number of entries in pfd, updated
	 * @return				timeout to use for poll() in ms, -1 for infinite
	 */
	int (*prepare_poll)(socket_default_tcp_t *this, struct pollfd **pfd,
						u_int *size, u_int *count);

	/**
	 * Handle events on the entries added by the last prepare_poll() call.
	 *
	 * @param pfd			poll array entries added by prepare_poll()
	 * @param count			number of these entries
	 * @return				received IKE packet, NULL if none
	 */
	packet_t *(*process_poll)(socket_default_tcp_t *this, struct pollfd *pfd,
							  u_int count);

	/**
	 * Send a packet over a TCP connection.
	 *
	 * @param packet		packet to send (including a Non-ESP marker)
	 * @param conn			connection identifier
	 * @return				SUCCESS if sent or queued
	 */
	status_t (*send)(socket_default_tcp_t *this, packet_t *packet,
					 uint32_t conn);

	/**
	 * Open a new connection as TCP Originator.
	 *
	 * @see socket_t.tcp_connect
	 */
	bool (*connect)(socket_default_tcp_t *this, host_t *src, host_t *dst,
					host_t **local, uint32_t *conn);

	/**
	 * Acquire a reference to a connection.
	 *
	 * @see socket_t.tcp_acquire
	 */
	bool (*acquire)(socket_default_tcp_t *this, uint32_t conn);

	/**
	 * Release a reference to a connection.
	 *
	 * @see socket_t.tcp_release
	 */
	void (*release)(socket_default_tcp_t *this, uint32_t conn);

	/**
	 * Close all connections and destroy the object.
	 */
	void (*destroy)(socket_default_tcp_t *this);
};

/**
 * Create the TCP encapsulation handler.
 *
 * @param port			port to listen on as TCP Responder, 0 to not listen
 * @param max_packet	maximum size of received messages
 * @return				object, NULL if not supported on this platform
 */
socket_default_tcp_t *socket_default_tcp_create(uint16_t port, int max_packet);

#endif /** SOCKET_DEFAULT_TCP_H_ @}*/
