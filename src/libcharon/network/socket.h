/*
 * Copyright (C) 2006-2013 Tobias Brunner
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
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
 * @defgroup socket socket
 * @{ @ingroup network
 */

#ifndef SOCKET_H_
#define SOCKET_H_

typedef struct socket_t socket_t;
typedef enum socket_family_t socket_family_t;

#include <library.h>
#include <networking/packet.h>
#include <collections/enumerator.h>
#include <plugins/plugin.h>

/**
 * Constructor prototype for sockets.
 */
typedef socket_t *(*socket_constructor_t)();

/**
 * Address families supported by socket implementations.
 */
enum socket_family_t {
	/**
	 * No address families supported
	 */
	SOCKET_FAMILY_NONE = 0,

	/**
	 * IPv4
	 */
	SOCKET_FAMILY_IPV4 = (1 << 0),

	/**
	 * IPv6
	 */
	SOCKET_FAMILY_IPV6 = (1 << 1),

	/**
	 * Both address families supported
	 */
	SOCKET_FAMILY_BOTH = (1 << 2) - 1,
};

/**
 * Socket interface definition.
 */
struct socket_t {

	/**
	 * Receive a packet.
	 *
	 * Reads a packet from the socket and sets source/dest
	 * appropriately.
	 *
	 * @param packet		received packet
	 * @return
	 *						- SUCCESS when packet successfully received
	 *						- FAILED when unable to receive
	 */
	status_t (*receive)(socket_t *this, packet_t **packet);

	/**
	 * Send a packet.
	 *
	 * Sends a packet to the net using source and destination addresses of
	 * the packet.
	 *
	 * @param packet		packet to send
	 * @return
	 *						- SUCCESS when packet successfully sent
	 *						- FAILED when unable to send
	 */
	status_t (*send)(socket_t *this, packet_t *packet);

	/**
	 * Get the port this socket is listening on.
	 *
	 * @param nat_t			TRUE to get the port used to float in case of NAT-T
	 * @return				the port
	 */
	uint16_t (*get_port)(socket_t *this, bool nat_t);

	/**
	 * Get the address families this socket is listening on.
	 *
	 * @return				supported families
	 */
	socket_family_t (*supported_families)(socket_t *this);

	/**
	 * Open a TCP connection to the given peer for TCP encapsulation of IKE
	 * and ESP (RFC 9329), optional.
	 *
	 * The connection is established asynchronously, packets sent before it
	 * is up are queued. The returned connection gets one reference that has
	 * to be released with tcp_release().
	 *
	 * @param src			local address to bind to (may be %any), port ignored
	 * @param dst			remote address and port
	 * @param local			local address and port of the connection (allocated)
	 * @param conn			unique identifier of the connection
	 * @return				TRUE if connection initiated
	 */
	bool (*tcp_connect)(socket_t *this, host_t *src, host_t *dst,
						host_t **local, uint32_t *conn);

	/**
	 * Acquire a reference to a TCP connection, optional.
	 *
	 * @param conn			connection identifier
	 * @return				TRUE if the connection is known
	 */
	bool (*tcp_acquire)(socket_t *this, uint32_t conn);

	/**
	 * Release a reference to a TCP connection, optional. The connection is
	 * closed once the last reference is gone.
	 *
	 * @param conn			connection identifier
	 */
	void (*tcp_release)(socket_t *this, uint32_t conn);

	/**
	 * Destroy a socket implementation.
	 */
	void (*destroy)(socket_t *this);
};

/**
 * Packet/message metadata key that stores the identifier (an int) of the TCP
 * connection a packet was received on or should be sent over. Packets without
 * it use UDP.
 */
#define TCP_CONN_METADATA "tcp-conn"

/**
 * Get the TCP connection identifier attached to a packet.
 *
 * @param packet		packet to check
 * @return				connection identifier, 0 for UDP
 */
static inline uint32_t packet_get_tcp_conn(packet_t *packet)
{
	metadata_t *metadata;
	int conn = 0;

	metadata = packet->get_metadata(packet, TCP_CONN_METADATA);
	if (metadata)
	{
		metadata->get(metadata, &conn);
	}
	return conn;
}

/**
 * Attach a TCP connection identifier to a packet.
 *
 * @param packet		packet to modify
 * @param conn			connection identifier, 0 to remove it (UDP)
 */
static inline void packet_set_tcp_conn(packet_t *packet, uint32_t conn)
{
	packet->set_metadata(packet, TCP_CONN_METADATA, conn ?
			lib->metadata->create(lib->metadata, METADATA_TYPE_INT, (int)conn) :
			NULL);
}

/**
 * Helper function to (un-)register socket interfaces from plugin features.
 *
 * This function is a plugin_feature_callback_t and can be used with the
 * PLUGIN_CALLBACK macro to register an socket interface constructor.
 *
 * @param plugin		plugin registering the socket interface
 * @param feature		associated plugin feature
 * @param reg			TRUE to register, FALSE to unregister
 * @param data			data passed to callback, a socket_constructor_t
 */
bool socket_register(plugin_t *plugin, plugin_feature_t *feature,
					 bool reg, void *data);

#endif /** SOCKET_H_ @}*/
