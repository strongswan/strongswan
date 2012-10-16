/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup ip_packet ip_packet
 * @{ @ingroup libipsec
 */

#ifndef IP_PACKET_H_
#define IP_PACKET_H_

#include <library.h>
#include <networking/host.h>
#include <networking/packet.h>

typedef struct ip_packet_t ip_packet_t;

/**
 *  IP packet
 */
struct ip_packet_t {

	/**
	 * IP version of this packet
	 *
	 * @return				ip version
	 */
	u_int8_t (*get_version)(ip_packet_t *this);

	/**
	 * Get the source address of this packet
	 *
	 * @return				source host
	 */
	host_t *(*get_source)(ip_packet_t *this);

	/**
	 * Get the destination address of this packet
	 *
	 * @return				destination host
	 */
	host_t *(*get_destination)(ip_packet_t *this);

	/**
	 * Get the protocol (IPv4) or next header (IPv6) field of this packet.
	 *
	 * @return				protocol|next header field
	 */
	u_int8_t (*get_next_header)(ip_packet_t *this);

	/**
	 * Get the complete IP packet (including the header)
	 *
	 * @return				IP packet (internal data)
	 */
	chunk_t (*get_encoding)(ip_packet_t *this);

	/**
	 * Clone the IP packet
	 *
	 * @return				clone of the packet
	 */
	ip_packet_t *(*clone)(ip_packet_t *this);

	/**
	 * Destroy an ip_packet_t
	 */
	void (*destroy)(ip_packet_t *this);

};

/**
 * Create an IP packet out of data from the wire (or decapsulated from another
 * packet).
 *
 * @note The raw IP packet gets either owned by the new object, or destroyed,
 * if the data is invalid.
 *
 * @param packet		the IP packet (including header), gets owned
 * @return				ip_packet_t instance, or NULL if invalid
 */
ip_packet_t *ip_packet_create(chunk_t packet);

#endif /** IP_PACKET_H_ @}*/
