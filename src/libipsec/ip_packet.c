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


#include "ip_packet.h"

#include <library.h>
#include <utils/debug.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

typedef struct private_ip_packet_t private_ip_packet_t;

/**
 * Private additions to ip_packet_t.
 */
struct private_ip_packet_t {

	/**
	 * Public members
	 */
	ip_packet_t public;

	/**
	 * Source address
	 */
	host_t *src;

	/**
	 * Destination address
	 */
	host_t *dst;

	/**
	 * IP packet
	 */
	chunk_t packet;

	/**
	 * IP version
	 */
	u_int8_t version;

	/**
	 * Protocol|Next Header field
	 */
	u_int8_t next_header;

};

METHOD(ip_packet_t, get_version, u_int8_t,
	private_ip_packet_t *this)
{
	return this->version;
}

METHOD(ip_packet_t, get_source, host_t*,
	private_ip_packet_t *this)
{
	return this->src;
}

METHOD(ip_packet_t, get_destination, host_t*,
	private_ip_packet_t *this)
{
	return this->dst;
}

METHOD(ip_packet_t, get_encoding, chunk_t,
	private_ip_packet_t *this)
{
	return this->packet;
}

METHOD(ip_packet_t, get_next_header, u_int8_t,
	private_ip_packet_t *this)
{
	return this->next_header;
}

METHOD(ip_packet_t, clone, ip_packet_t*,
	private_ip_packet_t *this)
{
	return ip_packet_create(chunk_clone(this->packet));
}

METHOD(ip_packet_t, destroy, void,
	private_ip_packet_t *this)
{
	this->src->destroy(this->src);
	this->dst->destroy(this->dst);
	chunk_free(&this->packet);
	free(this);
}

/**
 * Described in header.
 */
ip_packet_t *ip_packet_create(chunk_t packet)
{
	private_ip_packet_t *this;
	u_int8_t version, next_header;
	host_t *src, *dst;

	if (packet.len < 1)
	{
		DBG1(DBG_ESP, "IP packet too short");
		goto failed;
	}

	version = (packet.ptr[0] & 0xf0) >> 4;

	switch (version)
	{
		case 4:
		{
			struct ip *ip;

			if (packet.len < sizeof(struct ip))
			{
				DBG1(DBG_ESP, "IPv4 packet too short");
				goto failed;
			}
			ip = (struct ip*)packet.ptr;
			/* remove any RFC 4303 TFC extra padding */
			packet.len = min(packet.len, untoh16(&ip->ip_len));

			src = host_create_from_chunk(AF_INET,
										 chunk_from_thing(ip->ip_src), 0);
			dst = host_create_from_chunk(AF_INET,
										 chunk_from_thing(ip->ip_dst), 0);
			next_header = ip->ip_p;
			break;
		}
#ifdef HAVE_NETINET_IP6_H
		case 6:
		{
			struct ip6_hdr *ip;

			if (packet.len < sizeof(struct ip6_hdr))
			{
				DBG1(DBG_ESP, "IPv6 packet too short");
				goto failed;
			}
			ip = (struct ip6_hdr*)packet.ptr;
			/* remove any RFC 4303 TFC extra padding */
			packet.len = min(packet.len, untoh16(&ip->ip6_plen));

			src = host_create_from_chunk(AF_INET6,
										 chunk_from_thing(ip->ip6_src), 0);
			dst = host_create_from_chunk(AF_INET6,
										 chunk_from_thing(ip->ip6_dst), 0);
			next_header = ip->ip6_nxt;
			break;
		}
#endif /* HAVE_NETINET_IP6_H */
		default:
			DBG1(DBG_ESP, "unsupported IP version");
			goto failed;
	}

	INIT(this,
		.public = {
			.get_version = _get_version,
			.get_source = _get_source,
			.get_destination = _get_destination,
			.get_next_header = _get_next_header,
			.get_encoding = _get_encoding,
			.clone = _clone,
			.destroy = _destroy,
		},
		.src = src,
		.dst = dst,
		.packet = packet,
		.version = version,
		.next_header = next_header,
	);
	return &this->public;

failed:
	chunk_free(&packet);
	return NULL;
}
