/*
 * Copyright (C) 2007-2017 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * HSR Hochschule fuer Technik Rapperswil
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

/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <string.h>
#include <stdio.h>

#include "traffic_selector.h"

#include <utils/debug.h>
#include <utils/utils.h>
#include <utils/identification.h>
#include <collections/linked_list.h>

#define IPV4_LEN	4
#define IPV6_LEN	16
#define PORTID_LEN  3
#define TS_IP_LEN(this) ({ (((this)->type == TS_IPV4_ADDR_RANGE) ? IPV4_LEN : (((this)->type == TS_FC_ADDR_RANGE) ? PORTID_LEN: IPV6_LEN) ); })

#define NON_SUBNET_ADDRESS_RANGE	255

ENUM(ts_type_name, TS_IPV4_ADDR_RANGE, TS_FC_ADDR_RANGE,
	"TS_IPV4_ADDR_RANGE",
	"TS_IPV6_ADDR_RANGE",
	"TS_FC_ADDR_RANGE",
);

typedef struct private_traffic_selector_t private_traffic_selector_t;

/**
 * Private data of an traffic_selector_t object
 */
struct private_traffic_selector_t {

	/**
	 * Public part
	 */
	traffic_selector_t public;

	/**
	 * Type of address
	 */
	ts_type_t type;

	/**
	 * IP protocol (UDP, TCP, ICMP, ...)
	 */
	uint8_t protocol;

	/**
	 * narrow this traffic selector to hosts external ip
	 * if set, from and to have no meaning until set_address() is called
	 */
	bool dynamic;

	/**
	 * subnet size in CIDR notation, 255 means a non-subnet address range
	 */
	uint8_t netbits;

	/**
	 * begin of address range, network order
	 */
	char from[IPV6_LEN];

	/**
	 * end of address range, network order
	 */
	char to[IPV6_LEN];

	/**
	 * begin of port range
	 */
	uint16_t from_port;

	/**
	 * end of port range
	 */
	uint16_t to_port;

	/**
	 * starting R_CTL.
	 */
	uint8_t starting_r_ctl;

	/**
	 * ending R_CTL.
	 */
	uint8_t ending_r_ctl;

	/**
	 * FC port is identified using port index
	 * as host_t structure is still not FC compliant.
	 */
	uint16_t id;

};

/**
 * calculate the "to"-address for the "from" address and a subnet size
 */
static void calc_range(private_traffic_selector_t *this, uint8_t netbits)
{
	size_t len;
	int bytes, bits;
	uint8_t mask;

	this->netbits = netbits;

	len   = TS_IP_LEN(this);
	bytes = (netbits + 7)/8;
	bits  = (bytes * 8) - netbits;
	mask  = bits ? (1 << bits) - 1 : 0;

	memcpy(this->to, this->from, bytes);
	memset(this->from + bytes, 0x00, len - bytes);
	memset(this->to   + bytes, 0xff, len - bytes);
	this->from[bytes-1] &= ~mask;
	this->to[bytes-1]   |=  mask;
}

/**
 * calculate the subnet size from the "to" and "from" addresses
 */
static uint8_t calc_netbits(private_traffic_selector_t *this)
{
	int byte, bit;
	uint8_t netbits;
	size_t size = TS_IP_LEN(this);
	bool prefix = TRUE;

	/* a perfect match results in a single address with a /32 or /128 netmask */
	netbits = (size * 8);
	this->netbits = netbits;

	/* go through all bits of the addresses, beginning in the front.
	 * as long as they are equal, the subnet gets larger
	 */
	for (byte = 0; byte < size; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			uint8_t bitmask = 1 << bit;

			if (prefix)
			{
				if ((bitmask & this->from[byte]) != (bitmask & this->to[byte]))
				{
					/* store the common prefix which might be a true subnet */
					netbits = (7 - bit) + (byte * 8);
					this->netbits = netbits;
					prefix = FALSE;
				}
			}
			else
			{
				if ((bitmask & this->from[byte]) || !(bitmask & this->to[byte]))
				{
					this->netbits = NON_SUBNET_ADDRESS_RANGE;
					return netbits;  /* return a pseudo subnet */

				}
			}
		}
	}
	return netbits;  /* return a true subnet */
}

/**
 * internal generic constructor
 */
static private_traffic_selector_t *traffic_selector_create(uint8_t protocol,
						ts_type_t type, uint16_t from_port, uint16_t to_port);

/**
 * Check if TS contains "opaque" ports
 */
static bool is_opaque(private_traffic_selector_t *this)
{
	return this->from_port == 0xffff && this->to_port == 0;
}

/**
 * Check if TS contains "any" ports
 */
static bool is_any(private_traffic_selector_t *this)
{
	return this->from_port == 0 && this->to_port == 0xffff;
}

/**
 * Print ICMP/ICMPv6 type and code
 */
static int print_icmp(printf_hook_data_t *data, uint16_t port)
{
	uint8_t type, code;

	type = traffic_selector_icmp_type(port);
	code = traffic_selector_icmp_code(port);
	if (code)
	{
		return print_in_hook(data, "%d(%d)", type, code);
	}
	return print_in_hook(data, "%d", type);
}

/**
 * Described in header.
 */
int traffic_selector_printf_hook(printf_hook_data_t *data,
							printf_hook_spec_t *spec, const void *const *args)
{
	private_traffic_selector_t *this = *((private_traffic_selector_t**)(args[0]));
	linked_list_t *list = *((linked_list_t**)(args[0]));
	enumerator_t *enumerator;
	char from_str[INET6_ADDRSTRLEN] = "";
	char to_str[INET6_ADDRSTRLEN] = "";
	char *serv_proto = NULL, *sep = "";
	bool has_proto, has_ports;
	size_t written = 0, len;
	char from[IPV6_LEN], to[IPV6_LEN];

	if (this == NULL)
	{
		return print_in_hook(data, "(null)");
	}

	if (spec->hash)
	{
		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, (void**)&this))
		{
			written += print_in_hook(data, "%s%R", sep, this);
			sep = " ";
		}
		enumerator->destroy(enumerator);
		return written;
	}

	len = TS_IP_LEN(this);
	memset(from, 0, len);
	memset(to, 0xFF, len);
	if (this->dynamic && (this->type != TS_FC_ADDR_RANGE) &&
		memeq(this->from, from, len) &&	memeq(this->to, to, len))
	{
		written += print_in_hook(data, "dynamic");
	}
	else
	{
		if (this->type == TS_IPV4_ADDR_RANGE)
		{
			inet_ntop(AF_INET, &this->from, from_str, sizeof(from_str));
		}
		else if (this->type == TS_FC_ADDR_RANGE)
		{
			written += print_in_hook(data, "%x%x%x..%x%x%x", this->from[0], this->from[1], this->from[2],
					this->to[0], this->to[1], this->to[2]);
		}
		else
		{
			inet_ntop(AF_INET6, &this->from, from_str, sizeof(from_str));
		}
		if (this->netbits == NON_SUBNET_ADDRESS_RANGE)
		{
			if (this->type == TS_IPV4_ADDR_RANGE)
			{
				inet_ntop(AF_INET, &this->to, to_str, sizeof(to_str));
			}
			else
			{
				inet_ntop(AF_INET6, &this->to, to_str, sizeof(to_str));
			}
			written += print_in_hook(data, "%s..%s", from_str, to_str);
		}
		else
		{
			written += print_in_hook(data, "%s/%d", from_str, this->netbits);
		}
	}

	/* check if we have protocol and/or port selectors */
	has_proto = this->protocol != 0;
	has_ports = !is_any(this);

	if (!has_proto && !has_ports)
	{
		return written;
	}

	written += print_in_hook(data, "[");

	/* build protocol string */
	if (has_proto)
	{
		struct protoent *proto = getprotobynumber(this->protocol);

		if (proto)
		{
			written += print_in_hook(data, "%s", proto->p_name);
			serv_proto = proto->p_name;
		}
		else
		{
			written += print_in_hook(data, "%d", this->protocol);
		}
	}
	else
	{
		written += print_in_hook(data, "0");
	}

	/* build port string */
	if (has_ports)
	{
		written += print_in_hook(data, "/");

		if (this->from_port == this->to_port)
		{
			struct servent *serv;

			if (this->protocol == IPPROTO_ICMP ||
				this->protocol == IPPROTO_ICMPV6)
			{
				written += print_icmp(data, this->from_port);
			}
			else if (this->type == TS_FC_ADDR_RANGE)
			{
				written += print_in_hook(data, "%d-%d",
										 this->from_port, this->to_port);
				written += print_in_hook(data, "%d-%d",
										 this->starting_r_ctl, this->ending_r_ctl);

			}
			else
			{
				serv = getservbyport(htons(this->from_port), serv_proto);
				if (serv)
				{
					written += print_in_hook(data, "%s", serv->s_name);
				}
				else
				{
					written += print_in_hook(data, "%d", this->from_port);
				}
			}
		}
		else if (is_opaque(this))
		{
			written += print_in_hook(data, "OPAQUE");
		}
		else if (this->protocol == IPPROTO_ICMP ||
				 this->protocol == IPPROTO_ICMPV6)
		{
			written += print_icmp(data, this->from_port);
			written += print_in_hook(data, "-");
			written += print_icmp(data, this->to_port);
		}
		else
		{
			written += print_in_hook(data, "%d-%d",
									 this->from_port, this->to_port);
			if (this->type == TS_FC_ADDR_RANGE)
			{
				written += print_in_hook(data, "%d-%d",
										 this->starting_r_ctl, this->ending_r_ctl);

			}
		}
	}

	written += print_in_hook(data, "]");

	return written;
}

METHOD(traffic_selector_t, get_subset, traffic_selector_t*,
	private_traffic_selector_t *this, traffic_selector_t *other_public)
{
	private_traffic_selector_t *other, *subset;
	uint16_t from_port, to_port;
	u_char *from, *to;
	uint8_t protocol;
	size_t size;

	other = (private_traffic_selector_t*)other_public;

	if (this->dynamic || other->dynamic)
	{	/* no set_address() applied, TS has no subset */
		return NULL;
	}

	if (this->type != other->type)
	{
		return NULL;
	}

	if (this->protocol != other->protocol &&
		this->protocol != 0 && other->protocol != 0)
	{
		return NULL;
	}
	/* select protocol, which is not zero */
	protocol = max(this->protocol, other->protocol);

	if ((is_opaque(this) && is_opaque(other)) ||
		(is_opaque(this) && is_any(other)) ||
		(is_opaque(other) && is_any(this)))
	{
		from_port = 0xffff;
		to_port = 0;
	}
	else
	{
		/* calculate the maximum port range allowed for both */
		from_port = max(this->from_port, other->from_port);
		to_port = min(this->to_port, other->to_port);
		if (from_port > to_port)
		{
			return NULL;
		}
	}
	size = TS_IP_LEN(this);
	/* get higher from-address */
	if (memcmp(this->from, other->from, size) > 0)
	{
		from = this->from;
	}
	else
	{
		from = other->from;
	}
	/* get lower to-address */
	if (memcmp(this->to, other->to, size) > 0)
	{
		to = other->to;
	}
	else
	{
		to = this->to;
	}
	/* if "from" > "to", we don't have a match */
	if (memcmp(from, to, size) > 0)
	{
		return NULL;
	}

	/* we have a match in protocol, port, and address: return it... */
	subset = traffic_selector_create(protocol, this->type, from_port, to_port);
	if(this->type == TS_FC_ADDR_RANGE)
    {
		subset->starting_r_ctl = this->starting_r_ctl;
		subset->ending_r_ctl = this->ending_r_ctl;
		subset->id = this->id;
		from = this->from;
		to = this->to;
    }
	memcpy(subset->from, from, size);
	memcpy(subset->to, to, size);
	calc_netbits(subset);

	return &subset->public;
}

METHOD(traffic_selector_t, equals, bool,
	private_traffic_selector_t *this, traffic_selector_t *other)
{
	return traffic_selector_cmp(&this->public, other, NULL) == 0;
}

METHOD(traffic_selector_t, get_from_address, chunk_t,
	private_traffic_selector_t *this)
{
	return chunk_create(this->from, TS_IP_LEN(this));
}

METHOD(traffic_selector_t, get_to_address, chunk_t,
	private_traffic_selector_t *this)
{
	return chunk_create(this->to, TS_IP_LEN(this));
}

METHOD(traffic_selector_t, get_from_port, uint16_t,
	private_traffic_selector_t *this)
{
	return this->from_port;
}

METHOD(traffic_selector_t, get_to_port, uint16_t,
	private_traffic_selector_t *this)
{
	return this->to_port;
}

METHOD(traffic_selector_t, get_type, ts_type_t,
	private_traffic_selector_t *this)
{
	return this->type;
}

METHOD(traffic_selector_t, get_protocol, uint8_t,
	private_traffic_selector_t *this)
{
	return this->protocol;
}

METHOD(traffic_selector_t, get_start_rctl, uint8_t,
	private_traffic_selector_t *this)
{
	return this->starting_r_ctl;
}

METHOD(traffic_selector_t, set_start_rctl, void,
	private_traffic_selector_t *this, uint8_t starting_r_ctl)
{
	this->starting_r_ctl = starting_r_ctl;
}

METHOD(traffic_selector_t, get_end_rctl, uint8_t,
	private_traffic_selector_t *this)
{
	return this->ending_r_ctl;
}

METHOD(traffic_selector_t, set_end_rctl, void,
	private_traffic_selector_t *this, uint8_t ending_r_ctl)
{
	this->ending_r_ctl = ending_r_ctl;
}

METHOD(traffic_selector_t, set_id, void,
	private_traffic_selector_t *this, uint16_t port_index)
{
	this->id = port_index;
}

METHOD(traffic_selector_t, get_id, uint16_t,
	private_traffic_selector_t *this)
{
	return this->id;
}

METHOD(traffic_selector_t, set_port_id, void,
	private_traffic_selector_t *this, chunk_t from, chunk_t to)
{
	if (this->type == TS_FC_ADDR_RANGE)
	{
		if ((from.len != 3) || (to.len != 3))
		{
			return;
		}
		memcpy(this->from, from.ptr, from.len);
		memcpy(this->to, to.ptr, to.len);
	}
}

METHOD(traffic_selector_t, is_host, bool,
	private_traffic_selector_t *this, host_t *host)
{
	if (host)
	{
		chunk_t addr;
		int family = host->get_family(host);

		if ((family == AF_INET && this->type == TS_IPV4_ADDR_RANGE) ||
			(family == AF_INET6 && this->type == TS_IPV6_ADDR_RANGE))
		{
			addr = host->get_address(host);
			if (memeq(addr.ptr, this->from, addr.len) &&
				memeq(addr.ptr, this->to, addr.len))
			{
				return TRUE;
			}
		}
		else if (this->type == TS_FC_ADDR_RANGE)
		{
			uint16_t port_index = host->get_port(host);
			if (this->id == port_index)
			{
				return TRUE;
			}
		}
	}
	else
	{
		size_t length = TS_IP_LEN(this);

		if (this->dynamic)
		{
			return TRUE;
		}

		if (memeq(this->from, this->to, length))
		{
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(traffic_selector_t, is_dynamic, bool,
	private_traffic_selector_t *this)
{
	return this->dynamic;
}

METHOD(traffic_selector_t, set_address, void,
	private_traffic_selector_t *this, host_t *host)
{
	if (this->type != TS_FC_ADDR_RANGE)
	{
        this->type = host->get_family(host) == AF_INET ? TS_IPV4_ADDR_RANGE
				: TS_IPV6_ADDR_RANGE;
    }

	if (host->is_anyaddr(host))
	{
		memset(this->from, 0x00, sizeof(this->from));
		memset(this->to, 0xFF, sizeof(this->to));
		this->netbits = 0;

		if (this->type == TS_FC_ADDR_RANGE)
		{
			uint16_t port_index = host->get_port(host);
			this->id = port_index;
		}
	}
	else
	{
			if (this->type == TS_FC_ADDR_RANGE)
			{
				uint16_t port_index = host->get_port(host);
				this->id = port_index;
			}
			else
			{
        		chunk_t from = host->get_address(host);
        		memcpy(this->from, from.ptr, from.len);
        		memcpy(this->to, from.ptr, from.len);
        		this->netbits = from.len * 8;
            }
	}
	this->dynamic = FALSE;
}

METHOD(traffic_selector_t, is_contained_in, bool,
	private_traffic_selector_t *this, traffic_selector_t *other)
{
	private_traffic_selector_t *subset;
	bool contained_in = FALSE;

	if (this->type == TS_FC_ADDR_RANGE)
	{
		if (equals(this, other))
		{
			contained_in = TRUE;
		}
		return contained_in;
	}

	subset = (private_traffic_selector_t*)get_subset(this, other);

	if (subset)
	{
		if (equals(subset, &this->public))
		{
			contained_in = TRUE;
		}
		free(subset);
	}
	return contained_in;
}

METHOD(traffic_selector_t, includes, bool,
	private_traffic_selector_t *this, host_t *host)
{
	chunk_t addr;
	int family = host->get_family(host);
	uint16_t port_index = 0;

	if ((family == AF_INET && this->type == TS_IPV4_ADDR_RANGE) ||
		(family == AF_INET6 && this->type == TS_IPV6_ADDR_RANGE))
	{
		addr = host->get_address(host);

		return memcmp(this->from, addr.ptr, addr.len) <= 0 &&
				memcmp(this->to, addr.ptr, addr.len) >= 0;
	}

	if (this->type == TS_FC_ADDR_RANGE)
	{
		port_index = host->get_port(host);

		return ((this->from_port == port_index) || (this->to_port == port_index));
	}

	return FALSE;
}

METHOD(traffic_selector_t, to_subnet, bool,
	private_traffic_selector_t *this, host_t **net, uint8_t *mask)
{
	/* there is no way to do this cleanly, as the address range may
	 * be anything else but a subnet. We use from_addr as subnet
	 * and try to calculate a usable subnet mask.
	 */
	int family, non_zero_bytes;
	uint16_t port = 0;
	chunk_t net_chunk;

	*mask = (this->netbits == NON_SUBNET_ADDRESS_RANGE) ? calc_netbits(this)
														: this->netbits;

	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			family = AF_INET;
			net_chunk.len = IPV4_LEN;
			break;
		case TS_IPV6_ADDR_RANGE:
			family = AF_INET6;
			net_chunk.len = IPV6_LEN;
			break;
		default:
			/* unreachable */
			return FALSE;
	}

	net_chunk.ptr = malloc(net_chunk.len);
	memset(net_chunk.ptr, 0x00, net_chunk.len);
	if (*mask)
	{
		non_zero_bytes = (*mask + 7) / 8;
		memcpy(net_chunk.ptr, this->from, non_zero_bytes);
		net_chunk.ptr[non_zero_bytes-1] &= 0xFF << (8 * non_zero_bytes - *mask);
	}

	if (this->to_port == this->from_port)
	{
		port = this->to_port;
	}

	*net = host_create_from_chunk(family, net_chunk, port);
	chunk_free(&net_chunk);

	return this->netbits != NON_SUBNET_ADDRESS_RANGE;
}

METHOD(traffic_selector_t, clone_, traffic_selector_t*,
	private_traffic_selector_t *this)
{
	private_traffic_selector_t *clone;
	size_t len = TS_IP_LEN(this);

	clone = traffic_selector_create(this->protocol, this->type,
									this->from_port, this->to_port);
	clone->netbits = this->netbits;
	clone->dynamic = this->dynamic;

	memcpy(clone->from, this->from, len);
	memcpy(clone->to, this->to, len);
    if (clone->type == TS_FC_ADDR_RANGE)
    {
        clone->starting_r_ctl = this->starting_r_ctl;
        clone->ending_r_ctl = this->ending_r_ctl;
        clone->id = this->id;
    }
	return &clone->public;
}

METHOD(traffic_selector_t, hash, u_int,
	private_traffic_selector_t *this, u_int hash)
{
	if (this->type == TS_FC_ADDR_RANGE)
	{
		hash = chunk_hash_inc(chunk_from_thing(this->starting_r_ctl),
				  chunk_hash_inc(chunk_from_thing(this->ending_r_ctl),
						  hash));
	}
	return chunk_hash_inc(get_from_address(this),
			chunk_hash_inc(get_to_address(this),
			 chunk_hash_inc(chunk_from_thing(this->from_port),
			  chunk_hash_inc(chunk_from_thing(this->to_port),
			   chunk_hash_inc(chunk_from_thing(this->protocol),
				hash)))));
}

METHOD(traffic_selector_t, destroy, void,
	private_traffic_selector_t *this)
{
	free(this);
}

/**
 * Compare two integers
 */
static int compare_int(int a, int b)
{
	return a - b;
}

/*
 * See header
 */
int traffic_selector_cmp(traffic_selector_t *a_pub, traffic_selector_t *b_pub,
						 void *opts)
{
	private_traffic_selector_t *a, *b;
	size_t len;
	int res;

	a = (private_traffic_selector_t*)a_pub;
	b = (private_traffic_selector_t*)b_pub;

	/* IPv4 before IPv6 */
	res = compare_int(a->type, b->type);
	if (res)
	{
		return res;
	}
	len = TS_IP_LEN(a);
	/* lower starting subnets first */
	res = memcmp(a->from, b->from, len);
	if (res)
	{
		return res;
	}
	/* larger subnets first */
	res = memcmp(b->to, a->to, len);
	if (res)
	{
		return res;
	}
	/* lower protocols first */
	res = compare_int(a->protocol, b->protocol);
	if (res)
	{
		return res;
	}
	/* lower starting ports first */
	res = compare_int(a->from_port, b->from_port);
	if (res)
	{
		return res;
	}
	/* larger port ranges first */
	res = compare_int(b->to_port, a->to_port);
	if (res)
	{
		return res;
	}

	if (a->type == TS_FC_ADDR_RANGE)
	{
		res = compare_int(b->starting_r_ctl, a->starting_r_ctl);
		if (res)
		{
			return res;
		}
		res = compare_int(b->ending_r_ctl, a->ending_r_ctl);
	}
	return res;

}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_bytes(uint8_t protocol,
												ts_type_t type,
												chunk_t from, uint16_t from_port,
												chunk_t to, uint16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type,
															from_port, to_port);

	if (!this)
	{
		return NULL;
	}
	if (from.len != to.len || from.len != TS_IP_LEN(this))
	{
		free(this);
		return NULL;
	}
	memcpy(this->from, from.ptr, from.len);
	memcpy(this->to, to.ptr, to.len);
	calc_netbits(this);
	return &this->public;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_rfc3779_format(ts_type_t type,
												chunk_t from, chunk_t to)
{
	private_traffic_selector_t *this = traffic_selector_create(0, type, 0, 65535);
	size_t len;

	if (!this)
	{
		return NULL;
	}
	len = TS_IP_LEN(this);

	memset(this->from, 0x00, len);
	memset(this->to  , 0xff, len);

	if (from.len > 1)
	{
		memcpy(this->from, from.ptr+1, from.len-1);
	}
	if (to.len > 1)
	{
		uint8_t mask = to.ptr[0] ? (1 << to.ptr[0]) - 1 : 0;

		memcpy(this->to, to.ptr+1, to.len-1);
		this->to[to.len-2] |= mask;
	}
	calc_netbits(this);
	return &this->public;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_subnet(host_t *net,
							uint8_t netbits, uint8_t protocol,
							uint16_t from_port, uint16_t to_port)
{
	private_traffic_selector_t *this;
	ts_type_t type;
	chunk_t from;

	switch (net->get_family(net))
	{
		case AF_INET:
			type = TS_IPV4_ADDR_RANGE;
			break;
		case AF_INET6:
			type = TS_IPV6_ADDR_RANGE;
			break;
		default:
			net->destroy(net);
			return NULL;
	}

	this = traffic_selector_create(protocol, type, from_port, to_port);

	from = net->get_address(net);
	memcpy(this->from, from.ptr, from.len);
	netbits = min(netbits, TS_IP_LEN(this) * 8);
	calc_range(this, netbits);
	net->destroy(net);
	return &this->public;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_string(
										uint8_t protocol, ts_type_t type,
										char *from_addr, uint16_t from_port,
										char *to_addr, uint16_t to_port)
{
	private_traffic_selector_t *this;
	int family;

	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
			family = AF_INET;
			break;
		case TS_IPV6_ADDR_RANGE:
			family = AF_INET6;
			break;
		default:
			return NULL;
	}

	this = traffic_selector_create(protocol, type, from_port, to_port);

	if (inet_pton(family, from_addr, this->from) != 1 ||
		inet_pton(family, to_addr, this->to) != 1)
	{
		free(this);
		return NULL;
	}
	calc_netbits(this);
	return &this->public;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_cidr(
										char *string, uint8_t protocol,
										uint16_t from_port, uint16_t to_port)
{
	host_t *net;
	int bits;

	net = host_create_from_subnet(string, &bits);
	if (net)
	{
		return traffic_selector_create_from_subnet(net, bits, protocol,
												   from_port, to_port);
	}
	return NULL;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_dynamic(uint8_t protocol,
									uint16_t from_port, uint16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(
							protocol, TS_IPV4_ADDR_RANGE, from_port, to_port);

	memset(this->from, 0, sizeof(this->from));
	memset(this->to, 0xFF, sizeof(this->to));
	this->netbits = 0;
	this->dynamic = TRUE;

	return &this->public;
}

/*
 * see declaration
 */
static private_traffic_selector_t *traffic_selector_create(uint8_t protocol,
						ts_type_t type, uint16_t from_port, uint16_t to_port)
{
	private_traffic_selector_t *this;

	/* sanity check */
	if (type != TS_IPV4_ADDR_RANGE && type != TS_IPV6_ADDR_RANGE && type != TS_FC_ADDR_RANGE)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.get_subset = _get_subset,
			.equals = _equals,
			.get_from_address = _get_from_address,
			.get_to_address = _get_to_address,
			.get_from_port = _get_from_port,
			.get_to_port = _get_to_port,
			.get_type = _get_type,
			.get_protocol = _get_protocol,
			.is_host = _is_host,
			.is_dynamic = _is_dynamic,
			.is_contained_in = _is_contained_in,
			.includes = _includes,
			.set_address = _set_address,
			.to_subnet = _to_subnet,
			.clone = _clone_,
			.hash = _hash,
			.destroy = _destroy,
			.get_start_rctl = _get_start_rctl,
			.get_end_rctl = _get_end_rctl,
			.set_start_rctl = _set_start_rctl,
			.set_end_rctl = _set_end_rctl,
			.set_port_id = _set_port_id,
			.set_id = _set_id,
			.get_id = _get_id,
		},
		.from_port = from_port,
		.to_port = to_port,
		.protocol = protocol,
		.type = type,
	);
	if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
	{
		this->from_port = from_port < 256 ? from_port << 8 : from_port;
		this->to_port = to_port < 256 ? to_port << 8 : to_port;
	}
	return this;
}

traffic_selector_t *traffic_selector_create_from_fcsp2_format(chunk_t start_address, uint16_t start_type,
												chunk_t end_address, uint16_t end_type,
												uint8_t start_rctl, uint8_t end_rctl)
{
	ts_type_t type = TS_FC_ADDR_RANGE;
	private_traffic_selector_t *this = traffic_selector_create(IPPROTO_RAW, type,
			start_type, end_type);

	memset(this->from, 0x0, start_address.len);
	memcpy(this->from, start_address.ptr, start_address.len);
	this->starting_r_ctl = start_rctl;

	memset(this->to, 0x0, end_address.len);
	memcpy(this->to, end_address.ptr, end_address.len);
	this->ending_r_ctl = end_rctl;

	return &this->public;
}
