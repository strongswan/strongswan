/*
 * Copyright (C) 2007-2012 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>

#include "traffic_selector.h"

#include <utils/linked_list.h>
#include <utils/identification.h>
#include <debug.h>

#define NON_SUBNET_ADDRESS_RANGE	255

ENUM(ts_type_name, TS_IPV4_ADDR_RANGE, TS_IPV6_ADDR_RANGE,
	"TS_IPV4_ADDR_RANGE",
	"TS_IPV6_ADDR_RANGE",
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
	u_int8_t protocol;

	/**
	 * narrow this traffic selector to hosts external ip
	 * if set, from and to have no meaning until set_address() is called
	 */
	bool dynamic;

	/**
	 * subnet size in CIDR notation, 255 means a non-subnet address range
	 */
	u_int8_t netbits;

	/**
	 * begin of address range, network order
	 */
	union {
		/** dummy char for common address manipulation */
		char from[0];
		/** IPv4 address */
		u_int32_t from4[1];
		/** IPv6 address */
		u_int32_t from6[4];
	};

	/**
	 * end of address range, network order
	 */
	union {
		/** dummy char for common address manipulation */
		char to[0];
		/** IPv4 address */
		u_int32_t to4[1];
		/** IPv6 address */
		u_int32_t to6[4];
	};

	/**
	 * begin of port range
	 */
	u_int16_t from_port;

	/**
	 * end of port range
	 */
	u_int16_t to_port;

	/**
	 * list of subnets this address range consists of (subnet_t*)
	 */
	linked_list_t *subnets;
};

/**
 * Used to cache splitted subnets.
 */
typedef struct {
	/** network address */
	host_t *net;
	/** network bits */
	int netmask;
} subnet_t;

/**
 * Destroy a subnet.
 */
static void subnet_destroy(subnet_t *this)
{
	this->net->destroy(this->net);
	free(this);
}

/**
 * calculate the "to"-address for the "from" address and a subnet size
 */
static void calc_range(private_traffic_selector_t *this, u_int8_t netbits)
{
	size_t len;
	int bytes, bits;
	u_int8_t mask;

	this->netbits = netbits;

	len   = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;
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
static u_int8_t calc_netbits(private_traffic_selector_t *this)
{
	int byte, bit;
	u_int8_t netbits;
	size_t size = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;
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
			u_int8_t bitmask = 1 << bit;

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
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol, ts_type_t type, u_int16_t from_port, u_int16_t to_port);

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
	char *serv_proto = NULL;
	bool has_proto;
	bool has_ports;
	size_t written = 0;
	u_int32_t from[4], to[4];

	if (this == NULL)
	{
		return print_in_hook(data, "(null)");
	}

	if (spec->hash)
	{
		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, (void**)&this))
		{
			/* call recursivly */
			written += print_in_hook(data, "%R ", this);
		}
		enumerator->destroy(enumerator);
		return written;
	}

	memset(from, 0, sizeof(from));
	memset(to, 0xFF, sizeof(to));
	if (this->dynamic &&
		memeq(this->from, from, this->type == TS_IPV4_ADDR_RANGE ? 4 : 16) &&
		memeq(this->to, to, this->type == TS_IPV4_ADDR_RANGE ? 4 : 16))
	{
		written += print_in_hook(data, "dynamic");
	}
	else
	{
		if (this->type == TS_IPV4_ADDR_RANGE)
		{
			inet_ntop(AF_INET, &this->from4, from_str, sizeof(from_str));
		}
		else
		{
			inet_ntop(AF_INET6, &this->from6, from_str, sizeof(from_str));
		}
		if (this->netbits == NON_SUBNET_ADDRESS_RANGE)
		{
			if (this->type == TS_IPV4_ADDR_RANGE)
			{
				inet_ntop(AF_INET, &this->to4, to_str, sizeof(to_str));
			}
			else
			{
				inet_ntop(AF_INET6, &this->to6, to_str, sizeof(to_str));
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
	has_ports = !(this->from_port == 0 && this->to_port == 0xFFFF);

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

	if (has_proto && has_ports)
	{
		written += print_in_hook(data, "/");
	}

	/* build port string */
	if (has_ports)
	{
		if (this->from_port == this->to_port)
		{
			struct servent *serv = getservbyport(htons(this->from_port), serv_proto);

			if (serv)
			{
				written += print_in_hook(data, "%s", serv->s_name);
			}
			else
			{
				written += print_in_hook(data, "%d", this->from_port);
			}
		}
		else
		{
			written += print_in_hook(data, "%d-%d", this->from_port, this->to_port);
		}
	}

	written += print_in_hook(data, "]");

	return written;
}

/**
 * Implements traffic_selector_t.get_subset
 */
static traffic_selector_t *get_subset(private_traffic_selector_t *this,
									  private_traffic_selector_t *other)
{
	if (this->type == other->type && (this->protocol == other->protocol ||
								this->protocol == 0 || other->protocol == 0))
	{
		u_int16_t from_port, to_port;
		u_char *from, *to;
		u_int8_t protocol;
		size_t size;
		private_traffic_selector_t *new_ts;

		/* calculate the maximum port range allowed for both */
		from_port = max(this->from_port, other->from_port);
		to_port = min(this->to_port, other->to_port);
		if (from_port > to_port)
		{
			return NULL;
		}
		/* select protocol, which is not zero */
		protocol = max(this->protocol, other->protocol);

		switch (this->type)
		{
			case TS_IPV4_ADDR_RANGE:
				size = sizeof(this->from4);
				break;
			case TS_IPV6_ADDR_RANGE:
				size = sizeof(this->from6);
				break;
			default:
				return NULL;
		}

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
		new_ts = traffic_selector_create(protocol, this->type, from_port, to_port);
		new_ts->dynamic = this->dynamic || other->dynamic;
		memcpy(new_ts->from, from, size);
		memcpy(new_ts->to, to, size);
		calc_netbits(new_ts);
		return &new_ts->public;
	}
	return NULL;
}

/**
 * Implements traffic_selector_t.equals
 */
static bool equals(private_traffic_selector_t *this, private_traffic_selector_t *other)
{
	if (this->type != other->type)
	{
		return FALSE;
	}
	if (!(this->from_port == other->from_port &&
		  this->to_port == other->to_port &&
		  this->protocol == other->protocol))
	{
		return FALSE;
	}
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			if (memeq(this->from4, other->from4, sizeof(this->from4)) &&
				memeq(this->to4, other->to4, sizeof(this->to4)))
			{
				return TRUE;
			}
			break;
		case TS_IPV6_ADDR_RANGE:
			if (memeq(this->from6, other->from6, sizeof(this->from6)) &&
				memeq(this->to6, other->to6, sizeof(this->to6)))
			{
				return TRUE;
			}
			break;
		default:
			break;
	}
	return FALSE;
}

METHOD(traffic_selector_t, get_from_address, chunk_t,
	private_traffic_selector_t *this)
{
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			return chunk_create(this->from, sizeof(this->from4));
		case TS_IPV6_ADDR_RANGE:
			return chunk_create(this->from, sizeof(this->from6));
		default:
			return chunk_empty;
	}
}

METHOD(traffic_selector_t, get_to_address, chunk_t,
	private_traffic_selector_t *this)
{
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			return chunk_create(this->to, sizeof(this->to4));
		case TS_IPV6_ADDR_RANGE:
			return chunk_create(this->to, sizeof(this->to6));
		default:
			return chunk_empty;
	}
}

METHOD(traffic_selector_t, get_from_port, u_int16_t,
	private_traffic_selector_t *this)
{
	return this->from_port;
}

METHOD(traffic_selector_t, get_to_port, u_int16_t,
	private_traffic_selector_t *this)
{
	return this->to_port;
}

METHOD(traffic_selector_t, get_type, ts_type_t,
	private_traffic_selector_t *this)
{
	return this->type;
}

METHOD(traffic_selector_t, get_protocol, u_int8_t,
	private_traffic_selector_t *this)
{
	return this->protocol;
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
	}
	else
	{
		size_t length = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;

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
	if (this->dynamic)
	{
		this->type = host->get_family(host) == AF_INET ?
				TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE;

		if (host->is_anyaddr(host))
		{
			memset(this->from6, 0x00, sizeof(this->from6));
			memset(this->to6, 0xFF, sizeof(this->to6));
			this->netbits = 0;
		}
		else
		{
			chunk_t from = host->get_address(host);
			memcpy(this->from, from.ptr, from.len);
			memcpy(this->to, from.ptr, from.len);
			this->netbits = from.len * 8;
		}
		DESTROY_FUNCTION_IF(this->subnets, (void*)subnet_destroy);
		this->subnets = NULL;
	}
}

/**
 * Implements traffic_selector_t.is_contained_in.
 */
static bool is_contained_in(private_traffic_selector_t *this,
							private_traffic_selector_t *other)
{
	private_traffic_selector_t *subset;
	bool contained_in = FALSE;

	subset = (private_traffic_selector_t*)get_subset(this, other);

	if (subset)
	{
		if (equals(subset, this))
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

	if ((family == AF_INET && this->type == TS_IPV4_ADDR_RANGE) ||
		(family == AF_INET6 && this->type == TS_IPV6_ADDR_RANGE))
	{
		addr = host->get_address(host);

		return memcmp(this->from, addr.ptr, addr.len) <= 0 &&
				memcmp(this->to, addr.ptr, addr.len) >= 0;
	}

	return FALSE;
}

METHOD(traffic_selector_t, to_subnet, bool,
	private_traffic_selector_t *this, host_t **net, u_int8_t *mask)
{
	/* there is no way to do this cleanly, as the address range may
	 * be anything else but a subnet. We use from_addr as subnet
	 * and try to calculate a usable subnet mask.
	 */
	int family, non_zero_bytes;
	u_int16_t port = 0;
	chunk_t net_chunk;

	*mask = (this->netbits == NON_SUBNET_ADDRESS_RANGE) ? calc_netbits(this)
														: this->netbits;

	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			family = AF_INET;
			net_chunk.len = sizeof(this->from4);
			break;
		case TS_IPV6_ADDR_RANGE:
			family = AF_INET6;
			net_chunk.len = sizeof(this->from6);
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

/**
 * Insert a subnet into the list of subnets sorted by increasing address.
 * The address is not masked, i.e. host bits are expected to be 0.
 */
static void add_subnet(private_traffic_selector_t *this, chunk_t addr,
					   int netmask)
{
	enumerator_t *enumerator;
	subnet_t *subnet, *current;
	u_int16_t port = 0;
	int family;

	family = (this->type == TS_IPV4_ADDR_RANGE) ? AF_INET : AF_INET6;

	if (this->to_port == this->from_port)
	{
		port = this->to_port;
	}

	INIT(subnet,
		.net = host_create_from_chunk(family, addr, port),
		.netmask = netmask,
	);

	enumerator = this->subnets->create_enumerator(this->subnets);
	while (enumerator->enumerate(enumerator, &current))
	{
		int cmp = chunk_compare(current->net->get_address(current->net), addr);
		if (cmp > 0 || (cmp == 0 && current->netmask > subnet->netmask))
		{
			break;
		}
	}
	this->subnets->insert_before(this->subnets, enumerator, subnet);
	enumerator->destroy(enumerator);
}

/**
 * Split the address range of this traffic selector into a list of subnets.
 *
 * This list is sorted by increasing net address and cached.
 */
static void split_range(private_traffic_selector_t *this)
{
	static const u_char bitmask[] = { 0x80, 0x40, 0x20, 0x10,
									  0x08, 0x04, 0x02, 0x01 };
	int len, byte = 0, bit = 0, prefix, netmask, common_byte, common_bit,
		from_cur, from_prev, to_cur, to_prev;
	bool from_full = TRUE, to_full = TRUE;
	chunk_t from, to;

	/* clone addresses as host bits get modified */
	len = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;
	from = chunk_clonea(chunk_create(this->from, len));
	to = chunk_clonea(chunk_create(this->to, len));

	/* find a common prefix */
	while ((from.ptr[byte] & bitmask[bit]) == (to.ptr[byte] & bitmask[bit]) &&
			byte < from.len)
	{
		if (++bit == 8)
		{
			bit = 0;
			byte++;
		}
	}
	prefix = byte * 8 + bit;

	/* at this point we know that the addresses are either equal, or that the
	 * current bits in the 'from' and 'to' addresses are 0 and 1, respectively.
	 * we now look at the rest of the bits as two binary trees (0=left, 1=right)
	 * where 'from' and 'to' are both leaf nodes.  all leaf nodes between these
	 * nodes are addresses contained in the range.  to collect them as subnets
	 * we follow the trees from both leaf nodes to their root node and record
	 * all complete subtrees (right for from, left for to) we come across as
	 * subnets.  in that process host bits are zeroed out.  if both addresses
	 * are equal we won't enter the loop below.
	 *      0_____|_____1       for the 'from' address we assume we start on a
	 *   0__|__ 1    0__|__1    left subtree (0) and follow the left edges until
	 *  _|_   _|_   _|_   _|_   we reach the root of this subtree, which is
	 * |   | |   | |   | |   |  either the root of this whole 'from'-subtree
	 * 0   1 0   1 0   1 0   1  (causing us to leave the loop) or the root node
	 * of the right subtree (1) of another node (which actually could be the
	 * leaf node we start from).  that whole subtree gets recorded as subnet.
	 * next we follow the right edges to the root of that subtree which again is
	 * either the 'from'-root or the root node in the left subtree (0) of
	 * another node.  the complete right subtree of that node is the next subnet
	 * we record.  from there we assume that we are in that right subtree and
	 * recursively follow right edges to its root.  for the 'to' address the
	 * procedure is exactly the same but with left and right reversed.
	 */
	if (++bit == 8)
	{
		bit = 0;
		byte++;
	}
	common_byte = byte;
	common_bit = bit;
	netmask = from.len * 8;
	from_prev = 0, to_prev = 1;
	for (byte = from.len - 1; byte >= common_byte; byte--)
	{
		int bit_min = (byte == common_byte) ? common_bit : 0;
		for (bit = 7; bit >= bit_min; bit--)
		{
			u_char mask = bitmask[bit];

			from_cur = from.ptr[byte] & mask;
			if (!from_prev && from_cur)
			{	/* 0 -> 1: subnet is the whole current (right) subtree */
				add_subnet(this, from, netmask);
				from_full = FALSE;
			}
			else if (from_prev && !from_cur)
			{	/* 1 -> 0: invert bit to switch to right subtree and add it */
				from.ptr[byte] ^= mask;
				add_subnet(this, from, netmask);
				from_cur = 1;
			}
			/* clear the current bit */
			from.ptr[byte] &= ~mask;
			from_prev = from_cur;

			to_cur = to.ptr[byte] & mask;
			if (to_prev && !to_cur)
			{	/* 1 -> 0: subnet is the whole current (left) subtree */
				add_subnet(this, to, netmask);
				to_full = FALSE;
			}
			else if (!to_prev && to_cur)
			{	/* 0 -> 1: invert bit to switch to left subtree and add it */
				to.ptr[byte] ^= mask;
				add_subnet(this, to, netmask);
				to_cur = 0;
			}
			/* clear the current bit */
			to.ptr[byte] &= ~mask;
			to_prev = to_cur;
			netmask--;
		}
	}

	if (from_full && to_full)
	{	/* full subnet (from=to or from=0.. and to=1.. after common prefix) */
		add_subnet(this, from, prefix);
	}
	else if (from_full)
	{	/* full from subnet (from=0.. after prefix) */
		add_subnet(this, from, prefix + 1);
	}
	else if (to_full)
	{	/* full to subnet (to=1.. after prefix) */
		add_subnet(this, to, prefix + 1);
	}
}

/**
 * filter function for subnets
 */
static bool subnet_filter(void *data, subnet_t **in, host_t **net,
					   void **in2, u_int8_t *mask)
{
	*net = (*in)->net;
	*mask = (*in)->netmask;
	return TRUE;
}

METHOD(traffic_selector_t, create_subnet_enumerator, enumerator_t*,
	private_traffic_selector_t *this)
{
	if (!this->subnets)
	{
		this->subnets = linked_list_create();
		split_range(this);
	}
	return enumerator_create_filter(
							this->subnets->create_enumerator(this->subnets),
							(void*)subnet_filter, NULL, NULL);
}

METHOD(traffic_selector_t, clone_, traffic_selector_t*,
	private_traffic_selector_t *this)
{
	private_traffic_selector_t *clone;

	clone = traffic_selector_create(this->protocol, this->type,
									this->from_port, this->to_port);
	clone->netbits = this->netbits;
	clone->dynamic = this->dynamic;

	switch (clone->type)
	{
		case TS_IPV4_ADDR_RANGE:
			memcpy(clone->from4, this->from4, sizeof(this->from4));
			memcpy(clone->to4, this->to4, sizeof(this->to4));
			return &clone->public;
		case TS_IPV6_ADDR_RANGE:
			memcpy(clone->from6, this->from6, sizeof(this->from6));
			memcpy(clone->to6, this->to6, sizeof(this->to6));
			return &clone->public;
		default:
			/* unreachable */
			return &clone->public;
	}
}

METHOD(traffic_selector_t, destroy, void,
	private_traffic_selector_t *this)
{
	DESTROY_FUNCTION_IF(this->subnets, (void*)subnet_destroy);
	free(this);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_bytes(u_int8_t protocol,
												ts_type_t type,
												chunk_t from, u_int16_t from_port,
												chunk_t to, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type,
															from_port, to_port);

	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
			if (from.len != 4 || to.len != 4)
			{
				free(this);
				return NULL;
			}
			memcpy(this->from4, from.ptr, from.len);
			memcpy(this->to4, to.ptr, to.len);
			break;
		case TS_IPV6_ADDR_RANGE:
			if (from.len != 16 || to.len != 16)
			{
				free(this);
				return NULL;
			}
			memcpy(this->from6, from.ptr, from.len);
			memcpy(this->to6, to.ptr, to.len);
			break;
		default:
			free(this);
			return NULL;
	}
	calc_netbits(this);
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_rfc3779_format(ts_type_t type,
												chunk_t from, chunk_t to)
{
	size_t len;
	private_traffic_selector_t *this = traffic_selector_create(0, type, 0, 65535);

	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
			len = 4;
			break;
		case TS_IPV6_ADDR_RANGE:
			len = 16;
			break;
		default:
			free(this);
			return NULL;
	}
	memset(this->from, 0x00, len);
	memset(this->to  , 0xff, len);

	if (from.len > 1)
	{
		memcpy(this->from, from.ptr+1, from.len-1);
	}
	if (to.len > 1)
	{
		u_int8_t mask = to.ptr[0] ? (1 << to.ptr[0]) - 1 : 0;

		memcpy(this->to, to.ptr+1, to.len-1);
		this->to[to.len-2] |= mask;
	}
	this->netbits = chunk_equals(from, to) ? (from.len-1)*8 - from.ptr[0]
										   : NON_SUBNET_ADDRESS_RANGE;
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_subnet(host_t *net,
							u_int8_t netbits, u_int8_t protocol, u_int16_t port)
{
	private_traffic_selector_t *this;
	chunk_t from;

	this = traffic_selector_create(protocol, 0, 0, 65535);

	switch (net->get_family(net))
	{
		case AF_INET:
			this->type = TS_IPV4_ADDR_RANGE;
			break;
		case AF_INET6:
			this->type = TS_IPV6_ADDR_RANGE;
			break;
		default:
			net->destroy(net);
			free(this);
			return NULL;
	}
	from = net->get_address(net);
	memcpy(this->from, from.ptr, from.len);
	netbits = min(netbits, this->type == TS_IPV4_ADDR_RANGE ? 32 : 128);
	calc_range(this, netbits);
	if (port)
	{
		this->from_port = port;
		this->to_port = port;
	}
	net->destroy(net);

	return &this->public;
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_string(
										u_int8_t protocol, ts_type_t type,
										char *from_addr, u_int16_t from_port,
										char *to_addr, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type,
															from_port, to_port);

	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
			if (inet_pton(AF_INET, from_addr, (struct in_addr*)this->from4) < 0)
			{
				free(this);
				return NULL;
			}
			if (inet_pton(AF_INET, to_addr, (struct in_addr*)this->to4) < 0)
			{
				free(this);
				return NULL;
			}
			break;
		case TS_IPV6_ADDR_RANGE:
			if (inet_pton(AF_INET6, from_addr, (struct in6_addr*)this->from6) < 0)
			{
				free(this);
				return NULL;
			}
			if (inet_pton(AF_INET6, to_addr, (struct in6_addr*)this->to6) < 0)
			{
				free(this);
				return NULL;
			}
			break;
	}
	calc_netbits(this);
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_dynamic(u_int8_t protocol,
									u_int16_t from_port, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(
							protocol, TS_IPV4_ADDR_RANGE, from_port, to_port);

	memset(this->from6, 0, sizeof(this->from6));
	memset(this->to6, 0xFF, sizeof(this->to6));
	this->netbits = 0;
	this->dynamic = TRUE;

	return &this->public;
}

/*
 * see declaration
 */
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol,
						ts_type_t type, u_int16_t from_port, u_int16_t to_port)
{
	private_traffic_selector_t *this;

	INIT(this,
		.public = {
			.get_subset = (traffic_selector_t*(*)(traffic_selector_t*,traffic_selector_t*))get_subset,
			.equals = (bool(*)(traffic_selector_t*,traffic_selector_t*))equals,
			.get_from_address = _get_from_address,
			.get_to_address = _get_to_address,
			.get_from_port = _get_from_port,
			.get_to_port = _get_to_port,
			.get_type = _get_type,
			.get_protocol = _get_protocol,
			.is_host = _is_host,
			.is_dynamic = _is_dynamic,
			.is_contained_in = (bool(*)(traffic_selector_t*,traffic_selector_t*))is_contained_in,
			.includes = _includes,
			.set_address = _set_address,
			.to_subnet = _to_subnet,
			.create_subnet_enumerator = _create_subnet_enumerator,
			.clone = _clone_,
			.destroy = _destroy,
		},
		.from_port = from_port,
		.to_port = to_port,
		.protocol = protocol,
		.type = type,
	);

	return this;
}

