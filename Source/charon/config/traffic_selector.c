/**
 * @file traffic_selector.c
 * 
 * @brief Implementation of traffic_selector_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "traffic_selector.h"

#include <utils/linked_list.h>
#include <utils/allocator.h>
#include <utils/identification.h>
#include <arpa/inet.h>

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
	 * begin of address range, host order
	 */
	union {
		u_int32_t from_addr_ipv4;
	};
	
	/**
	 * end of address range, host order
	 */
	union {
		u_int32_t to_addr_ipv4;
	};
	
	/**
	 * begin of port range 
	 */
	u_int16_t from_port;
	
	/**
	 * end of port range 
	 */
	u_int16_t to_port;
};

/**
 * internal generic constructor
 */
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol, ts_type_t type, u_int16_t from_port, u_int16_t to_port);

/**
 * implements traffic_selector_t.get_subset
 */
static traffic_selector_t *get_subset(private_traffic_selector_t *this, private_traffic_selector_t *other)
{
	if ((this->type == TS_IPV4_ADDR_RANGE) &&
		(other->type == TS_IPV4_ADDR_RANGE) &&
		(this->protocol == other->protocol))
	{
		u_int32_t from_addr, to_addr;
		u_int16_t from_port, to_port;
		private_traffic_selector_t *new_ts;
		
		/* calculate the maximum address range allowed for both */
		from_addr = max(this->from_addr_ipv4, other->from_addr_ipv4);
		to_addr = min(this->to_addr_ipv4, other->to_addr_ipv4);
		if (from_addr > to_addr)
		{
			/* no match */
			return NULL;	
		}
		
		/* calculate the maximum port range allowed for both */
		from_port = max(this->from_port, other->from_port);
		to_port = min(this->to_port, other->to_port);
		if (from_port > to_port)
		{
			/* no match */
			return NULL;	
		}
		
		/* got a match, return it */
		new_ts = traffic_selector_create(this->protocol, this->type, from_port, to_port); 
		new_ts->from_addr_ipv4 = from_addr;
		new_ts->to_addr_ipv4 = to_addr;
		new_ts->type = TS_IPV4_ADDR_RANGE;
		return &(new_ts->public);
	}
	return NULL;
}

/**
 * Implements traffic_selector_t.get_from_address.
 */
static chunk_t get_from_address(private_traffic_selector_t *this)
{
	chunk_t from_addr = CHUNK_INITIALIZER;
	
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			u_int32_t network;
			from_addr.len = sizeof(network);
			from_addr.ptr = allocator_alloc(from_addr.len);
			/* chunk must contain network order, convert! */
			network = htonl(this->from_addr_ipv4);
			memcpy(from_addr.ptr, &network, from_addr.len);
			break;	
		}
		case TS_IPV6_ADDR_RANGE:
		{
			break;
		}
	}
	return from_addr;
}
	
/**
 * Implements traffic_selector_t.get_to_address.
 */
static chunk_t get_to_address(private_traffic_selector_t *this)
{
	chunk_t to_addr = CHUNK_INITIALIZER;
	
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			u_int32_t network;
			to_addr.len = sizeof(network);
			to_addr.ptr = allocator_alloc(to_addr.len);
			/* chunk must contain network order, convert! */
			network = htonl(this->to_addr_ipv4);
			memcpy(to_addr.ptr, &network, to_addr.len);
			break;	
		}
		case TS_IPV6_ADDR_RANGE:
		{
			break;
		}
	}
	return to_addr;
}
	
/**
 * Implements traffic_selector_t.get_from_port.
 */
static u_int16_t get_from_port(private_traffic_selector_t *this)
{
	return this->from_port;
}
	
/**
 * Implements traffic_selector_t.get_to_port.
 */
static u_int16_t get_to_port(private_traffic_selector_t *this)
{
	return this->to_port;
}

/**
 * Implements traffic_selector_t.get_type.
 */
static ts_type_t get_type(private_traffic_selector_t *this)
{
	return this->type;
}

/**
 * Implements traffic_selector_t.get_protocol.
 */
static u_int8_t get_protocol(private_traffic_selector_t *this)
{
	return this->protocol;
}

/**
 * Implements traffic_selector_t.get_netmask.
 */
static u_int8_t get_netmask(private_traffic_selector_t *this)
{
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			u_int32_t from, to, bit;
			from = htonl(this->from_addr_ipv4);
			to = htonl(this->to_addr_ipv4);
			for (bit = 0; bit < 32; bit++)
			{				
				if ((1<<bit & from) != (1<<bit & to))
				{
					return bit;
				}
			}
			return 0;
		}
		case TS_IPV6_ADDR_RANGE:
		default:
		{
			return 0;
		}
	}
}

/**
 * Implements traffic_selector_t.clone.
 */
static traffic_selector_t *clone(private_traffic_selector_t *this)
{
	private_traffic_selector_t *clone = traffic_selector_create(this->protocol, this->type, this->from_port, this->to_port);
	clone->type = this->type;
	switch (clone->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			clone->from_addr_ipv4 = this->from_addr_ipv4;
			clone->to_addr_ipv4 = this->to_addr_ipv4;
			return &(clone->public);	
		}
		case TS_IPV6_ADDR_RANGE:
		default:
		{
			allocator_free(this);
			return NULL;	
		}
	}
}

/**
 * Implements traffic_selector_t.destroy.
 */
static void destroy(private_traffic_selector_t *this)
{	
	allocator_free(this);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_bytes(u_int8_t protocol, ts_type_t type, chunk_t from_addr, int16_t from_port, chunk_t to_addr, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type, from_port, to_port);

	this->type = type;
	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			if (from_addr.len != 4 || to_addr.len != 4)
			{
				allocator_free(this);
				return NULL;	
			}
			/* chunk contains network order, convert! */
			this->from_addr_ipv4 = ntohl(*((u_int32_t*)from_addr.ptr));
			this->to_addr_ipv4 = ntohl(*((u_int32_t*)to_addr.ptr));
			break;	
		}
		case TS_IPV6_ADDR_RANGE:
		default:
		{
			allocator_free(this);
			return NULL;	
		}
	}
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_subnet(host_t *net, u_int8_t netbits)
{
	private_traffic_selector_t *this = traffic_selector_create(0, 0, 0, 65535);

	switch (net->get_family(net))
	{
		case AF_INET:
		{
			chunk_t from;
			
			this->type = TS_IPV4_ADDR_RANGE;
			from = net->get_address_as_chunk(net);
			this->from_addr_ipv4 = ntohl(*((u_int32_t*)from.ptr));
			this->to_addr_ipv4 = this->from_addr_ipv4 | ((1 << (32 - netbits)) - 1);
			allocator_free_chunk(&from);
			break;	
		}
		case AF_INET6:
		default:
		{
			allocator_free(this);
			return NULL;	
		}
	}
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_string(u_int8_t protocol, ts_type_t type, char *from_addr, u_int16_t from_port, char *to_addr, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type, from_port, to_port);

	/* public functions */
	this->public.get_subset = (traffic_selector_t*(*)(traffic_selector_t*,traffic_selector_t*))get_subset;
	this->public.destroy = (void(*)(traffic_selector_t*))destroy;

	this->type = type;
	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			if (inet_aton(from_addr, (struct in_addr*)&(this->from_addr_ipv4)) == 0)
			{
				allocator_free(this);
				return NULL;
			}
			if (inet_aton(to_addr, (struct in_addr*)&(this->to_addr_ipv4)) == 0)
			{
				allocator_free(this);
				return NULL;
			}
			/* convert to host order, inet_aton has network order */
			this->from_addr_ipv4 = ntohl(this->from_addr_ipv4);
			this->to_addr_ipv4 = ntohl(this->to_addr_ipv4);
			break;	
		}
		case TS_IPV6_ADDR_RANGE:
		{
			allocator_free(this);
			return NULL;	
		}
	}

	return (&this->public);
}

/*
 * see declaration
 */
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol, ts_type_t type, u_int16_t from_port, u_int16_t to_port)
{
	private_traffic_selector_t *this = allocator_alloc_thing(private_traffic_selector_t);

	/* public functions */
	this->public.get_subset = (traffic_selector_t*(*)(traffic_selector_t*,traffic_selector_t*))get_subset;
	this->public.get_from_address = (chunk_t(*)(traffic_selector_t*))get_from_address;
	this->public.get_to_address = (chunk_t(*)(traffic_selector_t*))get_to_address;
	this->public.get_from_port = (u_int16_t(*)(traffic_selector_t*))get_from_port;
	this->public.get_to_port = (u_int16_t(*)(traffic_selector_t*))get_to_port;	
	this->public.get_type = (ts_type_t(*)(traffic_selector_t*))get_type;	
	this->public.get_protocol = (u_int8_t(*)(traffic_selector_t*))get_protocol;
	this->public.get_netmask = (u_int8_t(*)(traffic_selector_t*))get_netmask;
	this->public.clone = (traffic_selector_t*(*)(traffic_selector_t*))clone;
	this->public.destroy = (void(*)(traffic_selector_t*))destroy;
	
	this->from_port = from_port;
	this->to_port = to_port;
	this->protocol = protocol;
	this->type = type;
	
	return this;
}
