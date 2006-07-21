/**
 * @file traffic_selector.c
 * 
 * @brief Implementation of traffic_selector_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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

#include "traffic_selector.h"

#include <utils/linked_list.h>
#include <utils/identification.h>

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
	
	/**
	 * string representation of this traffic selector
	 */
	char *string;
};

/**
 * internal generic constructor
 */
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol, ts_type_t type, u_int16_t from_port, u_int16_t to_port);

/**
 * update the string representation of this traffic selector
 */
static void update_string(private_traffic_selector_t *this)
{
	char buf[256];
	struct protoent *proto;
	struct servent *serv;
	char *serv_proto = NULL;
	char proto_str[8] = "";
	char addr_str[INET6_ADDRSTRLEN];
	char port_str[16] = "";
	char mask_str[8] = "";
	char proto_port_str[32] = "";
	bool has_proto = FALSE, has_port = FALSE;
	
	if (this->type == TS_IPV4_ADDR_RANGE)
	{
		u_int32_t from_no, to_no, bit;
		u_int8_t mask = 32;
		
		/* build address string */
		from_no = htonl(this->from_addr_ipv4);
		to_no = htonl(this->to_addr_ipv4);
		inet_ntop(AF_INET, &from_no, addr_str, sizeof(addr_str));
		
		/* build network mask string */
		for (bit = 0; bit < 32; bit++)
		{
			if ((1<<bit & from_no) != (1<<bit & to_no))
			{
				mask = bit;
				break;
			}
		}
		if (mask != 32)
		{
			snprintf(mask_str, sizeof(mask_str), "/%d", mask);
		}
	}
	else
	{
		/* TODO: be a little bit more verbose ;-) */
		snprintf(addr_str, sizeof(addr_str), "(IPv6 address range)");
	}
	
	/* build protocol string */
	if (this->protocol)
	{
		proto = getprotobynumber(this->protocol);
		if (proto)
		{
			snprintf(proto_str, sizeof(proto_str), "%s", proto->p_name);
			serv_proto = proto->p_name;
		}
		else
		{
			snprintf(proto_str, sizeof(proto_str), "%d", this->protocol);
		}
		has_proto = TRUE;
	}
	
	/* build port string */
	if (this->from_port == this->to_port)
	{
		serv = getservbyport(htons(this->from_port), serv_proto);
		if (serv)
		{
			snprintf(port_str, sizeof(port_str), "%s", serv->s_name);
		}
		else
		{
			snprintf(port_str, sizeof(port_str), "%d", this->from_port);
		}
		has_port = TRUE;
	}
	else if (!(this->from_port == 0 && this->to_port == 0xFFFF))
	{
		snprintf(port_str, sizeof(port_str), "%d-%d",
				 this->from_port, this->to_port);
		has_port = TRUE;
	}
	
	/* concatenate port & proto string */
	if (has_proto && has_port)
	{
		snprintf(proto_port_str, sizeof(proto_port_str), "[%s/%s]", 
				 proto_str, port_str);
	}
	else if (has_proto)
	{
		snprintf(proto_port_str, sizeof(proto_port_str), "[%s]", proto_str);
	}
	else if (has_port)
	{
		snprintf(proto_port_str, sizeof(proto_port_str), "[%s]", port_str);
	}
	
	/* concatenate it all */
	snprintf(buf, sizeof(buf), "%s%s%s", addr_str, mask_str, proto_port_str);

	if (this->string)
	{
		free(this->string);
	}
	this->string = strdup(buf);
}

/**
 * implements traffic_selector_t.get_string
 */
static char *get_string(private_traffic_selector_t *this)
{
	return this->string;
}

/**
 * implements traffic_selector_t.get_subset
 */
static traffic_selector_t *get_subset(private_traffic_selector_t *this, private_traffic_selector_t *other)
{
	if ((this->type == TS_IPV4_ADDR_RANGE) && (other->type == TS_IPV4_ADDR_RANGE) &&
		(this->protocol == other->protocol || this->protocol == 0 || other->protocol == 0))
	{
		u_int32_t from_addr, to_addr;
		u_int16_t from_port, to_port;
		u_int8_t protocol;
		private_traffic_selector_t *new_ts;
		
		/* calculate the maximum address range allowed for both */
		from_addr = max(this->from_addr_ipv4, other->from_addr_ipv4);
		to_addr = min(this->to_addr_ipv4, other->to_addr_ipv4);
		if (from_addr > to_addr)
		{
			return NULL;
		}
		
		/* calculate the maximum port range allowed for both */
		from_port = max(this->from_port, other->from_port);
		to_port = min(this->to_port, other->to_port);
		if (from_port > to_port)
		{
			return NULL;
		}
		
		/* select protocol, which is not zero */
		protocol = max(this->protocol, other->protocol);
		
		/* got a match, return it */
		new_ts = traffic_selector_create(protocol, this->type, from_port, to_port); 
		new_ts->from_addr_ipv4 = from_addr;
		new_ts->to_addr_ipv4 = to_addr;
		new_ts->type = TS_IPV4_ADDR_RANGE;
		update_string(new_ts);
		
		return &(new_ts->public);
	}
	return NULL;
}

/**
 * implements traffic_selector_t.equals
 */
static bool equals(private_traffic_selector_t *this, private_traffic_selector_t *other)
{
	if (this->type != other->type)
	{
		return FALSE;
	}
	if (this->type == TS_IPV4_ADDR_RANGE)
	{
		if (this->from_addr_ipv4 == other->from_addr_ipv4 &&
			this->to_addr_ipv4 == other->to_addr_ipv4 &&
			this->from_port == other->from_port &&
			this->to_port == other->to_port &&
			this->protocol == other->protocol)
		{
			return TRUE;
		}
	}
	return FALSE;
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
			from_addr.ptr = malloc(from_addr.len);
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
			to_addr.ptr = malloc(to_addr.len);
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
 * Implements traffic_selector_t.update_address_range.
 */
static void update_address_range(private_traffic_selector_t *this, host_t *host)
{
	if (host->get_family(host) == AF_INET &&
		this->type == TS_IPV4_ADDR_RANGE)
	{
		if (this->from_addr_ipv4 == 0)
		{
			chunk_t from = host->get_address(host);
			this->from_addr_ipv4 = ntohl(*((u_int32_t*)from.ptr));
			this->to_addr_ipv4 = this->from_addr_ipv4;
		}
	}
	update_string(this);
}

/**
 * Implements traffic_selector_t.clone.
 */
static traffic_selector_t *clone_(private_traffic_selector_t *this)
{
	private_traffic_selector_t *clone;
	
	clone = traffic_selector_create(this->protocol, this->type, 
									this->from_port, this->to_port);
	switch (clone->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			clone->from_addr_ipv4 = this->from_addr_ipv4;
			clone->to_addr_ipv4 = this->to_addr_ipv4;
			update_string(clone);
			return &clone->public;
		}
		case TS_IPV6_ADDR_RANGE:
		default:
		{
			free(this);
			return NULL;	
		}
	}
}

/**
 * Implements traffic_selector_t.destroy.
 */
static void destroy(private_traffic_selector_t *this)
{
	free(this->string);
	free(this);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_bytes(u_int8_t protocol, ts_type_t type, chunk_t from_addr, u_int16_t from_port, chunk_t to_addr, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type, from_port, to_port);
	
	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			if (from_addr.len != 4 || to_addr.len != 4)
			{
				free(this);
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
			free(this);
			return NULL;	
		}
	}
	
	update_string(this);
	
	return (&this->public);
}

/*
 * see header
 */
traffic_selector_t *traffic_selector_create_from_subnet(host_t *net, u_int8_t netbits, u_int8_t protocol, u_int16_t port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, 0, 0, 65535);

	switch (net->get_family(net))
	{
		case AF_INET:
		{
			chunk_t from;
			
			this->type = TS_IPV4_ADDR_RANGE;
			from = net->get_address(net);
			this->from_addr_ipv4 = ntohl(*((u_int32_t*)from.ptr));
			if (this->from_addr_ipv4 == 0)
			{
				/* use /0 for 0.0.0.0 */
				this->to_addr_ipv4 = ~0;
			}
			else
			{
				this->to_addr_ipv4 = this->from_addr_ipv4 | ((1 << (32 - netbits)) - 1);
			}
			break;	
		}
		case AF_INET6:
		default:
		{
			free(this);
			return NULL;	
		}
	}
	if (port)
	{
		this->from_port = port;
		this->to_port = port;
	}
	
	update_string(this);
	
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
				free(this);
				return NULL;
			}
			if (inet_aton(to_addr, (struct in_addr*)&(this->to_addr_ipv4)) == 0)
			{
				free(this);
				return NULL;
			}
			/* convert to host order, inet_aton has network order */
			this->from_addr_ipv4 = ntohl(this->from_addr_ipv4);
			this->to_addr_ipv4 = ntohl(this->to_addr_ipv4);
			break;	
		}
		case TS_IPV6_ADDR_RANGE:
		{
			free(this);
			return NULL;	
		}
	}
	
	update_string(this);
	
	return (&this->public);
}

/*
 * see declaration
 */
static private_traffic_selector_t *traffic_selector_create(u_int8_t protocol, ts_type_t type, u_int16_t from_port, u_int16_t to_port)
{
	private_traffic_selector_t *this = malloc_thing(private_traffic_selector_t);

	/* public functions */
	this->public.get_subset = (traffic_selector_t*(*)(traffic_selector_t*,traffic_selector_t*))get_subset;
	this->public.equals = (bool(*)(traffic_selector_t*,traffic_selector_t*))equals;
	this->public.get_string = (char*(*)(traffic_selector_t*))get_string;
	this->public.get_from_address = (chunk_t(*)(traffic_selector_t*))get_from_address;
	this->public.get_to_address = (chunk_t(*)(traffic_selector_t*))get_to_address;
	this->public.get_from_port = (u_int16_t(*)(traffic_selector_t*))get_from_port;
	this->public.get_to_port = (u_int16_t(*)(traffic_selector_t*))get_to_port;	
	this->public.get_type = (ts_type_t(*)(traffic_selector_t*))get_type;	
	this->public.get_protocol = (u_int8_t(*)(traffic_selector_t*))get_protocol;
	this->public.update_address_range = (void(*)(traffic_selector_t*,host_t*))update_address_range;
	this->public.clone = (traffic_selector_t*(*)(traffic_selector_t*))clone_;
	this->public.destroy = (void(*)(traffic_selector_t*))destroy;
	
	this->from_port = from_port;
	this->to_port = to_port;
	this->protocol = protocol;
	this->type = type;
	this->string = NULL;
	
	return this;
}
