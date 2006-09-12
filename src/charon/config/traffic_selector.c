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
#include <stdio.h>

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
	 * string representation of this traffic selector
	 */
	char *string;
};

/**
 * calculate to "to"-address for the "from" address and a subnet size
 */
static void calc_range(private_traffic_selector_t *this, u_int8_t netbits)
{
	int byte;
	size_t size = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;
	
	/* go through the from address, starting at the tail. While we
	 * have not processed the bits belonging to the host, set them to 1 on
	 * the to address. If we reach the bits for the net, copy them from "from". */
	for (byte = size - 1; byte >=0; byte--)
	{
		u_char mask = 0x00;
		int shift;
		
		shift = (byte+1) * 8 - netbits;
		if (shift > 0)
		{
			mask = 1 << shift;
			if (mask != 0xFF)
			{
				mask--;
			}
		}
		this->to[byte] = this->from[byte] | mask;
	}
}

/**
 * calculate to subnet size from "to"- and "from"-address
 */
static u_int8_t calc_netbits(private_traffic_selector_t *this)
{
	int byte, bit;
	size_t size = (this->type == TS_IPV4_ADDR_RANGE) ? 4 : 16;
	
	/* go trough all bits of the addresses, begging in the front. 
	 * As longer as they equal, the subnet gets larger */
	for (byte = 0; byte < size; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			if ((1<<bit & this->from[byte]) != (1<<bit & this->to[byte]))
			{
				return ((7 - bit) + (byte * 8));
			}
		}
	}
	/* single host, netmask is 32/128 */
	return (size * 8);
}


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
		u_int8_t mask;
		
		/* build address string */
		inet_ntop(AF_INET, &this->from4, addr_str, sizeof(addr_str));
		
		/* build network mask string */
		mask = calc_netbits(this);
		snprintf(mask_str, sizeof(mask_str), "/%d", mask);
	}
	else
	{
		u_int8_t mask;
		
		/* build address string */
		inet_ntop(AF_INET6, &this->from6, addr_str, sizeof(addr_str));
		
		/* build network mask string */
		mask = calc_netbits(this);
		snprintf(mask_str, sizeof(mask_str), "/%d", mask);
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
		new_ts->type = this->type;
		memcpy(new_ts->from, from, size);
		memcpy(new_ts->to, to, size);
		update_string(new_ts);
		
		return &new_ts->public;
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
	if (!(this->from_port == other->from_port &&
		  this->to_port == other->to_port &&
		  this->protocol == other->protocol))
	{
		return FALSE;
	}
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
			if (memeq(this->from4, other->from4, sizeof(this->from4)))
			{
				return TRUE;
			}
			break;
		case TS_IPV6_ADDR_RANGE:
			if (memeq(this->from6, other->from6, sizeof(this->from6)))
			{
				return TRUE;
			}
			break;
		default:
			break;
	}
	return FALSE;
}

/**
 * Implements traffic_selector_t.get_from_address.
 */
static chunk_t get_from_address(private_traffic_selector_t *this)
{
	chunk_t from = CHUNK_INITIALIZER;
	
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			from.len = sizeof(this->from4);
			from.ptr = malloc(from.len);
			memcpy(from.ptr, this->from4, from.len);
			break;
		}
		case TS_IPV6_ADDR_RANGE:
		{
			from.len = sizeof(this->from6);
			from.ptr = malloc(from.len);
			memcpy(from.ptr, this->from6, from.len);
			break;
		}
	}
	return from;
}
	
/**
 * Implements traffic_selector_t.get_to_address.
 */
static chunk_t get_to_address(private_traffic_selector_t *this)
{
	chunk_t to = CHUNK_INITIALIZER;
	
	switch (this->type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			to.len = sizeof(this->to4);
			to.ptr = malloc(to.len);
			memcpy(to.ptr, this->to4, to.len);
			break;
		}
		case TS_IPV6_ADDR_RANGE:
		{
			to.len = sizeof(this->to6);
			to.ptr = malloc(to.len);
			memcpy(to.ptr, this->to6, to.len);
			break;
		}
	}
	return to;
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
	if ((this->type == TS_IPV4_ADDR_RANGE && this->from4[0] == 0) ||
		(this->type == TS_IPV6_ADDR_RANGE && this->from6[0] == 0 &&
		 this->from6[1] == 0 && this->from6[2] == 0 && this->from6[3] == 0))
	{
		this->type = host->get_family(host) == AF_INET ?
						TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE;
		
		chunk_t from = host->get_address(host);
		memcpy(this->from, from.ptr, from.len);
		memcpy(this->to, from.ptr, from.len);
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
			memcpy(clone->from4, this->from4, sizeof(this->from4));
			memcpy(clone->to4, this->to4, sizeof(this->to4));
			update_string(clone);
			return &clone->public;
		}
		case TS_IPV6_ADDR_RANGE:
		{
			memcpy(clone->from6, this->from6, sizeof(this->from6));
			memcpy(clone->to6, this->to6, sizeof(this->to6));
			update_string(clone);
			return &clone->public;
		}
		default:
		{
			/* unreachable */
			return &clone->public;
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
traffic_selector_t *traffic_selector_create_from_bytes(u_int8_t protocol, ts_type_t type, chunk_t from, u_int16_t from_port, chunk_t to, u_int16_t to_port)
{
	private_traffic_selector_t *this = traffic_selector_create(protocol, type, from_port, to_port);
	
	switch (type)
	{
		case TS_IPV4_ADDR_RANGE:
		{
			if (from.len != 4 || to.len != 4)
			{
				free(this);
				return NULL;
			}
			memcpy(this->from4, from.ptr, from.len);
			memcpy(this->to4, to.ptr, to.len);
			break;
		}
		case TS_IPV6_ADDR_RANGE:
		{
			if (from.len != 16 || to.len != 16)
			{
				free(this);
				return NULL;
			}
			memcpy(this->from6, from.ptr, from.len);
			memcpy(this->to6, to.ptr, to.len);
			break;
		}
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
			memcpy(this->from4, from.ptr, from.len);
			if (this->from4[0] == 0)
			{
				/* use /0 for 0.0.0.0 */
				this->to4[0] = ~0;
			}
			else
			{
				calc_range(this, netbits);
			}
			break;
		}
		case AF_INET6:
		{
			chunk_t from;
			
			this->type = TS_IPV6_ADDR_RANGE;
			from = net->get_address(net);
			memcpy(this->from6, from.ptr, from.len);
			if (this->from6[0] == 0 && this->from6[1] == 0 &&
				this->from6[2] == 0 && this->from6[3] == 0)
			{
				/* use /0 for ::0 */
				this->to6[0] = ~0;
				this->to6[1] = ~0;
				this->to6[2] = ~0;
				this->to6[3] = ~0;
			}
			else
			{
				calc_range(this, netbits);
			}
			break;
		}
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
		}
		case TS_IPV6_ADDR_RANGE:
		{
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
