/**
 * @file traffic_selector.h
 * 
 * @brief Interface of traffic_selector_t.
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

#ifndef TRAFFIC_SELECTOR_H_
#define TRAFFIC_SELECTOR_H_

#include <types.h>
#include <utils/host.h>

typedef enum ts_type_t ts_type_t;

/**
 * Traffic selector types.
 * 
 * @ingroup config
 */
enum ts_type_t {
	
	/**
	 * A range of IPv4 addresses, represented by two four (4) octet
     * values.  The first value is the beginning IPv4 address
     * (inclusive) and the second value is the ending IPv4 address
     * (inclusive). All addresses falling between the two specified
     * addresses are considered to be within the list.
     */
	TS_IPV4_ADDR_RANGE = 7,
	
	/**
	 * A range of IPv6 addresses, represented by two sixteen (16)
     * octet values.  The first value is the beginning IPv6 address
     * (inclusive) and the second value is the ending IPv6 address
     * (inclusive). All addresses falling between the two specified
     *  addresses are considered to be within the list.
	 */
	TS_IPV6_ADDR_RANGE = 8
};

/**
 * string mappings for ts_type_t
 */
extern mapping_t ts_type_m[];


typedef struct traffic_selector_t traffic_selector_t;

/**
 * @brief Object representing a traffic selector entry.
 * 
 * A traffic selector defines an range of addresses
 * and a range of ports. IPv6 is not fully supported yet.
 * 
 * @b Constructors:
 * - traffic_selector_create_from_bytes()
 * - traffic_selector_create_from_string()
 * 
 * @todo Add IPv6 support
 * 
 * @ingroup config
 */
struct traffic_selector_t {
	
	/**
	 * @brief Compare two traffic selectors, and create a new one
	 * which is the largest subset of both (subnet & port).
	 *
	 * Resulting traffic_selector is newly created and must be destroyed.
	 *
	 * @param this		first to compare
	 * @param other		second to compare
	 * @return
	 * 					- created subset of them
	 * 					- or NULL if no match between this and other
	 */
	traffic_selector_t *(*get_subset)  (traffic_selector_t *this, 
										traffic_selector_t *other);
	
	/**
	 * @brief Clone a traffic selector.
	 *
	 * @param this		traffic selector to clone
	 * @return			clone of it
	 */
	traffic_selector_t *(*clone) (traffic_selector_t *this);
	
	/**
	 * @brief Get starting address of this ts as a chunk.
	 *
	 * Chunk is in network order gets allocated.
	 *
	 * @param this		calling object
	 * @return			chunk containing the address
	 */
	chunk_t (*get_from_address) (traffic_selector_t *this);
	
	/**
	 * @brief Get ending address of this ts as a chunk.
	 *
	 * Chunk is in network order gets allocated.
	 *
	 * @param this		calling object
	 * @return			chunk containing the address
	 */
	chunk_t (*get_to_address) (traffic_selector_t *this);
	
	/**
	 * @brief Get starting port of this ts.
	 * 
	 * Port is in host order, since the parser converts it.
	 * Size depends on protocol.
	 *  
	 * @param this		calling object
	 * @return			port
	 */
	u_int16_t (*get_from_port) (traffic_selector_t *this);
	
	/**
	 * @brief Get ending port of this ts.
	 *
	 * Port is in host order, since the parser converts it.
	 * Size depends on protocol.
	 *
	 * @param this		calling object
	 * @return			port
	 */
	u_int16_t (*get_to_port) (traffic_selector_t *this);
	
	/**
	 * @brief Get the type of the traffic selector.
	 *
	 * @param this		calling obect
	 * @return			ts_type_t specifying the type
	 */
	ts_type_t (*get_type) (traffic_selector_t *this);
	
	/**
	 * @brief Get the protocol id of this ts.
	 *
	 * @param this		calling obect
	 * @return			protocol id
	 */
	u_int8_t (*get_protocol) (traffic_selector_t *this);
	
	/**
	 * @brief Update the address of a traffic selector.
	 *
	 * Update the address range of a traffic selector, 
	 * if the current address is 0.0.0.0. The new address range
	 * starts from the supplied address and also ends there 
	 * (which means it is a one-host-address-range ;-).
	 *
	 * @param this		calling obect
	 * @param host		host_t specifying the address range
	 */
	void (*update_address_range) (traffic_selector_t *this, host_t* host);
	
	/**
	 * @brief Get a string representation of the traffic selector.
	 *
	 * String points to internal data, do not free/modify.
	 * 
	 * @param this		calling object
	 * @return 			pointer to a string.
	 */
	char* (*get_string) (traffic_selector_t *this);
	
	/**
	 * @brief Compare two traffic selectors for equality.
	 * 
	 * @param this		first to compare
	 * @param other		second to compare with first
	 * @return 			pointer to a string.
	 */
	bool (*equals) (traffic_selector_t *this, traffic_selector_t *other);
	
	/**
	 * @brief Destroys the ts object
	 *
	 * @param this		calling object
	 */
	void (*destroy) (traffic_selector_t *this);
};

/**
 * @brief Create a new traffic selector using human readable params.
 * 
 * @param protocol 		protocol for this ts, such as TCP or UDP
 * @param type			type of following addresses, such as TS_IPV4_ADDR_RANGE
 * @param from_addr		start of address range as string
 * @param from_port		port number in host order
 * @param to_addr		end of address range as string
 * @param to_port		port number in host order
 * @return
 * 						- traffic_selector_t object
 * 						- NULL if invalid address strings/protocol
 * 
 * @ingroup config
 */
traffic_selector_t *traffic_selector_create_from_string(
									u_int8_t protocol, ts_type_t type,
									char *from_addr, u_int16_t from_port,
									char *to_addr, u_int16_t to_port);

/**
 * @brief Create a new traffic selector using data read from the net.
 * 
 * There exists a mix of network and host order in the params.
 * But the parser gives us this data in this format, so we
 * don't have to convert twice.
 * 
 * @param protocol 		protocol for this ts, such as TCP or UDP
 * @param type			type of following addresses, such as TS_IPV4_ADDR_RANGE
 * @param from_address	start of address range, network order
 * @param from_port		port number, host order
 * @param to_address	end of address range as string, network
 * @param to_port		port number, host order
 * @return
 * 						- traffic_selector_t object
 * 						- NULL if invalid address input/protocol
 *
 * @ingroup config
 */
traffic_selector_t *traffic_selector_create_from_bytes(
								u_int8_t protocol, ts_type_t type,
								chunk_t from_address, u_int16_t from_port,
								chunk_t to_address, u_int16_t to_port);

/**
 * @brief Create a new traffic selector defining a whole subnet.
 * 
 * In most cases, definition of a traffic selector for full subnets
 * is sufficient. This constructor creates a traffic selector for
 * all protocols, all ports and the address range specified by the
 * subnet.
 * Additionally, a protocol and a port may be specified. Port ranges
 * are not supported via this constructor.
 * 
 * @param net			subnet to use
 * @param netbits		size of the subnet, as used in e.g. 192.168.0.0/24 notation
 * @return
 * 						- traffic_selector_t object
 * 						- NULL if address family of net not supported
 *
 * @ingroup config
 */
traffic_selector_t *traffic_selector_create_from_subnet(
									host_t *net, u_int8_t netbits, 
									u_int8_t protocol, u_int16_t port);

#endif /* TRAFFIC_SELECTOR_H_ */
