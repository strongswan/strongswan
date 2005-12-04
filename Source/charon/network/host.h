/**
 * @file host.h
 *
 * @brief Interface of host_t.
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

#ifndef HOST_H_
#define HOST_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>

#include <types.h>


typedef struct host_t host_t;

/**
 * @brief Representates a Host
 * 
 * Host object, identifies a host and defines some useful functions on it.
 * 
 * @ingroup network
 */
struct host_t {
	/** 
	 * @brief Build a clone of this host object.
	 * 
	 * @param this			object to clone
	 * @return				cloned host
	 */
	host_t *(*clone) (host_t *this);
	
	/** 
	 * @brief Get a pointer to the internal sockaddr struct.
	 * 
	 * This is used for sending and receiving via sockets.
	 * 
	 * @param this			object to clone
	 * @return				pointer to the internal sockaddr structure
	 */
	sockaddr_t  *(*get_sockaddr) (host_t *this);
	
	/** 
	 * @brief Get the length of the sockaddr struct.
	 * 
	 * Sepending on the family, the length of the sockaddr struct
	 * is different. Use this function to get the length of the sockaddr
	 * struct returned by get_sock_addr.
	 * 
	 * This is used for sending and receiving via sockets.
	 * 
	 * @param this			object to clone
	 * @return				length of the sockaddr struct
	 */
	socklen_t *(*get_sockaddr_len) (host_t *this);
	
	/**
	 * @brief Gets the address as xfrm_address_t.
	 */
	xfrm_address_t (*get_xfrm_addr) (host_t *this);
	
	/**
	 * @brief Gets the address as xfrm_address_t.
	 */
	int (*get_family) (host_t *this);
	
	/** 
	 * @brief get the address of this host
	 * 
	 * Mostly used for debugging purposes. 
	 * @warning string must NOT be freed
	 * 
	 * @param this			object
	 * @return				address string, 
	 */
	char* (*get_address) (host_t *this);
	
	/** 
	 * @brief Checks if the ip address of host is set to default route.
	 * 
	 * @param this			calling object
	 * @return				
	 * 						- TRUE if host has IP 0.0.0.0 for default route 
	 * 						- FALSE otherwise
	 */
	bool (*is_default_route) (host_t *this);
	
	/** 
	 * @brief get the address of this host as chunk_t
	 * 
	 * @warning returned chunk has to get destroyed by caller.
	 * 
	 * @param this			object
	 * @return				address string, 
	 */
	chunk_t (*get_address_as_chunk) (host_t *this);
		
	/** 
	 * @brief get the port of this host
	 * 
	 * Mostly used for debugging purposes. 
	 * 
	 * @param this			object to clone
	 * @return				port number
	 */
	u_int16_t (*get_port) (host_t *this);
		
	/** 
	 * @brief Compare the ips of two hosts hosts.
	 * 
	 * @param this			object to compare
	 * @param other			the other to compare
	 * @return				TRUE if addresses are equal.
	 */
	bool (*ip_is_equal) (host_t *this, host_t *other);
	
	/** 
	 * @brief Destroy this host object
	 * 
	 * @param this			calling
	 * @return				SUCCESS in any case
	 */
	void (*destroy) (host_t *this);
};

/**
 * @brief Constructor to create a host_t object
 * 
 * Currently supports only IPv4!
 *
 * @param family 		Address family to use for this object, such as AF_INET or AF_INET6
 * @param address		string of an address, such as "152.96.193.130"
 * @param port			port number
 * @return 				
 * 						- the host_t object, or 
 * 						- NULL, when family not supported.
 * 
 * @ingroup network
 */
host_t *host_create(int family, char *address, u_int16_t port);

/**
 * @brief Constructor to create a host_t object
 * 
 * Currently supports only IPv4!
 *
 * @param family 		Address family to use for this object, such as AF_INET or AF_INET6
 * @param address		address as 4 byte chunk_t in networ order
 * @param port			port number
 * @return 				
 * 						- the host_t object, or 
 * 						- NULL, when family not supported or chunk_t length not 4 bytes.
 * 
 * @ingroup network
 */
host_t *host_create_from_chunk(int family, chunk_t address, u_int16_t port);
#endif /*HOST_H_*/
