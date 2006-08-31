/**
 * @file host.h
 *
 * @brief Interface of host_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

typedef enum host_diff_t host_diff_t;

/**
 * Differences between two hosts. They differ in
 * address, port, or both.
 */
enum host_diff_t {
	HOST_DIFF_NONE = 0,
	HOST_DIFF_ADDR = 1,
	HOST_DIFF_PORT = 2,
};

typedef struct host_t host_t;

/**
 * @brief Representates a Host
 * 
 * Host object, identifies a address:port pair and defines some 
 * useful functions on it.
 * 
 * @b Constructors:
 * - host_create()
 * - host_create_from_chunk()
 * - host_create_from_sockaddr()
 * 
 * @todo Add IPv6 support
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
	 * Depending on the family, the length of the sockaddr struct
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
	 * @brief Gets the family of the address
	 * 
	 * @param this			calling object
	 * @return				family
	 */
	int (*get_family) (host_t *this);
	
	/** 
	 * @brief Get the address of this host as a string
	 * 
	 * Mostly used for debugging purposes. String
	 * points to internal data.
	 * 
	 * @param this			object
	 * @return				address string, 
	 */
	char* (*get_string) (host_t *this);
	
	/** 
	 * @brief Checks if the ip address of host is set to default route.
	 * 
	 * @param this			calling object
	 * @return				
	 * 						- TRUE if host has IP 0.0.0.0 for default route 
	 * 						- FALSE otherwise
	 */
	bool (*is_anyaddr) (host_t *this);
	
	/** 
	 * @brief get the address of this host as chunk_t
	 * 
	 * Returned chunk points to internal data.
	 * 
	 * @param this			object
	 * @return				address string, 
	 */
	chunk_t (*get_address) (host_t *this);
		
	/** 
	 * @brief get the port of this host
	 * 
	 * @param this			object to clone
	 * @return				port number
	 */
	u_int16_t (*get_port) (host_t *this);

	/** 
	 * @brief set the port of this host
	 *
	 * @param this			object to clone
	 * @param port			port numer
	 */
	void (*set_port) (host_t *this, u_int16_t port);
		
	/** 
	 * @brief Compare the ips of two hosts hosts.
	 * 
	 * @param this			object to compare
	 * @param other			the other to compare
	 * @return				TRUE if addresses are equal.
	 */
	bool (*ip_equals) (host_t *this, host_t *other);
		
	/** 
	 * @brief Compare two hosts, with port.
	 * 
	 * @param this			object to compare
	 * @param other			the other to compare
	 * @return				TRUE if addresses and ports are equal.
	 */
	bool (*equals) (host_t *this, host_t *other);

	/** 
	 * @brief Compare two hosts and return the differences.
	 *
	 * @param this			object to compare
	 * @param other			the other to compare
	 * @return				differences in a combination of host_diff_t's
	 */
	host_diff_t (*get_differences) (host_t *this, host_t *other);
	
	/** 
	 * @brief Destroy this host object
	 * 
	 * @param this			calling
	 * @return				SUCCESS in any case
	 */
	void (*destroy) (host_t *this);
};

/**
 * @brief Constructor to create a host_t object from an address string
 *
 * @param family 		Address family to use for this object, such as AF_INET or AF_INET6
 * @param address		string of an address, such as "152.96.193.130"
 * @param port			port number
 * @return 				
 * 						- host_t object 
 * 						- NULL, if family not supported/invalid string.
 * 
 * @ingroup network
 */
host_t *host_create(int family, char *address, u_int16_t port);

/**
 * @brief Same as host_create(), but guesses the family.
 *
 * @param string		string of an address, such as "152.96.193.130"
 * @param port			port number
 * @return 				
 * 						- host_t object 
 * 						- NULL, if string not an address.
 * 
 * @ingroup network
 */
host_t *host_create_from_string(char *string, u_int16_t port);

/**
 * @brief Constructor to create a host_t object from an address chunk
 *
 * @param family 		Address family to use for this object, such as AF_INET or AF_INET6
 * @param address		address as 4 byte chunk_t in networ order
 * @param port			port number
 * @return 				
 * 						- host_t object 
 * 						- NULL, if family not supported or chunk_t length not 4 bytes.
 * 
 * @ingroup network
 */
host_t *host_create_from_chunk(int family, chunk_t address, u_int16_t port);

/**
 * @brief Constructor to create a host_t object from a sockaddr struct
 *
 * @param sockaddr		sockaddr struct which contains family, address and port
 * @return 				
 * 						- host_t object 
 * 						- NULL, if family not supported.
 * 
 * @ingroup network
 */
host_t *host_create_from_sockaddr(sockaddr_t *sockaddr);


#endif /*HOST_H_*/
