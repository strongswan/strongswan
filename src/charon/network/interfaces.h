/**
 * @file interfaces.h
 *
 * @brief Interface of interfaces_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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
 
#ifndef INTERFACES_H_
#define INTERFACES_H_

#include <utils/linked_list.h>
#include <utils/host.h>

typedef struct interfaces_t interfaces_t;

/**
 * @brief Provides methods to enumerate local interfaces
 *
 * @b Constructors:
 * - interfaces_create()
 * 
 * @todo Handle changes in interface list.
 *
 * @ingroup network
 */
struct interfaces_t {

	/**
	 * @brief Get an iterator over addresses of local interfaces
	 *
	 * @param this		calling object
	 * @return			iterator over host_t objects
	 */
	iterator_t* (*create_address_iterator) (interfaces_t *this);
	
	/**
	 * @brief Check if address is associated with a local interface
	 *
	 * @param this		calling object
	 * @param host		address to set as destination
	 * @return			TRUE if address is associated with a local interface, FALSE otherwise
	 */
	bool (*is_local_address) (interfaces_t *this, host_t *host);
	
	/**
	 * @brief Destroy the object, freeing contained data.
	 *
	 * @param this		object to destroy
	 */
	void (*destroy) (interfaces_t *ifaces);
};

/**
 * @brief Create an object of type interfaces_t
 *
 * @param port		the port that gets added to the addresses
 * 
 * @return interfaces_t object
 *
 * @ingroup network
 */
interfaces_t *interfaces_create(u_int16_t port);


#endif /* INTERFACES_H_ */
