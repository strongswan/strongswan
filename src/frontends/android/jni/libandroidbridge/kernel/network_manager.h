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

/**
 * @defgroup network_manager network_manager
 * @{ @ingroup kernel_android
 */

#ifndef NETWORK_MANAGER_H_
#define NETWORK_MANAGER_H_

#include <jni.h>

#include <library.h>
#include <utils/host.h>

typedef struct network_manager_t network_manager_t;

/**
 * NetworkManager, used to retrieve local IP addresses.
 *
 * Communicates with NetworkManager via JNI
 */
struct network_manager_t {

	/**
	 * Get a local address
	 *
	 * @param ipv4				TRUE to get an IPv4 address
	 * @return					the address or NULL if none available
	 */
	host_t *(*get_local_address)(network_manager_t *this, bool ipv4);

	/**
	 * Destroy a network_manager_t instance
	 */
	void (*destroy)(network_manager_t *this);
};

/**
 * Create a network_manager_t instance
 *
 * @return						network_manager_t instance
 */
network_manager_t *network_manager_create();

#endif /** NETWORK_MANAGER_H_ @}*/
