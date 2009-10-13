/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup attribute_provider attribute_provider
 * @{ @ingroup attributes
 */

#ifndef ATTRIBUTE_PROVIDER_H_
#define ATTRIBUTE_PROVIDER_H_

#include <utils/host.h>
#include <utils/identification.h>

typedef struct attribute_provider_t attribute_provider_t;

/**
 * Interface to provide attributes to peers through attribute manager.
 */
struct attribute_provider_t {

	/**
	 * Acquire a virtual IP address to assign to a peer.
	 *
	 * @param pool			name of the pool to acquire address from
	 * @param id			peer ID
	 * @param requested		IP in configuration request
	 * @return				allocated address, NULL to serve none
	 */
	host_t* (*acquire_address)(attribute_provider_t *this,
							   char *pool, identification_t *id,
							   host_t *requested);
	/**
	 * Release a previously acquired address.
	 *
	 * @param pool			name of the pool this address was acquired from
	 * @param address		address to release
	 * @param id			peer ID
	 * @return				TRUE if the address has been released by the provider
	 */
	bool (*release_address)(attribute_provider_t *this,
							char *pool, host_t *address, identification_t *id);

	/**
	 * Create an enumerator over attributes to hand out to a peer.
	 *
	 * @param id			peer ID
	 * @return				enumerator (configuration_attribute_type_t, chunk_t)
	 */
	enumerator_t* (*create_attribute_enumerator)(attribute_provider_t *this,
												 identification_t *id);
};

#endif /** ATTRIBUTE_PROVIDER_H_ @}*/
