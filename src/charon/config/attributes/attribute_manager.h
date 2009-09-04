/*
 * Copyright (C) 2008-2009 Martin Willi
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
 * @defgroup attribute_manager attribute_manager
 * @{ @ingroup attributes
 */

#ifndef ATTRIBUTE_MANAGER_H_
#define ATTRIBUTE_MANAGER_H_

#include <config/attributes/attribute_provider.h>
#include <config/attributes/attribute_handler.h>

typedef struct attribute_manager_t attribute_manager_t;

/**
 * The attribute manager hands out attributes or handles them.
 *
 * The attribute manager manages both, attribute providers and attribute
 * handlers. Attribute providers are responsible to hand out attributes if
 * a connecting peer requests them. Handlers handle such attributes if they
 * are received on the requesting peer.
 */
struct attribute_manager_t {

	/**
	 * Acquire a virtual IP address to assign to a peer.
	 *
	 * @param pool			pool name to acquire address from
	 * @param id			peer identity to get address forua
	 * @param requested		IP in configuration request
	 * @return				allocated address, NULL to serve none
	 */
	host_t* (*acquire_address)(attribute_manager_t *this,
							   char *pool, identification_t *id,
							   host_t *requested);

	/**
	 * Release a previously acquired address.
	 *
	 * @param pool			pool name from which the address was acquired
	 * @param address		address to release
	 * @param id			peer identity to get address for
	 */
	void (*release_address)(attribute_manager_t *this,
							char *pool, host_t *address, identification_t *id);

	/**
	 * Create an enumerator over attributes to hand out to a peer.
	 *
	 * @param id			peer identity to hand out attributes to
	 * @return				enumerator (configuration_attribute_type_t, chunk_t)
	 */
	enumerator_t* (*create_attribute_enumerator)(attribute_manager_t *this,
												 identification_t *id);

	/**
	 * Register an attribute provider to the manager.
	 *
	 * @param provider		attribute provider to register
	 */
	void (*add_provider)(attribute_manager_t *this,
						 attribute_provider_t *provider);
	/**
	 * Unregister an attribute provider from the manager.
	 *
	 * @param provider		attribute provider to unregister
	 */
	void (*remove_provider)(attribute_manager_t *this,
							attribute_provider_t *provider);

	/**
	 * Handle a configuration attribute by passing them to the handlers.
	 *
	 * @param ike_sa		IKE_SA where attribute was received
	 * @param type			type of configuration attribute
	 * @param data			associated attribute data
	 * @return				handler which handled this attribute, NULL if none
	 */
	attribute_handler_t* (*handle)(attribute_manager_t *this, ike_sa_t *ike_sa,
							configuration_attribute_type_t type, chunk_t data);

	/**
	 * Release an attribute previously handle()d by a handler.
	 *
	 * @param handler		handler returned by handle() for this attribute
	 * @param ike_sa		IKE_SA owning the attribute
	 * @param type			type of attribute to release
	 * @param data			associated attribute data
	 */
	void (*release)(attribute_manager_t *this, attribute_handler_t *handler,
						ike_sa_t *ike_sa, configuration_attribute_type_t type,
						chunk_t data);

	/**
	 * Register an attribute handler to the manager.
	 *
	 * @param handler		attribute handler to register
	 */
	void (*add_handler)(attribute_manager_t *this,
						attribute_handler_t *handler);

	/**
	 * Unregister an attribute handler from the manager.
	 *
	 * @param handler		attribute handler to unregister
	 */
	void (*remove_handler)(attribute_manager_t *this,
						   attribute_handler_t *handler);

	/**
	 * Destroy a attribute_manager instance.
	 */
	void (*destroy)(attribute_manager_t *this);
};

/**
 * Create a attribute_manager instance.
 */
attribute_manager_t *attribute_manager_create();

#endif /** ATTRIBUTE_MANAGER_H_ @}*/
