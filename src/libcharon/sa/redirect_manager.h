/*
 * Copyright (C) 2015 Tobias Brunner
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
 * @defgroup redirect_manager redirect_manager
 * @{ @ingroup sa
 */

#ifndef REDIRECT_MANAGER_H_
#define REDIRECT_MANAGER_H_

typedef struct redirect_manager_t redirect_manager_t;

#include <sa/redirect_provider.h>

/**
 * Manages redirect providers.
 */
struct redirect_manager_t {

	/**
	 * Add a redirect provider.
	 *
	 * All registered providers are queried until one of them decides to
	 * redirect a client.
	 *
	 * A provider may be called concurrently for different IKE_SAs.
	 *
	 * @param provider	provider to register
	 */
	void (*add_provider)(redirect_manager_t *this,
						 redirect_provider_t *provider);

	/**
	 * Remove a redirect provider.
	 *
	 * @param provider	provider to unregister
	 */
	void (*remove_provider)(redirect_manager_t *this,
							redirect_provider_t *provider);

	/**
	 * Determine whether a client should be redirected upon receipt of the
	 * IKE_SA_INIT message.
	 *
	 * @param ike_sa		IKE_SA for which this is called
	 * @param gateway[out]	new IKE gateway (IP or FQDN)
	 * @return				TRUE if client should be redirected, FALSE otherwise
	 */
	bool (*redirect_on_init)(redirect_manager_t *this, ike_sa_t *ike_sa,
							 identification_t **gateway);

	/**
	 * Determine whether a client should be redirected after the IKE_AUTH has
	 * been handled.  Should be called after the client is authenticated and
	 * when the server authenticates itself.
	 *
	 * @param ike_sa		IKE_SA for which this is called
	 * @param gateway[out]	new IKE gateway (IP or FQDN)
	 * @return				TRUE if client should be redirected, FALSE otherwise
	 */
	bool (*redirect_on_auth)(redirect_manager_t *this, ike_sa_t *ike_sa,
							 identification_t **gateway);

	/**
	 * Destroy this instance.
	 */
	void (*destroy)(redirect_manager_t *this);
};

/**
 * Create a redirect manager instance.
 *
 * @return					manager instance
 */
redirect_manager_t *redirect_manager_create();

#endif /** REDIRECT_MANAGER_H_ @}*/
