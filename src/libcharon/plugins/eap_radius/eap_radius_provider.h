/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup eap_radius_provider eap_radius_provider
 * @{ @ingroup eap_radius
 */

#ifndef EAP_RADIUS_PROVIDER_H_
#define EAP_RADIUS_PROVIDER_H_

#include <attributes/attribute_provider.h>

typedef struct eap_radius_provider_t eap_radius_provider_t;

/**
 * IKE configuration attribute fed by RADIUS attributes
 */
struct eap_radius_provider_t {

	/**
	 * Implements attribute_provider_t
	 */
	attribute_provider_t provider;

	/**
	 * Add a received Framed-IP-Address to the provider to serve to client.
	 *
	 * @param id			client identity
	 * @param ip			IP address received from RADIUS server, gets owned
	 */
	void (*add_framed_ip)(eap_radius_provider_t *this, identification_t *id,
						  host_t *ip);

	/**
	 * Destroy a eap_radius_provider_t.
	 */
	void (*destroy)(eap_radius_provider_t *this);
};

/**
 * Create a eap_radius_provider instance.
 */
eap_radius_provider_t *eap_radius_provider_create();

/**
 * Get singleton instance previously created with eap_radius_provider_create().
 */
eap_radius_provider_t *eap_radius_provider_get();

#endif /** EAP_RADIUS_PROVIDER_H_ @}*/
