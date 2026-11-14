/*
 * Copyright (C) 2026 Manuel Montesdeoca
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
 * @defgroup cfg_subnet_handler cfg_subnet_handler
 * @{ @ingroup cfg_subnet
 */

#ifndef CFG_SUBNET_HANDLER_H_
#define CFG_SUBNET_HANDLER_H_

#include <sa/ike_sa_id.h>
#include <attributes/attribute_handler.h>

typedef struct cfg_subnet_handler_t cfg_subnet_handler_t;

/**
 * Requests the INTERNAL_IP4_SUBNET/INTERNAL_IP6_SUBNET attributes via the
 * IKEv2 configuration payload and stores the subnets received from the
 * server as traffic selectors.
 */
struct cfg_subnet_handler_t {

	/**
	 * Implements attribute_handler_t.
	 */
	attribute_handler_t handler;

	/**
	 * Create an enumerator over subnets received for an IKE_SA.
	 *
	 * @param id			IKE_SA ID to get received subnets for
	 * @return				enumerator over traffic_selector_t*
	 */
	enumerator_t* (*create_include_enumerator)(cfg_subnet_handler_t *this,
											   ike_sa_id_t *id);

	/**
	 * Associate the subnets stored for an IKE_SA with its rekeyed successor.
	 *
	 * @param old			ID of the rekeyed IKE_SA
	 * @param new			ID of the new IKE_SA
	 */
	void (*migrate_includes)(cfg_subnet_handler_t *this,
							 ike_sa_id_t *old, ike_sa_id_t *new);

	/**
	 * Remove all subnets stored for an IKE_SA.
	 *
	 * @param id			IKE_SA ID to remove subnets for
	 */
	void (*remove_includes)(cfg_subnet_handler_t *this, ike_sa_id_t *id);

	/**
	 * Destroy a cfg_subnet_handler_t.
	 */
	void (*destroy)(cfg_subnet_handler_t *this);
};

/**
 * Create a cfg_subnet_handler instance.
 */
cfg_subnet_handler_t *cfg_subnet_handler_create();

#endif /** CFG_SUBNET_HANDLER_H_ @}*/
