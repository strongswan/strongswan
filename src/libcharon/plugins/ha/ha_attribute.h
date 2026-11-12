/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup ha_attribute ha_attribute
 * @{ @ingroup ha
 */

#ifndef HA_ATTRIBUTE_H_
#define HA_ATTRIBUTE_H_

#include "ha_kernel.h"
#include "ha_segments.h"

#include <attributes/attribute_provider.h>

typedef struct ha_attribute_t ha_attribute_t;

/**
 * A HA enabled in memory address pool attribute provider.
 */
struct ha_attribute_t {

	/**
	 * Implements attribute provider interface.
	 */
	attribute_provider_t provider;

	/**
	 * Reserve an address for a passive IKE_SA.
	 *
	 * @param ike_sa		passive IKE_SA the address is reserved for
	 * @param name			pool name to reserve address in
	 * @param address		address to reserve
	 */
	void (*reserve)(ha_attribute_t *this, ike_sa_t *ike_sa, char *name,
					host_t *address);

	/**
	 * Migrate address ownership from one IKE_SA to another.
	 *
	 * Used when IKE rekeying moves remote virtual IPs from an old SA to the
	 * new one without releasing them to the pool.
	 *
	 * @param old			old IKE_SA
	 * @param new			new IKE_SA that inherits the virtual IPs
	 */
	void (*migrate)(ha_attribute_t *this, ike_sa_t *old, ike_sa_t *new);

	/**
	 * Update the remote endpoint hash associated with leases of an SA so
	 * make-before-break reauth can reassign the same virtual IP later.
	 *
	 * @param ike_sa		IKE_SA that changed
	 * @param remote		new remote endpoint
	 */
	void (*update)(ha_attribute_t *this, ike_sa_t *ike_sa, host_t *remote);

	/**
	 * Let leases get adopted by the given IKE_SA.
	 *
	 * This is only used for IKEv1 to cover the multiple adopt/migrate VIPs
	 * paths.
	 *
	 * @param ike_sa		new IKE_SA that adopted the virtual IPs
	 */
	void (*adopt)(ha_attribute_t *this, ike_sa_t *ike_sa);

	/**
	 * Cleanup leases owned by the given IKE_SA if another still owns the same
	 * address or if it can't release them itself later.
	 *
	 * This is only used by IKEv1 to handle VIPs that were adopted without being
	 * released.
	 *
	 * @param ike_sa		IKE_SA for which to release virtual IPs
	 */
	void (*cleanup)(ha_attribute_t *this, ike_sa_t *ike_sa);

	/**
	 * Destroy a ha_attribute_t.
	 */
	void (*destroy)(ha_attribute_t *this);
};

/**
 * Create a ha_attribute instance.
 */
ha_attribute_t *ha_attribute_create(ha_kernel_t *kernel, ha_segments_t *segments);

#endif /** HA_ATTRIBUTE_H_ @}*/
