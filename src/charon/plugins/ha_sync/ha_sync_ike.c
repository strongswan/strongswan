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
 *
 * $Id$
 */

#include "ha_sync_ike.h"

typedef struct private_ha_sync_ike_t private_ha_sync_ike_t;

/**
 * Private data of an ha_sync_ike_t object.
 */
struct private_ha_sync_ike_t {

	/**
	 * Public ha_sync_ike_t interface.
	 */
	ha_sync_ike_t public;

	/**
	 * socket we use for syncing
	 */
	ha_sync_socket_t *socket;
};

/**
 * Implementation of listener_t.ike_keys
 */
static bool ike_keys(private_ha_sync_ike_t *this, ike_sa_t *ike_sa,
					 diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r,
					 ike_sa_t *rekey)
{
	return TRUE;
}

/**
 * Implementation of ha_sync_ike_t.destroy.
 */
static void destroy(private_ha_sync_ike_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_sync_ike_t *ha_sync_ike_create(ha_sync_socket_t *socket)
{
	private_ha_sync_ike_t *this = malloc_thing(private_ha_sync_ike_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.ike_keys = (bool(*)(listener_t*, ike_sa_t *ike_sa, diffie_hellman_t *dh,chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey))ike_keys;
	this->public.destroy = (void(*)(ha_sync_ike_t*))destroy;

	this->socket = socket;

	return &this->public;
}

