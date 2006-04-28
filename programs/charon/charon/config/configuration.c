/**
 * @file configuration.c
 * 
 * @brief Implementation of configuration_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <stdlib.h>

#include "configuration.h"

#include <types.h>

/**
 * First retransmit timeout in milliseconds.
 * Timeout value is increasing in each retransmit round.
 */
#define RETRANSMIT_TIMEOUT 3000

/**
 * Timeout in milliseconds after that a half open IKE_SA gets deleted.
 */
#define HALF_OPEN_IKE_SA_TIMEOUT 30000

/**
 * Max retransmit count.
 * 0 for infinite. The max time a half open IKE_SA is alive is set by 
 * RETRANSMIT_TIMEOUT.
 */
#define MAX_RETRANSMIT_COUNT 0


typedef struct private_configuration_t private_configuration_t;

/**
 * Private data of an configuration_t object.
 */
struct private_configuration_t {

	/**
	 * Public part of configuration_t object.
	 */
	configuration_t public;

};

/**
 * Implementation of configuration_t.get_retransmit_timeout.
 */
static status_t get_retransmit_timeout (private_configuration_t *this, u_int32_t retransmit_count, u_int32_t *timeout)
{
	int new_timeout = RETRANSMIT_TIMEOUT, i;
	if (retransmit_count > MAX_RETRANSMIT_COUNT && MAX_RETRANSMIT_COUNT != 0)
	{
		return FAILED;
	}
	
	for (i = 0; i < retransmit_count; i++)
	{
		new_timeout *= 2;
	}
	
	*timeout = new_timeout;
	
	return SUCCESS;
}

/**
 * Implementation of configuration_t.get_half_open_ike_sa_timeout.
 */
static u_int32_t get_half_open_ike_sa_timeout (private_configuration_t *this)
{
	return HALF_OPEN_IKE_SA_TIMEOUT;
}

/**
 * Implementation of configuration_t.destroy.
 */
static void destroy(private_configuration_t *this)
{
	free(this);
}

/*
 * Described in header-file
 */
configuration_t *configuration_create()
{
	private_configuration_t *this = malloc_thing(private_configuration_t);
	
	/* public functions */
	this->public.destroy = (void(*)(configuration_t*))destroy;
	this->public.get_retransmit_timeout = (status_t (*) (configuration_t *, u_int32_t retransmit_count, u_int32_t *timeout))get_retransmit_timeout;
	this->public.get_half_open_ike_sa_timeout = (u_int32_t (*) (configuration_t *)) get_half_open_ike_sa_timeout;
	
	return (&this->public);
}
