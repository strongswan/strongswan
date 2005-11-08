/**
 * @file generator.c
 * 
 * @brief Generic generator class used to generate IKEv2-Header and Payload
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "types.h"
#include "generator.h"

/**
 * Private data of a generator_t object
 */
typedef struct private_generator_s private_generator_t;
 
struct private_generator_s { 	
	/**
	 * Public part of a generator object
	 */
	 generator_t public;
};

static status_t generate_payload (private_generator_t *this,payload_type_t payload_type,void * data_struct, chunk_t *data)
{
	return FAILED;
}

/**
 * Implementation of generator_t's destroy function
 */
static status_t destroy(private_generator_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}

	pfree(this);
	return SUCCESS;
}


generator_t * generator_create()
{
	private_generator_t *this = alloc_thing(private_generator_t,"private_generator_t");
	
	this->public.generate_payload = (status_t(*)(generator_t*, payload_type_t, void *, chunk_t *)) generate_payload;
	this->public.destroy = (status_t(*)(generator_t*)) destroy;
	
	return &(this->public);
}
