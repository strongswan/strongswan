/**
 * @file child_sa.c
 *
 * @brief Implementation of child_sa_t.
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

#include "child_sa.h"


#include <utils/allocator.h>

typedef struct private_child_sa_t private_child_sa_t;

/**
 * Private data of an child_sa_t object
 */
struct private_child_sa_t {
	/**
	 * Public part of a child_sa object
	 */
	child_sa_t public;
	
	/**
	 * type of this child sa, ESP or AH
	 */
	protocol_id_t sa_type;
	
	
};


/**
 * implements child_sa_t.clone.
 */
static u_int32_t get_spi(private_child_sa_t *this)
{
	return 0;
}

/**
 * implements child_sa_t.clone.
 */
static void destroy(private_child_sa_t *this)
{
	allocator_free(this);
}

/*
 * Described in Header-File
 */
child_sa_t * child_sa_create(protocol_id_t sa_type, prf_plus_t *prf_plus)
{
	private_child_sa_t *this = allocator_alloc_thing(private_child_sa_t);

	/* Public functions */
	this->public.get_spi = (u_int32_t(*)(child_sa_t*))get_spi;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->sa_type = sa_type;
	

	
	
	return (&this->public);
}
