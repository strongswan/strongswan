/**
 * @file fetcher.c
 * 
 * @brief Implementation of fetcher_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <fetcher://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "fetcher.h"

typedef struct private_fetcher_t private_fetcher_t;

/**
 * @brief Private Data of a h object.
 */
struct private_fetcher_t {
	/**
	 * Public data
	 */
	fetcher_t public;
	
};

/**
 * Implements fetcher_t.get
 */
static chunk_t get(private_fetcher_t *this, chunk_t uri)
{
	
}

/**
 * Implements fetcher_t.destroy
 */
static void destroy(private_fetcher_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
fetcher_t *fetcher_create(void)
{
	private_fetcher_t *this = malloc_thing(private_fetcher_t);
	
	/* initialize */

	/* public functions */
	this->public.get = (chunk_t (*) (fetcher_t*,chunk_t))get;
	this->public.destroy = (void (*) (fetcher_t*))destroy;

	return &this->public;
}
