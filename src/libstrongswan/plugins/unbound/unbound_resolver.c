/*
 * Copyright (C) 2011-2012 Reto Guadagnini
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

#include <string.h>

#include <library.h>
#include <utils/debug.h>

#include "unbound_resolver.h"

typedef struct private_resolver_t private_resolver_t;

/**
 * private data of a unbound_resolver_t object.
 */
struct private_resolver_t {

	/**
	 * Public data
	 */
	resolver_t public;
};

/**
 * query method implementation
 */
METHOD(resolver_t, query, resolver_response_t*,
	private_resolver_t *this, char *domain, rr_class_t rr_class,
	rr_type_t rr_type)
{
	/* TODO: Implement */
	return NULL;
}

/**
 * destroy method implementation
 */
METHOD(resolver_t, destroy, void,
	private_resolver_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
resolver_t *unbound_resolver_create()
{
	private_resolver_t *this;

	INIT(this,
		.public = {
			.query = _query,
			.destroy = _destroy,
		},
	);

	/* TODO: Implement */
	destroy(this);
	return NULL;
}

