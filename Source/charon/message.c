/**
 * @file message.c
 *
 * @brief Class message_t. Object of this type represents an IKEv2-Message
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
#include "message.h"

/**
 * Private data of an message_t object
 */
typedef struct private_message_s private_message_t;

struct private_message_s {

	/**
	 * Public part of a message_t object
	 */
	message_t public;


	/* Private values */

};

/**
 * @brief implements function destroy of message_t
 */
static status_t destroy (private_message_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in Header-File
 */
message_t * message_create()
{
	private_message_t *this = allocator_alloc_thing(private_message_t, "private_message_t");
	if (this == NULL)
	{
		return NULL;
	}

	/* Public functions */
	this->public.destroy = (status_t(*)(message_t*))destroy;


	return (&this->public);
}
