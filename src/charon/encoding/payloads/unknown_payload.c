/**
 * @file unknown_payload.c
 * 
 * @brief Implementation of unknown_payload_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stddef.h>

#include "unknown_payload.h"



typedef struct private_unknown_payload_t private_unknown_payload_t;

/**
 * Private data of an unknown_payload_t object.
 */
struct private_unknown_payload_t {
	
	/**
	 * Public unknown_payload_t interface.
	 */
	unknown_payload_t public;
	
	/**
	 * Next payload type.
	 */
	u_int8_t next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;
	
	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;
	
	/**
	 * The contained data.
	 */
	chunk_t data;
};

/**
 * Encoding rules to parse an payload which is not further specified.
 * 
 * The defined offsets are the positions in a object of type 
 * private_unknown_payload_t.
 * 
 */
encoding_rule_t unknown_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_unknown_payload_t, next_payload)},
	/* the critical bit */
	{ FLAG,				offsetof(private_unknown_payload_t, critical) 	},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_unknown_payload_t, payload_length)},
	/* some unknown data bytes, length is defined in PAYLOAD_LENGTH */
	{ UNKNOWN_DATA,		offsetof(private_unknown_payload_t, data) 		}
};

/*
                           1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !C!  RESERVED   !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !                                                               !
       ~                       Data of any type                        ~
       !                                                               !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_unknown_payload_t *this)
{
	/* can't do any checks, so we assume its good */
	return SUCCESS;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_unknown_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = unknown_payload_encodings;
	*rule_count = sizeof(unknown_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_unknown_payload_t *this)
{
	return UNKNOWN_PAYLOAD;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_unknown_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_unknown_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_unknown_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implementation of unknown_payload_t.get_data.
 */
static bool is_critical(private_unknown_payload_t *this)
{
	return this->critical;	
}

/**
 * Implementation of unknown_payload_t.get_data.
 */
static chunk_t get_data (private_unknown_payload_t *this)
{
	return (this->data);
}

/**
 * Implementation of payload_t.destroy and unknown_payload_t.destroy.
 */
static void destroy(private_unknown_payload_t *this)
{
	if (this->data.ptr != NULL)
	{
		chunk_free(&(this->data));
	}
	
	free(this);	
}

/*
 * Described in header
 */
unknown_payload_t *unknown_payload_create()
{
	private_unknown_payload_t *this = malloc_thing(private_unknown_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (unknown_payload_t *)) destroy;
	this->public.is_critical = (bool (*) (unknown_payload_t *)) is_critical;
	this->public.get_data = (chunk_t (*) (unknown_payload_t *)) get_data;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = UNKNOWN_PAYLOAD_HEADER_LENGTH;
	this->data = CHUNK_INITIALIZER;

	return (&(this->public));
}
