/**
 * @file auth_payload.h
 * 
 * @brief Implementation of auth_payload_t.
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

#include "auth_payload.h"

#include <encoding/payloads/encodings.h>


typedef struct private_auth_payload_t private_auth_payload_t;

/**
 * Private data of an auth_payload_t object.
 * 
 */
struct private_auth_payload_t {
	
	/**
	 * Public auth_payload_t interface.
	 */
	auth_payload_t public;
	
	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;
	
	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;
	
	/**
	 * Method of the AUTH Data.
	 */
	u_int8_t auth_method;
	
	/**
	 * The contained auth data value.
	 */
	chunk_t auth_data;
};

/**
 * Encoding rules to parse or generate a AUTH payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_auth_payload_t.
 * 
 */
encoding_rule_t auth_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_auth_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_auth_payload_t, critical) 		},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_auth_payload_t, payload_length)},
 	/* 1 Byte AUTH type*/
	{ U_INT_8,			offsetof(private_auth_payload_t, auth_method)	},
	/* 3 reserved bytes */
	{ RESERVED_BYTE,	0 													},
	{ RESERVED_BYTE,	0 													},
	{ RESERVED_BYTE,	0 													},
	/* some auth data bytes, length is defined in PAYLOAD_LENGTH */
	{ AUTH_DATA,			offsetof(private_auth_payload_t, auth_data) 		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Auth Method   !                RESERVED                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Authentication Data                      ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_auth_payload_t *this)
{
	if ((this->auth_method == 0) ||
		((this->auth_method >= 4) && (this->auth_method <= 200)))
	{
		/* reserved IDs */
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of auth_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_auth_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = auth_payload_encodings;
	*rule_count = sizeof(auth_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_auth_payload_t *this)
{
	return AUTHENTICATION;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_auth_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_auth_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_auth_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implementation of auth_payload_t.set_auth_method.
 */
static void set_auth_method (private_auth_payload_t *this, auth_method_t method)
{
	this->auth_method = method;
}

/**
 * Implementation of auth_payload_t.get_auth_method.
 */
static auth_method_t get_auth_method (private_auth_payload_t *this)
{
	return (this->auth_method);
}

/**
 * Implementation of auth_payload_t.set_data.
 */
static void set_data (private_auth_payload_t *this, chunk_t data)
{
	if (this->auth_data.ptr != NULL)
	{
		chunk_free(&(this->auth_data));
	}
	this->auth_data.ptr = clalloc(data.ptr,data.len);
	this->auth_data.len = data.len;
	this->payload_length = AUTH_PAYLOAD_HEADER_LENGTH + this->auth_data.len;
}

/**
 * Implementation of auth_payload_t.get_data.
 */
static chunk_t get_data (private_auth_payload_t *this)
{
	return (this->auth_data);
}

/**
 * Implementation of auth_payload_t.get_data_clone.
 */
static chunk_t get_data_clone (private_auth_payload_t *this)
{
	chunk_t cloned_data;
	if (this->auth_data.ptr == NULL)
	{
		return (this->auth_data);
	}
	cloned_data.ptr = clalloc(this->auth_data.ptr,this->auth_data.len);
	cloned_data.len = this->auth_data.len;
	return cloned_data;
}

/**
 * Implementation of payload_t.destroy and auth_payload_t.destroy.
 */
static void destroy(private_auth_payload_t *this)
{
	if (this->auth_data.ptr != NULL)
	{
		chunk_free(&(this->auth_data));
	}
	
	free(this);	
}

/*
 * Described in header
 */
auth_payload_t *auth_payload_create()
{
	private_auth_payload_t *this = malloc_thing(private_auth_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (auth_payload_t *)) destroy;
	this->public.set_auth_method = (void (*) (auth_payload_t *,auth_method_t)) set_auth_method;
	this->public.get_auth_method = (auth_method_t (*) (auth_payload_t *)) get_auth_method;
	this->public.set_data = (void (*) (auth_payload_t *,chunk_t)) set_data;
	this->public.get_data_clone = (chunk_t (*) (auth_payload_t *)) get_data_clone;
	this->public.get_data = (chunk_t (*) (auth_payload_t *)) get_data;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length =AUTH_PAYLOAD_HEADER_LENGTH;
	this->auth_data = CHUNK_INITIALIZER;

	return (&(this->public));
}
