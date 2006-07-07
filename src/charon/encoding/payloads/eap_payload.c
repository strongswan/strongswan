/**
 * @file eap_payload.c
 * 
 * @brief Implementation of eap_payload_t.
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

#include "eap_payload.h"


typedef struct private_eap_payload_t private_eap_payload_t;

/**
 * Private data of an eap_payload_t object.
 * 
 */
struct private_eap_payload_t {
	/**
	 * Public eap_payload_t interface.
	 */
	eap_payload_t public;
	
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
	 * The contained message.
	 */
	chunk_t message;
};

/**
 * Encoding rules to parse or generate a EAP payload.
 * 
 * The defined offsets are the positions in a object of type 
 * private_eap_payload_t.
 * 
 */
encoding_rule_t eap_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_eap_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_eap_payload_t, critical) 		},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_eap_payload_t, payload_length)},
	/* some eap data bytes, length is defined in PAYLOAD_LENGTH */
	{ EAP_MESSAGE,		offsetof(private_eap_payload_t, message) 		}
};

/*
                           1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !C!  RESERVED   !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !                                                               !
       ~                       EAP Message                             ~
       !                                                               !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_eap_payload_t *this)
{
	return SUCCESS;
}

/**
 * Implementation of eap_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_eap_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = eap_payload_encodings;
	*rule_count = sizeof(eap_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_eap_payload_t *this)
{
	return EXTENSIBLE_AUTHENTICATION;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_eap_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_eap_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_eap_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implementation of eap_payload_t.set_message.
 */
static void set_message (private_eap_payload_t *this, chunk_t message)
{
	if (this->message.ptr != NULL)
	{
		chunk_free(&(this->message));
	}
	this->message.ptr = clalloc(message.ptr,message.len);
	this->message.len = message.len;
	this->payload_length = EAP_PAYLOAD_HEADER_LENGTH + this->message.len;
}

/**
 * Implementation of eap_payload_t.get_message.
 */
static chunk_t get_message (private_eap_payload_t *this)
{
	return (this->message);
}

/**
 * Implementation of eap_payload_t.get_data_clone.
 */
static chunk_t get_message_clone (private_eap_payload_t *this)
{
	chunk_t cloned_message;
	if (this->message.ptr == NULL)
	{
		return (this->message);
	}
	cloned_message.ptr = clalloc(this->message.ptr,this->message.len);
	cloned_message.len = this->message.len;
	return cloned_message;
}

/**
 * Implementation of payload_t.destroy and eap_payload_t.destroy.
 */
static void destroy(private_eap_payload_t *this)
{
	if (this->message.ptr != NULL)
	{
		chunk_free(&(this->message));
	}
	
	free(this);	
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create()
{
	private_eap_payload_t *this = malloc_thing(private_eap_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (eap_payload_t *)) destroy;
	this->public.set_message = (void (*) (eap_payload_t *,chunk_t)) set_message;
	this->public.get_message_clone = (chunk_t (*) (eap_payload_t *)) get_message_clone;
	this->public.get_message = (chunk_t (*) (eap_payload_t *)) get_message;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = EAP_PAYLOAD_HEADER_LENGTH;
	this->message = CHUNK_INITIALIZER;

	return (&(this->public));
}
