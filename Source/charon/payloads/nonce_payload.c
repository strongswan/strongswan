/**
 * @file nonce_payload.h
 * 
 * @brief Declaration of the class nonce_payload_t. 
 * 
 * An object of this type represents an IKEv2 Nonce-Payload.
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
 
/* offsetof macro */
#include <stddef.h>

#include "nonce_payload.h"

#include "encodings.h"
#include "../utils/allocator.h"



/**
 * Private data of an nonce_payload_t' Object
 * 
 */
typedef struct private_nonce_payload_s private_nonce_payload_t;

struct private_nonce_payload_s {
	/**
	 * public nonce_payload_t interface
	 */
	nonce_payload_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag
	 */
	bool critical;
	
	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;
	
	/**
	 * the contained nonce value
	 */
	chunk_t nonce;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_nonce_payload_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_nonce_payload_t *this);
};

/**
 * Encoding rules to parse or generate a nonce payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_nonce_payload_t.
 * 
 */
encoding_rule_t nonce_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_nonce_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_nonce_payload_t, critical) 		},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole nonce payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_nonce_payload_t, payload_length) 	},	
	/* some nonce bytes, lenth is defined in PAYLOAD_LENGTH */
	{ NONCE_DATA,			offsetof(private_nonce_payload_t, nonce) 		}
};

/*                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                            Nonce Data                         ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_nonce_payload_t *this)
{
	if (this->critical)
	{
		/* critical bit is set! */
		return FAILED;
	}
	if ((this->nonce.len < 16) || ((this->nonce.len > 256)))
	{
		/* nonce length is wrong */
		return FAILED;
	}
	
	return SUCCESS;
}

/**
 * Implements payload_t's and nonce_payload_t's destroy function.
 * See #payload_s.destroy or nonce_payload_s.destroy for description.
 */
static status_t destroy(private_nonce_payload_t *this)
{
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implements nonce_payload_t's set_nonce function.
 * See #nonce_payload_t.set_nonce for description.
 */
static status_t set_nonce(private_nonce_payload_t *this, chunk_t nonce)
{
	if (nonce.len >= 16 && nonce.len <= 256)
	{
		this->nonce.len = nonce.len;
		this->nonce.ptr = nonce.ptr;
		this->payload_length = NONCE_PAYLOAD_HEADER_LENGTH + nonce.len;
		return SUCCESS;	
	}
	return INVALID_ARG;
}

/**
 * Implements nonce_payload_t's get_nonce function.
 * See #nonce_payload_t.get_nonce for description.
 */
static status_t get_nonce(private_nonce_payload_t *this, chunk_t *nonce)
{
	nonce->ptr = this->nonce.ptr;
	nonce->len = this->nonce.len;
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_nonce_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = nonce_payload_encodings;
	*rule_count = sizeof(nonce_payload_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_nonce_payload_t *this)
{
	return NONCE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_nonce_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's set_next_type function.
 * See #payload_s.set_next_type for description.
 */
static status_t set_next_type(private_nonce_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
	return SUCCESS;
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_nonce_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/*
 * Described in header
 */
nonce_payload_t *nonce_payload_create()
{
	private_nonce_payload_t *this = allocator_alloc_thing(private_nonce_payload_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->public.destroy = (status_t (*) (nonce_payload_t *)) destroy;
	this->public.set_nonce = (status_t (*) (nonce_payload_t *,chunk_t)) set_nonce;
	this->public.get_nonce = (status_t (*) (nonce_payload_t *,chunk_t*)) get_nonce;
	
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = NONCE_PAYLOAD_HEADER_LENGTH;
	this->nonce.ptr = NULL;
	this->nonce.len = 0;

	return (&(this->public));
}


