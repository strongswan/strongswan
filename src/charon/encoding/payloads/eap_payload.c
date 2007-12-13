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

#include <daemon.h>

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
	 * EAP message data, if available
	 */
	chunk_t data;
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
	{ PAYLOAD_LENGTH,	offsetof(private_eap_payload_t, payload_length)	},
	/* chunt to data, starting at "code" */
	{ EAP_DATA,			offsetof(private_eap_payload_t, data)			},
};

/*
                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !C!  RESERVED   !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Code      ! Identifier    !           Length              !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Type      ! Type_Data...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_eap_payload_t *this)
{
	u_int16_t length;
	u_int8_t code;
	
	if (this->data.len < 4)
	{
		DBG1(DBG_ENC, "EAP payloads EAP message too short (%d)", this->data.len);
		return FAILED;
	}
	code = *this->data.ptr;
	length = htons(*(u_int16_t*)(this->data.ptr + 2));
	if (this->data.len != length)
	{
		DBG1(DBG_ENC, "EAP payload length (%d) does not match contained message length (%d)",
			 this->data.len, length);
		return FAILED;
	}
	switch (code)
	{
		case EAP_REQUEST:
		case EAP_RESPONSE:
		{
			if (this->data.len < 4)
			{
				DBG1(DBG_ENC, "EAP Request/Response does not have any data");
				return FAILED;
			}
			break;
		}
		case EAP_SUCCESS:
		case EAP_FAILURE:
		{
			if (this->data.len != 4)
			{
				DBG1(DBG_ENC, "EAP Success/Failure has data");
				return FAILED;
			}
			break;
		}
		default:
			return FAILED;
	}
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
 * Implementation of eap_payload_t.get_data.
 */
static chunk_t get_data(private_eap_payload_t *this)
{
	return this->data;
}

/**
 * Implementation of eap_payload_t.set_data.
 */
static void set_data(private_eap_payload_t *this, chunk_t data)
{
	chunk_free(&this->data);
	this->data = chunk_clone(data);
	this->payload_length = this->data.len + 4;
}

/**
 * Implementation of eap_payload_t.get_code.
 */
static eap_code_t get_code(private_eap_payload_t *this)
{
	if (this->data.len > 0)
	{
		return *this->data.ptr;
	}
	/* should not happen, as it is verified */
	return 0;
}

/**
 * Implementation of eap_payload_t.get_identifier.
 */
static u_int8_t get_identifier(private_eap_payload_t *this)
{
	if (this->data.len > 1)
	{
		return *(this->data.ptr + 1);
	}
	/* should not happen, as it is verified */
	return 0;
}

/**
 * Implementation of eap_payload_t.get_type.
 */
static eap_type_t get_type(private_eap_payload_t *this, u_int32_t *vendor)
{
	eap_type_t type;

	*vendor = 0;
	if (this->data.len > 4)
	{
		type = *(this->data.ptr + 4);
		if (type != EAP_EXPANDED)
		{
			return type;
		}
		if (this->data.len >= 12)
		{
			*vendor = ntohl(*(u_int32_t*)(this->data.ptr + 4)) & 0x00FFFFFF;
			return ntohl(*(u_int32_t*)(this->data.ptr + 8));
		}
	}
	return 0;
}

/**
 * Implementation of payload_t.destroy and eap_payload_t.destroy.
 */
static void destroy(private_eap_payload_t *this)
{
	chunk_free(&this->data);
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
	this->public.get_data = (chunk_t (*) (eap_payload_t*))get_data;
	this->public.set_data = (void (*) (eap_payload_t *,chunk_t))set_data;
	this->public.get_code = (eap_code_t (*) (eap_payload_t*))get_code;
	this->public.get_identifier = (u_int8_t (*) (eap_payload_t*))get_identifier;
	this->public.get_type = (eap_type_t (*) (eap_payload_t*,u_int32_t*))get_type;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = EAP_PAYLOAD_HEADER_LENGTH;
	this->data = chunk_empty;
	
	return &(this->public);
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_data(chunk_t data)
{
	eap_payload_t *this = eap_payload_create();
	
	this->set_data(this, data);
	return this;
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_code(eap_code_t code)
{
	eap_payload_t *this = eap_payload_create();
	chunk_t data = chunk_alloca(4);
	
	*(data.ptr + 0) = code;
	*(data.ptr + 1) = 0;
	*(u_int16_t*)(data.ptr + 2) = htons(data.len);
	
	this->set_data(this, data);
	return this;
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_nak()
{
	eap_payload_t *this = eap_payload_create();
	chunk_t data = chunk_alloca(5);
	
	*(data.ptr + 0) = EAP_RESPONSE;
	*(data.ptr + 1) = 0;
	*(u_int16_t*)(data.ptr + 2) = htons(data.len);
	*(data.ptr + 4) = EAP_NAK;
	
	this->set_data(this, data);
	return this;
}

