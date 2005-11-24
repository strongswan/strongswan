/**
 * @file ke_payload.c
 * 
 * @brief Declaration of the class ke_payload_t. 
 * 
 * An object of this type represents an IKEv2 KE-Payload.
 * 
 * See section 3.4 of RFC for details of this payload type.
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

#include "ke_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/allocator.h>


typedef struct private_ke_payload_t private_ke_payload_t;

/**
 * Private data of an ke_payload_t Object
 * 
 */
struct private_ke_payload_t {
	/**
	 * public ke_payload_t interface
	 */
	ke_payload_t public;
	
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
	 * DH Group Number
	 */
	diffie_hellman_group_t dh_group_number;
	
	/**
	 * Key Exchange Data of this KE payload
	 */
	chunk_t key_exchange_data;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_ke_payload_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_ke_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-KE Payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_ke_payload_t.
 * 
 */
encoding_rule_t ke_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_ke_payload_t, next_payload) 		},
	/* the critical bit */
	{ FLAG,				offsetof(private_ke_payload_t, critical) 			},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_ke_payload_t, payload_length) 		},	
	/* DH Group number as 16 bit field*/
	{ U_INT_16,			offsetof(private_ke_payload_t, dh_group_number) 		},
	{ RESERVED_BYTE,	0 														}, 
	{ RESERVED_BYTE,	0 														}, 
	/* Key Exchange Data is from variable size */
	{ KEY_EXCHANGE_DATA,	offsetof(private_ke_payload_t, key_exchange_data) 	}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !          DH Group #           !           RESERVED            !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       Key Exchange Data                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_ke_payload_t *this)
{
	if (this->critical)
	{
		/* critical bit is set! */
		return FAILED;
	}
	
	/* dh group is not verified in here */
	return SUCCESS;
}

/**
 * Implements payload_t's and ke_payload_t's destroy function.
 * See #payload_s.destroy or ke_payload_s.destroy for description.
 */
static status_t destroy(private_ke_payload_t *this)
{
	if (this->key_exchange_data.ptr != NULL)
	{
		allocator_free(this->key_exchange_data.ptr);
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_ke_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = ke_payload_encodings;
	*rule_count = sizeof(ke_payload_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_ke_payload_t *this)
{
	return KEY_EXCHANGE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_ke_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's set_next_type function.
 * See #payload_s.set_next_type for description.
 */
static status_t set_next_type(private_ke_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
	return SUCCESS;
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_ke_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implements private_ke_payload_t's compute_length function.
 * See #private_ke_payload_s.compute_length for description.
 */
static status_t compute_length (private_ke_payload_t *this)
{
	size_t length = KE_PAYLOAD_HEADER_LENGTH;
	if (this->key_exchange_data.ptr != NULL)
	{
		length += this->key_exchange_data.len;
	}
	
	this->payload_length = length;
		
	return SUCCESS;
}


/**
 * Implements ke_payload_t's get_key_exchange_data function.
 * See #ke_payload_t.get_key_exchange_data for description.
 */
chunk_t get_key_exchange_data(private_ke_payload_t *this)
{
	return (this->key_exchange_data);
}

/**
 * Implements ke_payload_t's set_key_exchange_data function.
 * See #ke_payload_t.set_key_exchange_data for description.
 */
status_t set_key_exchange_data(private_ke_payload_t *this, chunk_t key_exchange_data)
{
	/* destroy existing data first */
	if (this->key_exchange_data.ptr != NULL)
	{
		/* free existing value */
		allocator_free(this->key_exchange_data.ptr);
		this->key_exchange_data.ptr = NULL;
		this->key_exchange_data.len = 0;
		
	}
	
	this->key_exchange_data.ptr = allocator_clone_bytes(key_exchange_data.ptr,key_exchange_data.len);
	if (this->key_exchange_data.ptr == NULL)
	{
		return OUT_OF_RES;
	}
	this->key_exchange_data.len = key_exchange_data.len;
	this->compute_length(this);
	
	return SUCCESS;
}

/**
 * Implements ke_payload_t's get_dh_group_number function.
 * See #ke_payload_t.get_dh_group_number for description.
 */
diffie_hellman_group_t get_dh_group_number(private_ke_payload_t *this)
{
	return this->dh_group_number;
}

/**
 * Implements ke_payload_t's set_dh_group_number function.
 * See #ke_payload_t.set_dh_group_number for description.
 */
status_t set_dh_group_number(private_ke_payload_t *this, diffie_hellman_group_t dh_group_number)
{
	this->dh_group_number = dh_group_number;
	return SUCCESS;
}

/*
 * Described in header
 */
ke_payload_t *ke_payload_create()
{
	private_ke_payload_t *this = allocator_alloc_thing(private_ke_payload_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;

	/* public functions */
	this->public.get_key_exchange_data = (chunk_t (*) (ke_payload_t *)) get_key_exchange_data;
	this->public.set_key_exchange_data = (status_t (*) (ke_payload_t *,chunk_t)) set_key_exchange_data;
	this->public.get_dh_group_number = (diffie_hellman_group_t (*) (ke_payload_t *)) get_dh_group_number;
	this->public.set_dh_group_number =(status_t (*) (ke_payload_t *,diffie_hellman_group_t)) set_dh_group_number;
	this->public.destroy = (status_t (*) (ke_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = KE_PAYLOAD_CRITICAL_FLAG;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = KE_PAYLOAD_HEADER_LENGTH;
	this->key_exchange_data.ptr = NULL;
	this->key_exchange_data.len = 0;
	this->dh_group_number = 0;

	return (&(this->public));
}
