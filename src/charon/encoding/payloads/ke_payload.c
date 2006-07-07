/**
 * @file ke_payload.c
 * 
 * @brief Implementation of ke_payload_t.
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

#include "ke_payload.h"

#include <encoding/payloads/encodings.h>


typedef struct private_ke_payload_t private_ke_payload_t;

/**
 * Private data of an ke_payload_t object.
 * 
 */
struct private_ke_payload_t {
	/**
	 * Public ke_payload_t interface.
	 */
	ke_payload_t public;
	
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
	 * DH Group Number.
	 */
	diffie_hellman_group_t dh_group_number;
	
	/**
	 * Key Exchange Data of this KE payload.
	 */
	chunk_t key_exchange_data;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_ke_payload_t object
	 */
	void (*compute_length) (private_ke_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-KE Payload.
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
	{ U_INT_16,			offsetof(private_ke_payload_t, dh_group_number) 	},
	{ RESERVED_BYTE,	0 													}, 
	{ RESERVED_BYTE,	0 													}, 
	/* Key Exchange Data is from variable size */
	{ KEY_EXCHANGE_DATA,	offsetof(private_ke_payload_t, key_exchange_data)}
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
 * Implementation of payload_t.verify.
 */
static status_t verify(private_ke_payload_t *this)
{
	/* dh group is not verified in here */
	return SUCCESS;
}

/**
 * Implementation of payload_t.destroy.
 */
static void destroy(private_ke_payload_t *this)
{
	if (this->key_exchange_data.ptr != NULL)
	{
		free(this->key_exchange_data.ptr);
	}
	free(this);
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_ke_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = ke_payload_encodings;
	*rule_count = sizeof(ke_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_ke_payload_t *this)
{
	return KEY_EXCHANGE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_ke_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_ke_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_ke_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of private_ke_payload_t.compute_length.
 */
static void compute_length (private_ke_payload_t *this)
{
	size_t length = KE_PAYLOAD_HEADER_LENGTH;
	if (this->key_exchange_data.ptr != NULL)
	{
		length += this->key_exchange_data.len;
	}	
	this->payload_length = length;
}


/**
 * Implementation of ke_payload_t.get_key_exchange_data.
 */
static chunk_t get_key_exchange_data(private_ke_payload_t *this)
{
	return (this->key_exchange_data);
}

/**
 * Implementation of ke_payload_t.set_key_exchange_data.
 */
static void set_key_exchange_data(private_ke_payload_t *this, chunk_t key_exchange_data)
{
	/* destroy existing data first */
	if (this->key_exchange_data.ptr != NULL)
	{
		/* free existing value */
		free(this->key_exchange_data.ptr);
		this->key_exchange_data.ptr = NULL;
		this->key_exchange_data.len = 0;
		
	}
	
	this->key_exchange_data = chunk_clone(key_exchange_data);
	this->compute_length(this);
}

/**
 * Implementation of ke_payload_t.get_dh_group_number.
 */
static diffie_hellman_group_t get_dh_group_number(private_ke_payload_t *this)
{
	return this->dh_group_number;
}

/**
 * Implementation of ke_payload_t.set_dh_group_number.
 */
static void set_dh_group_number(private_ke_payload_t *this, diffie_hellman_group_t dh_group_number)
{
	this->dh_group_number = dh_group_number;
}

/*
 * Described in header
 */
ke_payload_t *ke_payload_create()
{
	private_ke_payload_t *this = malloc_thing(private_ke_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;

	/* public functions */
	this->public.get_key_exchange_data = (chunk_t (*) (ke_payload_t *)) get_key_exchange_data;
	this->public.set_key_exchange_data = (void (*) (ke_payload_t *,chunk_t)) set_key_exchange_data;
	this->public.get_dh_group_number = (diffie_hellman_group_t (*) (ke_payload_t *)) get_dh_group_number;
	this->public.set_dh_group_number =(void (*) (ke_payload_t *,diffie_hellman_group_t)) set_dh_group_number;
	this->public.destroy = (void (*) (ke_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = KE_PAYLOAD_HEADER_LENGTH;
	this->key_exchange_data = CHUNK_INITIALIZER;
	this->dh_group_number = MODP_NONE;

	return &this->public;
}

/*
 * Described in header
 */
ke_payload_t *ke_payload_create_from_diffie_hellman(diffie_hellman_t *dh)
{
	private_ke_payload_t *this = (private_ke_payload_t*)ke_payload_create();
	
	dh->get_my_public_value(dh, &this->key_exchange_data);
	this->dh_group_number = dh->get_dh_group(dh);
	this->compute_length(this);
	
	return &this->public;
}
