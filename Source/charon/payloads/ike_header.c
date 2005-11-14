/**
 * @file ike_header.c
 * 
 * @brief Definition of the encoding rules used when parsing or generating
 * an IKEv2-Header
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

#include "ike_header.h"

#include "encodings.h"
#include "../utils/allocator.h"

/**
 * Encoding rules to parse or generate a IKEv2-Header
 * 
 * The defined offsets are the positions in a struct of type 
 * ike_header_t.
 * 
 */
encoding_rule_t ike_header_encodings[] = {
 	/* 8 Byte SPI, stored in the field initiator_spi */
	{ U_INT_64,		offsetof(ike_header_t, initiator_spi)	},
 	/* 8 Byte SPI, stored in the field responder_spi */
	{ U_INT_64,		offsetof(ike_header_t, responder_spi) 	},
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,		offsetof(ike_header_t, next_payload) 	},
 	/* 4 Bit major version, stored in the field maj_version */
	{ U_INT_4,		offsetof(ike_header_t, maj_version) 	},
 	/* 4 Bit minor version, stored in the field min_version */
	{ U_INT_4,		offsetof(ike_header_t, min_version) 	},
	/* 8 Bit for the exchange type */
	{ U_INT_8,		offsetof(ike_header_t, exchange_type) 	},
 	/* 2 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 										}, 
	{ RESERVED_BIT,	0 										}, 
 	/* 3 Bit flags, stored in the fields response, version and initiator */
	{ FLAG,			offsetof(ike_header_t, flags.response) 	},	
	{ FLAG,			offsetof(ike_header_t, flags.version) 	},
	{ FLAG,			offsetof(ike_header_t, flags.initiator) },
 	/* 3 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 										},
	{ RESERVED_BIT,	0 										},
	{ RESERVED_BIT,	0 										},
 	/* 4 Byte message id, stored in the field message_id */
	{ U_INT_32,		offsetof(ike_header_t, message_id) 		},
 	/* 4 Byte length fied, stored in the field length */
	{ LENGTH,		offsetof(ike_header_t, length) 			}
};



static status_t destroy(ike_header_t *this)
{
	allocator_free(this);
	
	return SUCCESS;
}
	
static status_t get_encoding_rules(payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = ike_header_encodings;
	*rule_count = sizeof(ike_header_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

static payload_type_t get_type(payload_t *this)
{
	return HEADER;
}

static payload_type_t get_next_type(payload_t *this)
{
	return (((ike_header_t*)this)->next_payload);
}

static size_t get_length(payload_t *this)
{
	return sizeof(ike_header_t);
}


ike_header_t *ike_header_create()
{
	ike_header_t *this = allocator_alloc_thing(ike_header_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->payload_interface.get_encoding_rules = get_encoding_rules;
	this->payload_interface.get_length = get_length;
	this->payload_interface.get_next_type = get_next_type;
	this->payload_interface.get_type = get_type;
	this->payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->destroy = destroy;
	
	return this;
}


