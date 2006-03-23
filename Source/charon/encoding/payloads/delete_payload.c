/**
 * @file delete_payload.c
 * 
 * @brief Implementation of delete_payload_t.
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

#include "delete_payload.h"

#include <utils/allocator.h>


typedef struct private_delete_payload_t private_delete_payload_t;

/**
 * Private data of an delete_payload_t object.
 * 
 */
struct private_delete_payload_t {
	/**
	 * Public delete_payload_t interface.
	 */
	delete_payload_t public;
	
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
	 * Protocol ID.
	 */
	u_int8_t protocol_id;

	/**
	 * SPI Size.
	 */
	u_int8_t spi_size;
	
	/**
	 * Number of SPI's.
	 */
	u_int16_t spi_count;
	
	/**
	 * The contained SPI's.
	 */
	chunk_t spis;
};

/**
 * Encoding rules to parse or generate a DELETE payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_delete_payload_t.
 * 
 */
encoding_rule_t delete_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_delete_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_delete_payload_t, critical) 		},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_delete_payload_t, payload_length)},
	{ U_INT_8,			offsetof(private_delete_payload_t, protocol_id)		},
	{ U_INT_8,			offsetof(private_delete_payload_t, spi_size)		},
	{ U_INT_16,			offsetof(private_delete_payload_t, spi_count)		},
	/* some delete data bytes, length is defined in PAYLOAD_LENGTH */
	{ SPIS,			offsetof(private_delete_payload_t, spis) 				}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Protocol ID   !   SPI Size    !           # of SPIs           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~               Security Parameter Index(es) (SPI)              ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_delete_payload_t *this)
{
	if ((this->protocol_id == 0) ||
		(this->protocol_id > 3))
	{
		/* reserved IDs */
		return FAILED;
	}
	if (this->spis.len != (this->spi_count * this->spi_size))
	{
		return FAILED;
	}
	if ((this->protocol_id == PROTO_IKE) && (this->spis.len != 0))
	{
		/* IKE deletion has no spi assigned! */
		return FAILED;
	}
	
	
	return SUCCESS;
}

/**
 * Implementation of delete_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_delete_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = delete_payload_encodings;
	*rule_count = sizeof(delete_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_delete_payload_t *this)
{
	return DELETE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_delete_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_delete_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_delete_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implementation of delete_payload_t.set_protocol_id.
 */
static void set_protocol_id (private_delete_payload_t *this, protocol_id_t protocol_id)
{
	this->protocol_id = protocol_id;
}

/**
 * Implementation of delete_payload_t.get_protocol_id.
 */
static protocol_id_t get_protocol_id (private_delete_payload_t *this)
{
	return (this->protocol_id);
}

/**
 * Implementation of delete_payload_t.set_spi_size.
 */
static void set_spi_size (private_delete_payload_t *this, u_int8_t spi_size)
{
	this->spi_size = spi_size;
}

/**
 * Implementation of delete_payload_t.get_spi_size.
 */
static u_int8_t get_spi_size (private_delete_payload_t *this)
{
	return (this->spi_size);
}

/**
 * Implementation of delete_payload_t.set_spi_count.
 */
static void set_spi_count (private_delete_payload_t *this, u_int16_t spi_count)
{
	this->spi_count = spi_count;
}

/**
 * Implementation of delete_payload_t.get_spi_count.
 */
static u_int16_t get_spi_count (private_delete_payload_t *this)
{
	return (this->spi_count);
}


/**
 * Implementation of delete_payload_t.set_spis.
 */
static void set_spis (private_delete_payload_t *this, chunk_t spis)
{
	if (this->spis.ptr != NULL)
	{
		allocator_free_chunk(&(this->spis));
	}
	this->spis.ptr = allocator_clone_bytes(spis.ptr,spis.len);
	this->spis.len = spis.len;
	this->payload_length = DELETE_PAYLOAD_HEADER_LENGTH + this->spis.len;
}

/**
 * Implementation of delete_payload_t.get_spis.
 */
static chunk_t get_spis (private_delete_payload_t *this)
{
	return (this->spis);
}

/**
 * Implementation of delete_payload_t.get_spis_clone.
 */
static chunk_t get_spis_clone (private_delete_payload_t *this)
{
	chunk_t cloned_spis;
	if (this->spis.ptr == NULL)
	{
		return (this->spis);
	}
	cloned_spis.ptr = allocator_clone_bytes(this->spis.ptr,this->spis.len);
	cloned_spis.len = this->spis.len;
	return cloned_spis;
}

/**
 * Implementation of payload_t.destroy and delete_payload_t.destroy.
 */
static void destroy(private_delete_payload_t *this)
{
	if (this->spis.ptr != NULL)
	{
		allocator_free_chunk(&(this->spis));
	}
	
	allocator_free(this);	
}

/*
 * Described in header
 */
delete_payload_t *delete_payload_create()
{
	private_delete_payload_t *this = allocator_alloc_thing(private_delete_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (delete_payload_t *)) destroy;
	this->public.set_protocol_id = (void (*) (delete_payload_t *,protocol_id_t)) set_protocol_id;
	this->public.get_protocol_id = (protocol_id_t (*) (delete_payload_t *)) get_protocol_id;
	this->public.set_spi_size = (void (*) (delete_payload_t *,u_int8_t)) set_spi_size;
	this->public.get_spi_size = (u_int8_t (*) (delete_payload_t *)) get_spi_size;
	this->public.set_spi_count = (void (*) (delete_payload_t *,u_int16_t)) set_spi_count;
	this->public.get_spi_count = (u_int16_t (*) (delete_payload_t *)) get_spi_count;
	this->public.set_spis = (void (*) (delete_payload_t *,chunk_t)) set_spis;
	this->public.get_spis_clone = (chunk_t (*) (delete_payload_t *)) get_spis_clone;
	this->public.get_spis = (chunk_t (*) (delete_payload_t *)) get_spis;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length =DELETE_PAYLOAD_HEADER_LENGTH;
	this->protocol_id = PROTO_NONE;
	this->spi_size = 0;
	this->spi_count = 0;
	this->spis = CHUNK_INITIALIZER;

	return (&(this->public));
}
