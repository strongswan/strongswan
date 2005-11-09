/**
 * @file generator.c
 * 
 * @brief Generic generator class used to generate IKEv2-Header and Payload
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
#include "generator.h"

/**
 * Private data of a generator_t object
 */
typedef struct private_generator_s private_generator_t;
 
struct private_generator_s { 	
	/**
	 * Public part of a generator object
	 */
	 generator_t public;
	
	/* private functions and fields */
	
	/**
	 * Generates a chunk_t with specific encoding rules
	 * 
	 * items are bytewhise written
	 *
	 * @param this private_generator_t-object
	 * @param data_struct data_struct to read data from
	 * @param encoding_rules pointer to first encoding_rule of encoding rules array
	 * @param encoding_rules_count number of encoding rules in encoding rules array
	 * @param data pointer to chunk where to write the data in
	 * 
	 * @return SUCCESS if succeeded,
 	 * 		   OUT_OF_RES if out of ressources
	 */
	status_t (*generate) (private_generator_t *this,void * data_struct,encoding_rule_t *encoding_rules, size_t encoding_rules_count, chunk_t *data);
	
	/**
	 * TODO
	 */
	status_t (*generate_u_int_type) (private_generator_t *this,encoding_type_t int_type,u_int8_t **buffer,u_int8_t **out_position,u_int8_t **roof_position,size_t *current_bit);
	 
	/**
	 * Pointer to the payload informations needed to automatic
	 * generate a specific payload type
	 */
	payload_info_t **payload_infos;
};


/**
 * implements private_generator_t's generate_u_int_type function
 */

static status_t generate_u_int_type (private_generator_t *this,encoding_type_t int_type,u_int8_t **buffer,u_int8_t **out_position,u_int8_t **roof_position,size_t *current_bit)
{
	size_t number_of_bits = 0;	
	
	switch (int_type)
	{
			case U_INT_4:
				number_of_bits = 4;
				break;
			case U_INT_8:
				number_of_bits = 8;
				break;
			case U_INT_16:
				number_of_bits = 16;
				break;
			case U_INT_32:
				number_of_bits = 32;
				break;
			case U_INT_64:
				number_of_bits = 64;
				break;
			default:
			return FAILED;
	}
	return SUCCESS;
}

/**
 * implements private_generator_t's generate function
 */
static status_t generate (private_generator_t *this,void * data_struct,encoding_rule_t *encoding_rules, size_t encoding_rules_count, chunk_t *data)
{
	u_int8_t * buffer = alloc_bytes(GENERATOR_DATA_BUFFER_SIZE,  "generator buffer");
	u_int8_t * out_position = buffer;
	u_int8_t * roof_position = buffer + GENERATOR_DATA_BUFFER_SIZE;
	size_t current_bit = 0;
	int i;

	if (buffer == NULL)
	{
		return OUT_OF_RES;
	}
	for (i = 0; i < encoding_rules_count;i++)
	{
		status_t status = SUCCESS;
		switch (encoding_rules[i].type)
		{
			case U_INT_4:
			case U_INT_8:
			case U_INT_16:
			case U_INT_32:
			case U_INT_64:
				status = this->generate_u_int_type(this,encoding_rules[i].type,&buffer,&out_position,&roof_position,&current_bit);
				break;
			case RESERVED_BIT:
			case RESERVED_BYTE:
			case FLAG:
			case LENGTH:
			case SPI_SIZE:
			default:
				break;
		}
		if (status != SUCCESS)
		{
			pfree(buffer);
			return status;
		}
	}
	
	return SUCCESS;
}

static status_t generate_payload (private_generator_t *this,payload_type_t payload_type,void * data_struct, chunk_t *data)
{
	int i;
	
	/* check every payload info for specific type */
	for (i = 0; this->payload_infos[i] != NULL; i++)
	{
		if (this->payload_infos[i]->payload_type == payload_type)
		{
			/* found payload informations, generating is done in private function generate() */
			return (this->generate(this, data_struct,this->payload_infos[i]->ecoding_rules,this->payload_infos[i]->encoding_rules_count,data));
		}
	}
	return NOT_SUPPORTED;
}

/**
 * Implementation of generator_t's destroy function
 */
static status_t destroy(private_generator_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}

	pfree(this);
	return SUCCESS;
}

/*
 * Described in header
 */
generator_t * generator_create(payload_info_t ** payload_infos)
{
	private_generator_t *this;
	
	if (payload_infos == NULL)
	{
		return NULL;
	}
	
	this = alloc_thing(private_generator_t,"private_generator_t");
	if (this == NULL)
	{
		return NULL;
	}
	
	this->public.generate_payload = (status_t(*)(generator_t*, payload_type_t, void *, chunk_t *)) generate_payload;
	this->public.destroy = (status_t(*)(generator_t*)) destroy;
	
	/* initiate private fields */
	this->generate = generate;
	this->generate_u_int_type = generate_u_int_type;
	
	this->payload_infos = payload_infos;
	
	return &(this->public);
}
