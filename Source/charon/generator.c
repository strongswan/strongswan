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
#include <string.h>

#include "allocator.h"
#include "types.h"
#include "generator.h"


/**
 * buffer_t: used for geneartor operations
 */
typedef struct generator_infos_s generator_infos_t;

struct generator_infos_s {

	/**
	 * Buffer used to generate to 
	 */
	u_int8_t *buffer;
	
	/**
	 * current write position in buffer (one byte alligned)
	 */
	u_int8_t *out_position;
	
	/**
	 * position of last byte in buffer
	 */
	u_int8_t *roof_position;
	
	/**
	 * Current bit writing to
	 */
	size_t current_bit;
	
	/**
	 * Associated data struct to read informations from
	 */
	 void * data_struct;
	/**
	 * @brief Destroys a generator_infos_t object
	 * 
	 * @param generator_infos_t generator_infos_t object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (generator_infos_t *this);
	
	/**
	 * Checks if enough space is available in buffer and if not,
	 * the buffer size is increased until at least the asked amount of space 
	 * is available
	 * 
	 * @param bits number of bits to make at leas available in buffer
 	 * @param generator_infos_t generator_infos_t object
	 * @return SUCCESSFUL if succeeded, OUT_OF_RES otherwise
	 */
	status_t (*make_space_available) (generator_infos_t *this,size_t bits);
	
	status_t (*write_bytes_to_buffer) (generator_infos_t *this,void * bytes,size_t number_of_bytes);
	
	status_t (*write_chunk) (generator_infos_t *this,chunk_t *data);	
};

/**
 * implements generator_infos_t's increase_buffer function
 */
static status_t generator_info_make_space_available (generator_infos_t *this, size_t bits)
{
	size_t free_bits = ((this->roof_position - this->out_position) * 8) - this->current_bit;
	
	while (free_bits < bits)
	{
		size_t old_buffer_size = ((this->roof_position) - (	this->buffer));
		size_t new_buffer_size = old_buffer_size + GENERATOR_DATA_BUFFER_INCREASE_VALUE;
		size_t out_position_offset = ((this->out_position) - (this->buffer));
		u_int8_t *new_buffer;
	
		new_buffer = allocator_realloc(this->buffer,new_buffer_size);
		if (new_buffer == NULL)
		{
			return OUT_OF_RES;
		}
	
		this->buffer = new_buffer;
	
		this->out_position = (this->buffer + out_position_offset);
		this->roof_position = (this->buffer + new_buffer_size);
	}
	
	return SUCCESS;
}

static status_t generator_info_write_bytes_to_buffer (generator_infos_t *this,void * bytes,size_t number_of_bytes)
{
	u_int8_t *read_position = (u_int8_t *) bytes;
	int i;
	status_t status;
	
	status = this->make_space_available(this,number_of_bytes * 8);
	
	if (status != SUCCESS)
	{
		return status;
	}
	
	for (i = 0; i < number_of_bytes; i++)
	{
		*(this->out_position) = *(read_position);
		read_position++;
		this->out_position++;
	}
	return status;
}

static status_t generator_infos_write_chunk (generator_infos_t *this,chunk_t *data)
{
	size_t data_length = this->out_position - this->buffer;
	if (this->current_bit > 0)
	data_length++;
	data->ptr = allocator_alloc(data_length);
	if (data->ptr == NULL)
	{
		data->len = 0;
		return OUT_OF_RES;
	}
	memcpy(data->ptr,this->buffer,data_length);
	data->len = data_length;
	return SUCCESS;
}


static status_t generator_infos_destroy (generator_infos_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	allocator_free(this->buffer);
	allocator_free(this);
	return SUCCESS;
}

/**
 * Creates a generator_infos_t-object holding necessary informations 
 * for generating (buffer, data_struct, etc)
 * 
 * @param data_struct where to read the data out
 */
generator_infos_t * generator_infos_create(void *data_struct)
{
	generator_infos_t *this = allocator_alloc_thing(generator_infos_t);

	if (this == NULL)
	{
		return NULL;
	}

	/* object methods */
	this->destroy = generator_infos_destroy;
	this->make_space_available = generator_info_make_space_available;
	this->write_chunk = generator_infos_write_chunk;
	this->write_bytes_to_buffer = generator_info_write_bytes_to_buffer;

	/* allocate memory for buffer */
	this->buffer = allocator_alloc(GENERATOR_DATA_BUFFER_SIZE);
	if (this->buffer == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	
	/* set private data */
	this->out_position = this->buffer;
	this->roof_position = this->buffer + GENERATOR_DATA_BUFFER_SIZE;
	this->data_struct = data_struct;
	this->current_bit = 0;
	return (this);
}



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
	status_t (*generate_u_int_type) (private_generator_t *this,encoding_type_t int_type,u_int32_t offset, generator_infos_t *generator_infos);

	/**
	 * Pointer to the payload informations needed to automatic
	 * generate a specific payload type
	 */
	payload_info_t **payload_infos;
};

/**
 * implements private_generator_t's double_buffer function
 */
static status_t generate_u_int_type (private_generator_t *this,encoding_type_t int_type,u_int32_t offset,generator_infos_t *generator_infos)
{
	size_t number_of_bits = 0;
	status_t status;
	

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
	if (((number_of_bits % 8) == 0) && (generator_infos->current_bit != 0))
	{
		/* current bit has to be zero for values greater then 4 bits */
		return FAILED;
	}
	
	status = generator_infos->make_space_available(generator_infos,number_of_bits);
	
	if (status != SUCCESS)
	{
		return status;
	}

	switch (int_type)
	{
			case U_INT_4:
			{
				if (generator_infos->current_bit == 0)
				{			
					u_int8_t high_val = *((u_int8_t *)(generator_infos->data_struct + offset)) << 4;
					u_int8_t low_val = *(generator_infos->out_position) & 0x0F;
						
					*(generator_infos->out_position) = high_val | low_val;
					/* write position is not changed, just bit position is moved */
					generator_infos->current_bit = 4;
				}
				else if (generator_infos->current_bit == 4)
				{
					u_int high_val = *(generator_infos->out_position) & 0xF0;
					u_int low_val = *((u_int8_t *)(generator_infos->data_struct + offset)) & 0x0F;
					*(generator_infos->out_position) = high_val | low_val;
					generator_infos->out_position++;
					generator_infos->current_bit = 0;
					
				}
				else
				{
					/* 4 Bit integers must have a 4 bit alignment */
					return FAILED;
				};
				break;
			}
			
			case U_INT_8:
			{
				*generator_infos->out_position = *((u_int8_t *)(generator_infos->data_struct + offset));
				generator_infos->out_position++;
				break;
				
			}
			case U_INT_16:
			{
				u_int16_t int16_val = htons(*((u_int16_t*)(generator_infos->data_struct + offset)));
				generator_infos->write_bytes_to_buffer(generator_infos,&int16_val,sizeof(u_int16_t));
		
				break;
			}
			case U_INT_32:
			{
				u_int32_t int32_val = htonl(*((u_int32_t*)(generator_infos->data_struct + offset)));			
				generator_infos->write_bytes_to_buffer(generator_infos,&int32_val,sizeof(u_int32_t));
				break;
			}
			case U_INT_64:
			{
				u_int32_t int32_val_low = htonl(*((u_int32_t*)(generator_infos->data_struct + offset)));
				u_int32_t int32_val_high = htonl(*((u_int32_t*)(generator_infos->data_struct + offset) + 1));			
				generator_infos->write_bytes_to_buffer(generator_infos,&int32_val_high,sizeof(u_int32_t));				
				generator_infos->write_bytes_to_buffer(generator_infos,&int32_val_low,sizeof(u_int32_t));				
				break;
			}
				
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
	int i;
	status_t status;
	
	
	generator_infos_t *infos = generator_infos_create(data_struct);

	if (infos == NULL)
	{
		return OUT_OF_RES;
	}


	for (i = 0; i < encoding_rules_count;i++)
	{
		status = SUCCESS;
		switch (encoding_rules[i].type)
		{
			/* all u int values are generated in generate_u_int_type */
			case U_INT_4:
			case U_INT_8:
			case U_INT_16:
			case U_INT_32:
			case U_INT_64:
				status = this->generate_u_int_type(this,encoding_rules[i].type,encoding_rules[i].offset,infos);
				break;
			case RESERVED_BIT:
			{
				u_int8_t reserved_bit = ~(1 << (7 - infos->current_bit));
				
				*(infos->out_position) = *(infos->out_position) & reserved_bit;
				
				infos->current_bit++;
				if (infos->current_bit >= 8)
				{
					infos->current_bit = infos->current_bit % 8;
					status = infos->make_space_available(infos,8);
					infos->out_position++;
				}
				break;
			}
			case RESERVED_BYTE:
			{
				if (infos->current_bit > 0)
				{
					return FAILED;
				}
				*(infos->out_position) = 0x00;
				infos->out_position++;
				break;
			}
			case FLAG:
			{
				u_int8_t flag_value = (*((bool *) (infos->data_struct + encoding_rules[i].offset))) ? 1 : 0;
				u_int8_t flag = (flag_value << (7 - infos->current_bit));
				
				*(infos->out_position) = *(infos->out_position) | flag;
				
				infos->current_bit++;
				if (infos->current_bit >= 8)
				{
					infos->current_bit = infos->current_bit % 8;
					status = infos->make_space_available(infos,8);
					infos->out_position++;
				}
				break;
			}
			case LENGTH:
				/* length is generated like an U_INT_32 */
				status = this->generate_u_int_type(this,U_INT_32,encoding_rules[i].offset,infos);
			case SPI_SIZE:
				/* actually not implemented */
			default:
				break;
		}
		if (status != SUCCESS)
		{
			infos->destroy(infos);
			return status;
		}
	}


	status = infos->write_chunk(infos,data);
	infos->destroy(infos);
	return status;
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

	allocator_free(this);
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

	this = allocator_alloc_thing(private_generator_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* initiate public functions */
	this->public.generate_payload = (status_t(*)(generator_t*, payload_type_t, void *, chunk_t *)) generate_payload;
	this->public.destroy = (status_t(*)(generator_t*)) destroy;

	/* initiate private functions */
	this->generate = generate;
	this->generate_u_int_type = generate_u_int_type;

	/* initiate private variables */
	this->payload_infos = payload_infos;

	return &(this->public);
}
