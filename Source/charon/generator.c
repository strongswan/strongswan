/**
 * @file generator.c
 *
 * @brief Generic generator class used to generate IKEv2-header and payloads.
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
#include <arpa/inet.h>
#include <stdio.h>

#include "allocator.h"
#include "types.h"
#include "generator.h"


typedef struct private_generator_context_s private_generator_context_t;

struct private_generator_context_s{
	/**
	 * Public part of the context
	 */
	generator_context_t public;

	/**
	 * Buffer used to generate the data into.
	 */
	u_int8_t *buffer;

	/**
	 * Current write position in buffer (one byte aligned).
	 */
	u_int8_t *out_position;

	/**
	 * Position of last byte in buffer.
	 */
	u_int8_t *roof_position;

	/**
	 * Current bit writing to in current byte (between 0 and 7).
	 */
	size_t current_bit;

	/**
	 * Associated data struct to read informations from.
	 */
	 void * data_struct;

	/**
	 * Writes the current buffer content into a chunk_t
	 * 
	 * Memory of specific chunk_t gets allocated.
	 *
 	 * @param generator_infos_t calling generator_infos_t object
	 * @param data				pointer of chunk_t to write to
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_chunk) (private_generator_context_t *this,chunk_t *data);
	

	/**
	 * Makes sure enough space is available in buffer to store amount of bits.
     *
	 * If buffer is to small to hold the specific amount of bits it 
	 * is increased using reallocation function of allocator.
	 *
 	 * @param generator_infos_t calling generator_infos_t object
	 * @param bits 				number of bits to make available in buffer
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*make_space_available) (private_generator_context_t *this,size_t bits);

	/**
	 * Writes a specific amount of byte into the buffer.
	 * 
	 * If buffer is to small to hold the specific amount of bytes it 
	 * is increased.
	 *
 	 * @param generator_infos_t calling generator_infos_t object
	 * @param bytes 				pointer to bytes to write
	 * @param number_of_bytes	number of bytes to write into buffer
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_bytes_to_buffer) (private_generator_context_t *this,void * bytes,size_t number_of_bytes);

	
};

/**
 * Implements generator_infos_t's increase_buffer function.
 * See #generator_infos_s.increase_buffer.
 */
static status_t generator_context_make_space_available (private_generator_context_t *this, size_t bits)
{
	while ((((this->roof_position - this->out_position) * 8) - this->current_bit) < bits)
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

/**
 * Implements generator_infos_t's write_bytes_to_buffer function.
 * See #generator_infos_s.write_bytes_to_buffer.
 */
static status_t generator_context_write_bytes_to_buffer (private_generator_context_t *this,void * bytes,size_t number_of_bytes)
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

/**
 * Implements generator_infos_t's write_chunk function.
 * See #generator_infos_s.write_chunk.
 */
static status_t generator_context_write_chunk (private_generator_context_t *this,chunk_t *data)
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


/**
 * Implements generator_infos_t's destroy function.
 * See #generator_infos_s.destroy.
 */
static status_t generator_context_destroy (private_generator_context_t *this)
{
	allocator_free(this->buffer);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
static generator_context_t * generator_context_create(generator_t *generator)
{
	private_generator_context_t *this = allocator_alloc_thing(private_generator_context_t);

	if (this == NULL)
	{
		return NULL;
	}

	/* object methods */
	this->public.destroy = (status_t (*) (generator_context_t *this))generator_context_destroy;
	this->make_space_available = generator_context_make_space_available;
	this->write_chunk = generator_context_write_chunk;
	this->write_bytes_to_buffer = generator_context_write_bytes_to_buffer;

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
	this->data_struct = NULL;
	this->current_bit = 0;
	return &(this->public);
}


/**
 * Private part of a generator_t object
 */
typedef struct private_generator_s private_generator_t;

struct private_generator_s {
	/**
	 * Public part of a generator_t object
	 */
	 generator_t public;

	/* private functions and fields */

	/**
	 * Generates a chunk_t with specific encoding rules.
	 *
	 * Iems are bytewhise written.
	 *
	 * @param this 					private_generator_t object
	 * @param data_struct 			data_struct to read data from
	 * @param encoding_rules 		pointer to first encoding_rule 
	 * 								of encoding rules array
	 * @param encoding_rules_count 	number of encoding rules 
	 * 								in encoding rules array
	 * @param data 					pointer to chunk_t where to write the data in
	 *
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 */
	status_t (*generate) (private_generator_t *this,void * data_struct,encoding_rule_t *encoding_rules, size_t encoding_rules_count, private_generator_context_t *generator_context);

	/**
	 * Generates a U_INT-Field type
	 *
	 * @param this 					private_generator_t object
	 * @param int_type 				type of U_INT field (U_INT_4, U_INT_8, etc.)
	 * @param offset 				offset of value in data struct
	 * @param generator_contexts		generator_contexts_t object where the context is written or read from
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_u_int_type) (private_generator_t *this,encoding_type_t int_type,u_int32_t offset, private_generator_context_t *generator_context);

	/**
	 * Generates a RESERVED BIT field or a RESERVED BYTE field
	 *
	 * @param this 					private_generator_t object
	 * @param generator_contexts		generator_contexts_t object where the context is written or read from
	 * @param bits 					number of bits to generate
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 * 								- FAILED if bit count not supported
	 */
	status_t (*generate_reserved_field) (private_generator_t *this,private_generator_context_t *generator_context,int bits);
	
	/**
	 * Generates a FLAG field
	 *
	 * @param this 					private_generator_t object
	 * @param generator_contexts		generator_contexts_t object where the context is written or read from
	 * @param offset					offset of flag value in data struct
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_flag) (private_generator_t *this,private_generator_context_t *generator_context,u_int32_t offset);

	/**
	 * Pointer to the payload informations needed to automatic
	 * generate a specific payload type
	 */
	payload_info_t **payload_infos;
};

/**
 * Implements private_generator_t's generate_u_int_type function.
 * See #private_generator_s.generate_u_int_type.
 */
static status_t generate_u_int_type (private_generator_t *this,encoding_type_t int_type,u_int32_t offset,private_generator_context_t *generator_context)
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
	if (((number_of_bits % 8) == 0) && (generator_context->current_bit != 0))
	{
		/* current bit has to be zero for values greater then 4 bits */
		return FAILED;
	}

	status = generator_context->make_space_available(generator_context,number_of_bits);

	if (status != SUCCESS)
	{
		return status;
	}

	switch (int_type)
	{
			case U_INT_4:
			{
				if (generator_context->current_bit == 0)
				{
					u_int8_t high_val = *((u_int8_t *)(generator_context->data_struct + offset)) << 4;
					u_int8_t low_val = *(generator_context->out_position) & 0x0F;

					*(generator_context->out_position) = high_val | low_val;
					/* write position is not changed, just bit position is moved */
					generator_context->current_bit = 4;
				}
				else if (generator_context->current_bit == 4)
				{
					u_int high_val = *(generator_context->out_position) & 0xF0;
					u_int low_val = *((u_int8_t *)(generator_context->data_struct + offset)) & 0x0F;
					*(generator_context->out_position) = high_val | low_val;
					generator_context->out_position++;
					generator_context->current_bit = 0;

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
				*generator_context->out_position = *((u_int8_t *)(generator_context->data_struct + offset));
				generator_context->out_position++;
				break;

			}
			case U_INT_16:
			{
				u_int16_t int16_val = htons(*((u_int16_t*)(generator_context->data_struct + offset)));
				generator_context->write_bytes_to_buffer(generator_context,&int16_val,sizeof(u_int16_t));

				break;
			}
			case U_INT_32:
			{
				u_int32_t int32_val = htonl(*((u_int32_t*)(generator_context->data_struct + offset)));
				generator_context->write_bytes_to_buffer(generator_context,&int32_val,sizeof(u_int32_t));
				break;
			}
			case U_INT_64:
			{
				u_int32_t int32_val_low = htonl(*((u_int32_t*)(generator_context->data_struct + offset)));
				u_int32_t int32_val_high = htonl(*((u_int32_t*)(generator_context->data_struct + offset) + 1));
				generator_context->write_bytes_to_buffer(generator_context,&int32_val_high,sizeof(u_int32_t));
				generator_context->write_bytes_to_buffer(generator_context,&int32_val_low,sizeof(u_int32_t));
				break;
			}

			default:
			return FAILED;

	}

	return SUCCESS;
}

static status_t generate_reserved_field (private_generator_t *this,private_generator_context_t *generator_context,int bits)
{
	status_t status;
	
	if ((bits != 1) && (bits != 8))
	{
		return FAILED;
	}
	status = generator_context->make_space_available(generator_context,bits);
	if (status != SUCCESS)
	{
		return status;
	}
	
	if (bits == 1)
	{	
		u_int8_t reserved_bit = ~(1 << (7 - generator_context->current_bit));

		*(generator_context->out_position) = *(generator_context->out_position) & reserved_bit;
		generator_context->current_bit++;
		if (generator_context->current_bit >= 8)
		{
			generator_context->current_bit = generator_context->current_bit % 8;
			generator_context->out_position++;
		}
	}
	else
	{
		/* one byte */
		if (generator_context->current_bit > 0)
		{
			return FAILED;
		}
		*(generator_context->out_position) = 0x00;
		generator_context->out_position++;
	}

	return SUCCESS;
		
		
}

static status_t generate_flag (private_generator_t *this,private_generator_context_t *generator_context,u_int32_t offset)
{
	status_t status;
	u_int8_t flag_value = (*((bool *) (generator_context->data_struct + offset))) ? 1 : 0;
	u_int8_t flag = (flag_value << (7 - generator_context->current_bit));
	
	status = generator_context->make_space_available(generator_context,1);
	if (status != SUCCESS)
	{
		return status;
	}

	*(generator_context->out_position) = *(generator_context->out_position) | flag;

	generator_context->current_bit++;
	if (generator_context->current_bit >= 8)
	{
		generator_context->current_bit = generator_context->current_bit % 8;
		generator_context->out_position++;
	}
	return SUCCESS;
}

/**
 * Implements private_generator_t's generate function.
 * See #private_generator_s.generate.
 */
static status_t generate (private_generator_t *this,void * data_struct,encoding_rule_t *encoding_rules, size_t encoding_rules_count, private_generator_context_t *generator_context)
{
	int i;
	status_t status;

	if (generator_context == NULL)
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
				status = this->generate_u_int_type(this,encoding_rules[i].type,encoding_rules[i].offset,generator_context);
				break;
			case RESERVED_BIT:
			{
				status = this->generate_reserved_field(this,generator_context,1);
	
				break;
			}
			case RESERVED_BYTE:
			{
				status = this->generate_reserved_field(this,generator_context,8);
				break;
			} 
			case FLAG:
			{
				status = this->generate_flag(this,generator_context,encoding_rules[i].offset);
				break;
			}
			case LENGTH:
				/* length is generated like an U_INT_32 */
				status = this->generate_u_int_type(this,U_INT_32,encoding_rules[i].offset,generator_context);
				break;
			case SPI_SIZE:
				/* currently not implemented */
			default:
				break;
		}
		if (status != SUCCESS)
		{
			generator_context->public.destroy(&(generator_context->public));
			return status;
		}
	}

//	infos->destroy(infos);
	return status;
}

/**
 * Implements generator_t's generate_payload function.
 * See #generator_s.generate_payload.
 */
static status_t generate_payload (private_generator_t *this,payload_type_t payload_type,void * data_struct,  generator_context_t *generator_context)
{
	int i;
	
	 private_generator_context_t *private_generator_context = (private_generator_context_t *) generator_context;
	 
	 private_generator_context->data_struct = data_struct;

	/* check every payload info for specific type */
	for (i = 0; this->payload_infos[i] != NULL; i++)
	{
		if (this->payload_infos[i]->payload_type == payload_type)
		{
			/* found payload informations, generating is done in private function generate() */
			return (this->generate(this, data_struct,this->payload_infos[i]->ecoding_rules,this->payload_infos[i]->encoding_rules_count,private_generator_context));
		}
	}
	return NOT_SUPPORTED;
}

status_t write_to_chunk (private_generator_t *this,private_generator_context_t *generator_context, chunk_t *data)
{
	return generator_context->write_chunk(generator_context,data);
}

/**
 * Implements generator_t's destroy function.
 * See #generator_s.destroy.
 */
static status_t destroy(private_generator_t *this)
{
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
	this->public.create_context = (generator_context_t * (*) (generator_t *)) generator_context_create;
	this->public.generate_payload = (status_t(*)(generator_t*, payload_type_t, void *, generator_context_t *)) generate_payload;
	this->public.destroy = (status_t(*)(generator_t*)) destroy;
	this->public.write_to_chunk = (status_t (*) (generator_t *,generator_context_t *, chunk_t *)) write_to_chunk;
	/* initiate private functions */
	this->generate = generate;
	this->generate_u_int_type = generate_u_int_type;
	this->generate_reserved_field = generate_reserved_field;
	this->generate_flag = generate_flag;

	/* initiate private variables */
	this->payload_infos = payload_infos;

	return &(this->public);
}
