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


#include "generator.h"

#include "types.h"
#include "utils/allocator.h"
#include "utils/logger_manager.h"
#include "payloads/payload.h"


extern logger_manager_t *global_logger_manager;

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
	 * Generates a U_INT-Field type
	 *
	 * @param this 					private_generator_t object
	 * @param int_type 				type of U_INT field (U_INT_4, U_INT_8, etc.)
	 * @param offset 				offset of value in data struct
	 * @param generator_contexts		generator_contexts_t object where the context is written or read from
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_u_int_type) (private_generator_t *this,encoding_type_t int_type,u_int32_t offset);

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
	status_t (*generate_reserved_field) (private_generator_t *this,int bits);
	
	/**
	 * Generates a FLAG field
	 *
	 * @param this 					private_generator_t object
	 * @param generator_contexts		generator_contexts_t object where the context is written or read from
	 * @param offset					offset of flag value in data struct
	 * @return 						- SUCCESS if succeeded
	 * 		  						- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_flag) (private_generator_t *this,u_int32_t offset);
	
	/**
	 * Writes the current buffer content into a chunk_t
	 * 
	 * Memory of specific chunk_t gets allocated.
	 *
 	 * @param this				calling private_generator_t object
	 * @param data				pointer of chunk_t to write to
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_chunk) (private_generator_t *this,chunk_t *data);
	

	/**
	 * Makes sure enough space is available in buffer to store amount of bits.
     *
	 * If buffer is to small to hold the specific amount of bits it 
	 * is increased using reallocation function of allocator.
	 *
 	 * @param this 				calling private_generator_t object
	 * @param bits 				number of bits to make available in buffer
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*make_space_available) (private_generator_t *this,size_t bits);

	/**
	 * Writes a specific amount of byte into the buffer.
	 * 
	 * If buffer is to small to hold the specific amount of bytes it 
	 * is increased.
	 *
 	 * @param this				calling private_generator_t object
	 * @param bytes 				pointer to bytes to write
	 * @param number_of_bytes	number of bytes to write into buffer
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_bytes_to_buffer) (private_generator_t *this,void * bytes,size_t number_of_bytes);
	
	
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
	 * Associated Logger
	 */
	logger_t *logger;
};

/**
 * Implements private_generator_t's generate_u_int_type function.
 * See #private_generator_s.generate_u_int_type.
 */
static status_t generate_u_int_type (private_generator_t *this,encoding_type_t int_type,u_int32_t offset)
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
	if (((number_of_bits % 8) == 0) && (this->current_bit != 0))
	{
		/* current bit has to be zero for values greater then 4 bits */
		return FAILED;
	}

	status = this->make_space_available(this,number_of_bits);

	if (status != SUCCESS)
	{
		return status;
	}

	switch (int_type)
	{
			case U_INT_4:
			{
				if (this->current_bit == 0)
				{
					u_int8_t high_val = *((u_int8_t *)(this->data_struct + offset)) << 4;
					u_int8_t low_val = *(this->out_position) & 0x0F;

					*(this->out_position) = high_val | low_val;
					/* write position is not changed, just bit position is moved */
					this->current_bit = 4;
				}
				else if (this->current_bit == 4)
				{
					u_int high_val = *(this->out_position) & 0xF0;
					u_int low_val = *((u_int8_t *)(this->data_struct + offset)) & 0x0F;
					*(this->out_position) = high_val | low_val;
					this->out_position++;
					this->current_bit = 0;

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
				*this->out_position = *((u_int8_t *)(this->data_struct + offset));
				this->out_position++;
				break;

			}
			case U_INT_16:
			{
				u_int16_t int16_val = htons(*((u_int16_t*)(this->data_struct + offset)));
				this->write_bytes_to_buffer(this,&int16_val,sizeof(u_int16_t));

				break;
			}
			case U_INT_32:
			{
				u_int32_t int32_val = htonl(*((u_int32_t*)(this->data_struct + offset)));
				this->write_bytes_to_buffer(this,&int32_val,sizeof(u_int32_t));
				break;
			}
			case U_INT_64:
			{
				u_int32_t int32_val_low = htonl(*((u_int32_t*)(this->data_struct + offset)));
				u_int32_t int32_val_high = htonl(*((u_int32_t*)(this->data_struct + offset) + 1));
				this->write_bytes_to_buffer(this,&int32_val_high,sizeof(u_int32_t));
				this->write_bytes_to_buffer(this,&int32_val_low,sizeof(u_int32_t));
				break;
			}

			default:
			return FAILED;

	}

	return SUCCESS;
}

/**
 * Implements private_generator_t's generate_reserved_field function.
 * See #private_generator_s.generate_reserved_field.
 */
static status_t generate_reserved_field (private_generator_t *this,int bits)
{
	status_t status;
	
	if ((bits != 1) && (bits != 8))
	{
		return FAILED;
	}
	status = this->make_space_available(this,bits);
	if (status != SUCCESS)
	{
		return status;
	}
	
	if (bits == 1)
	{	
		u_int8_t reserved_bit = ~(1 << (7 - this->current_bit));

		*(this->out_position) = *(this->out_position) & reserved_bit;
		this->current_bit++;
		if (this->current_bit >= 8)
		{
			this->current_bit = this->current_bit % 8;
			this->out_position++;
		}
	}
	else
	{
		/* one byte */
		if (this->current_bit > 0)
		{
			return FAILED;
		}
		*(this->out_position) = 0x00;
		this->out_position++;
	}

	return SUCCESS;
		
		
}

/**
 * Implements private_generator_t's generate_flag function.
 * See #private_generator_s.generate_flag.
 */
static status_t generate_flag (private_generator_t *this,u_int32_t offset)
{
	status_t status;
	u_int8_t flag_value = (*((bool *) (this->data_struct + offset))) ? 1 : 0;
	u_int8_t flag = (flag_value << (7 - this->current_bit));
	
	status = this->make_space_available(this,1);
	if (status != SUCCESS)
	{
		return status;
	}

	*(this->out_position) = *(this->out_position) | flag;

	this->current_bit++;
	if (this->current_bit >= 8)
	{
		this->current_bit = this->current_bit % 8;
		this->out_position++;
	}
	return SUCCESS;
}

/**
 * Implements private_generator_t's generator_context_make_space_available function.
 * See #private_generator_s.generator_context_make_space_available.
 */
static status_t make_space_available (private_generator_t *this, size_t bits)
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
 * Implements private_generator_t's write_bytes_to_buffer function.
 * See #private_generator_s.write_bytes_to_buffer.
 */
static status_t write_bytes_to_buffer (private_generator_t *this,void * bytes,size_t number_of_bytes)
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
 * Implements generator_t's write_chunk function.
 * See #generator_s.write_chunk.
 */
static status_t write_to_chunk (private_generator_t *this,chunk_t *data)
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
 * Implements generator_t's generate_payload function.
 * See #generator_s.generate_payload.
 */
static status_t generate_payload (private_generator_t *this,payload_t *payload)
{
	int i;
	status_t status;
	this->data_struct = payload;
	size_t rule_count;
	encoding_rule_t *rules;
	
	
	payload_type_t payload_type = payload->get_type(payload);
	
	this->logger->log(this->logger,CONTROL,"Start generating payload of type %s",mapping_find(payload_type_t_mappings,payload_type));
	
	payload->get_encoding_rules(payload,&rules,&rule_count);

	for (i = 0; i < rule_count;i++)
	{
		status = SUCCESS;
		switch (rules[i].type)
		{
			/* all u int values are generated in generate_u_int_type */
			case U_INT_4:
			case U_INT_8:
			case U_INT_16:
			case U_INT_32:
			case U_INT_64:
				status = this->generate_u_int_type(this,rules[i].type,rules[i].offset);
				break;
			case RESERVED_BIT:
			{
				status = this->generate_reserved_field(this,1);
	
				break;
			}
			case RESERVED_BYTE:
			{
				status = this->generate_reserved_field(this,8);
				break;
			} 
			case FLAG:
			{
				status = this->generate_flag(this,rules[i].offset);
				break;
			}
			case PAYLOAD_LENGTH:
				/* payload length is generated like an U_INT_16 */
				status = this->generate_u_int_type(this,U_INT_16,rules[i].offset);
				break;

			case HEADER_LENGTH:
				/* header length is generated like an U_INT_32 */
				status = this->generate_u_int_type(this,U_INT_32,rules[i].offset);
				break;
			case SPI_SIZE:
				/* currently not implemented */
			default:
				break;
		}
	}

	return status;
	
	return NOT_SUPPORTED;
}

/**
 * Implements generator_t's destroy function.
 * See #generator_s.destroy.
 */
static status_t destroy(private_generator_t *this)
{
	allocator_free(this->buffer);
	global_logger_manager->destroy_logger(global_logger_manager,this->logger);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
generator_t * generator_create()
{
	private_generator_t *this;

	this = allocator_alloc_thing(private_generator_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* initiate public functions */
	this->public.generate_payload = (status_t(*)(generator_t*, payload_t *)) generate_payload;
	this->public.destroy = (status_t(*)(generator_t*)) destroy;
	this->public.write_to_chunk = (status_t (*) (generator_t *,chunk_t *)) write_to_chunk;
	
	
	/* initiate private functions */
//	this->generate = generate;
	this->generate_u_int_type = generate_u_int_type;
	this->generate_reserved_field = generate_reserved_field;
	this->generate_flag = generate_flag;
	this->make_space_available = make_space_available;
	this->write_bytes_to_buffer = write_bytes_to_buffer;


	/* allocate memory for buffer */
	this->buffer = allocator_alloc(GENERATOR_DATA_BUFFER_SIZE);
	if (this->buffer == NULL)
	{
		allocator_free(this);
		return NULL;
	}

	/* initiate private variables */
	this->out_position = this->buffer;
	this->roof_position = this->buffer + GENERATOR_DATA_BUFFER_SIZE;
	this->data_struct = NULL;
	this->current_bit = 0;
	this->logger = global_logger_manager->create_logger(global_logger_manager,GENERATOR,NULL);
	return &(this->public);
}
