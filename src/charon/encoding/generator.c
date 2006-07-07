/**
 * @file generator.c
 *
 * @brief Implementation of generator_t.
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

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>


#include "generator.h"

#include <types.h>
#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/vendor_id_payload.h>
#include <encoding/payloads/cp_payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <encoding/payloads/eap_payload.h>


typedef struct private_generator_t private_generator_t;

/**
 * Private part of a generator_t object.
 */
struct private_generator_t {
	/**
	 * Public part of a generator_t object.
	 */
	 generator_t public;
	 
	/**
	 * Generates a U_INT-Field type and writes it to buffer.
	 *
	 * @param this 					private_generator_t object
	 * @param int_type 				type of U_INT field (U_INT_4, U_INT_8, etc.)
	 * 								ATTRIBUTE_TYPE is also generated in this function
	 * @param offset 				offset of value in data struct
	 * @param generator_contexts	generator_contexts_t object where the context is written or read from
	 * @return
	 *  							- SUCCESS
	 * 								- FAILED if allignment is wrong
	 */
	void (*generate_u_int_type) (private_generator_t *this,encoding_type_t int_type,u_int32_t offset);

	/**
	 * Get size of current buffer in bytes.
	 *
	 * @param this 					private_generator_t object
	 * @return 						Size of buffer in bytes
	 */
	size_t (*get_current_buffer_size) (private_generator_t *this);
	
	/**
	 * Get free space of current buffer in bytes.
	 *
	 * @param this 					private_generator_t object
	 * @return 						space in buffer in bytes
	 */
	size_t (*get_current_buffer_space) (private_generator_t *this);

	/**
	 * Get length of data in buffer (in bytes).
	 *
	 * @param this 					private_generator_t object
	 * @return 						length of data in bytes
	 */	
	size_t (*get_current_data_length) (private_generator_t *this);

	/**
	 * Get current offset in buffer (in bytes).
	 *
	 * @param this 					private_generator_t object
	 * @return 						offset in bytes
	 */	
	u_int32_t (*get_current_buffer_offset) (private_generator_t *this);
	
	/**
	 * Generates a RESERVED BIT field or a RESERVED BYTE field and writes 
	 * it to the buffer.
	 *
	 * @param this 					private_generator_t object
	 * @param generator_contexts	generator_contexts_t object where the context is written or read from
	 * @param bits 					number of bits to generate
	 */
	void (*generate_reserved_field) (private_generator_t *this,int bits);
	
	/**
	 * Generates a FLAG field.
	 *
	 * @param this 					private_generator_t object
	 * @param generator_contexts	generator_contexts_t object where the context is written or read from
	 * @param offset				offset of flag value in data struct
	 */
	void (*generate_flag) (private_generator_t *this,u_int32_t offset);
	
	/**
	 * Writes the current buffer content into a chunk_t.
	 * 
	 * Memory of specific chunk_t gets allocated.
	 *
 	 * @param this				calling private_generator_t object
	 * @param data				pointer of chunk_t to write to
	 */
	void (*write_chunk) (private_generator_t *this,chunk_t *data);
	
	/**
	 * Generates a bytestream from a chunk_t.
	 *
	 * @param this 				private_generator_t object
	 * @param offset			offset of chunk_t value in data struct
	 */
	void (*generate_from_chunk) (private_generator_t *this,u_int32_t offset);	

	/**
	 * Makes sure enough space is available in buffer to store amount of bits.
     *
	 * If buffer is to small to hold the specific amount of bits it 
	 * is increased using reallocation function of allocator.
	 *
 	 * @param this 				calling private_generator_t object
	 * @param bits 				number of bits to make available in buffer
	 */
	void (*make_space_available) (private_generator_t *this,size_t bits);

	/**
	 * Writes a specific amount of byte into the buffer.
	 * 
	 * If buffer is to small to hold the specific amount of bytes it 
	 * is increased.
	 *
 	 * @param this				calling private_generator_t object
	 * @param bytes 			pointer to bytes to write
	 * @param number_of_bytes	number of bytes to write into buffer
	 */
	void (*write_bytes_to_buffer) (private_generator_t *this,void * bytes,size_t number_of_bytes);
	
	
	/**
	 * Writes a specific amount of byte into the buffer at a specific offset.
	 * 
	 * @warning buffer size is not check to hold the data if offset is to large.
	 *
 	 * @param this				calling private_generator_t object
	 * @param bytes 			pointer to bytes to write
	 * @param number_of_bytes	number of bytes to write into buffer
	 * @param offset			offset to write the data into
	 */
	void (*write_bytes_to_buffer_at_offset) (private_generator_t *this,void * bytes,size_t number_of_bytes,u_int32_t offset);
	
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
	
	/*
	 * Last payload length position offset in the buffer.
	 */
	u_int32_t last_payload_length_position_offset;
	
	/**
	 * Offset of the header length field in the buffer.
	 */
	u_int32_t header_length_position_offset;
	
	/**
	 * Last SPI size.
	 */
	u_int8_t last_spi_size;
	
	/*
	 * Attribute format of the last generated transform attribute.
	 * 
	 * Used to check if a variable value field is used or not for 
	 * the transform attribute value.
	 */
	bool attribute_format;
	
	/*
	 * Depending on the value of attribute_format this field is used
	 * to hold the length of the transform attribute in bytes.
	 */
	u_int16_t attribute_length;
	
	/**
	 * Associated Logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of private_generator_t.get_current_buffer_size.
 */
static size_t get_current_buffer_size (private_generator_t *this)
{
	return ((this->roof_position) - (this->buffer));
}

/**
 * Implementation of private_generator_t.get_current_buffer_space.
 */
static size_t get_current_buffer_space (private_generator_t *this)
{
	/* we know, one byte more */
	size_t space = (this->roof_position) - (this->out_position);
	return (space);
}

/**
 * Implementation of private_generator_t.get_current_data_length.
 */
static size_t get_current_data_length (private_generator_t *this)
{
	return (this->out_position - this->buffer);
}

/**
 * Implementation of private_generator_t.get_current_buffer_offset.
 */
static u_int32_t get_current_buffer_offset (private_generator_t *this)
{
	return (this->out_position - this->buffer);
}

/**
 * Implementation of private_generator_t.generate_u_int_type.
 */
static void generate_u_int_type (private_generator_t *this,encoding_type_t int_type,u_int32_t offset)
{
	size_t number_of_bits = 0;

	/* find out number of bits of each U_INT type to check for enough space 
	   in buffer */
	switch (int_type)
	{
			case U_INT_4:
				number_of_bits = 4;
				break;
			case TS_TYPE:
			case U_INT_8:
				number_of_bits = 8;
				break;
			case U_INT_16:
			case CONFIGURATION_ATTRIBUTE_LENGTH:
				number_of_bits = 16;
				break;
			case U_INT_32:
				number_of_bits = 32;
				break;
			case U_INT_64:
				number_of_bits = 64;
				break;
			case ATTRIBUTE_TYPE:
				number_of_bits = 15;
				break;
			case IKE_SPI:
				number_of_bits = 64;
				break;

			default:
			this->logger->log(this->logger, ERROR, "U_INT Type %s is not supported", 
							mapping_find(encoding_type_m,int_type));

			return;
	}
	/* U_INT Types of multiple then 8 bits must be aligned */
	if (((number_of_bits % 8) == 0) && (this->current_bit != 0))
	{
		this->logger->log(this->logger, ERROR, "U_INT Type %s is not 8 Bit aligned", 
							mapping_find(encoding_type_m,int_type));
		/* current bit has to be zero for values multiple of 8 bits */
		return;
	}
	
	/* make sure enough space is available in buffer */
	this->make_space_available(this,number_of_bits);
	/* now handle each u int type differently */
	switch (int_type)
	{
		case U_INT_4:
		{
			if (this->current_bit == 0)
			{
				/* highval of current byte in buffer has to be set to the new value*/
				u_int8_t high_val = *((u_int8_t *)(this->data_struct + offset)) << 4;
				/* lowval in buffer is not changed */
				u_int8_t low_val = *(this->out_position) & 0x0F;
				/* highval is set, low_val is not changed */
				*(this->out_position) = high_val | low_val;
				this->logger->log(this->logger, RAW|LEVEL2, "   => %d", *(this->out_position));
				/* write position is not changed, just bit position is moved */
				this->current_bit = 4;
			}
			else if (this->current_bit == 4)
			{
				/* highval in buffer is not changed */
				u_int high_val = *(this->out_position) & 0xF0;
				/* lowval of current byte in buffer has to be set to the new value*/
				u_int low_val = *((u_int8_t *)(this->data_struct + offset)) & 0x0F;
				*(this->out_position) = high_val | low_val;
				this->logger->log(this->logger, RAW|LEVEL2, "   => %d", *(this->out_position));
				this->out_position++;
				this->current_bit = 0;

			}
			else
			{
				this->logger->log(this->logger, ERROR, "U_INT_4 Type is not 4 Bit aligned");
				/* 4 Bit integers must have a 4 bit alignment */
				return;
			};
			break;
		}
		case TS_TYPE:
		case U_INT_8:
		{
			/* 8 bit values are written as they are */
			*this->out_position = *((u_int8_t *)(this->data_struct + offset));
			this->logger->log(this->logger, RAW|LEVEL2, "   => %d", *(this->out_position));
			this->out_position++;
			break;

		}
		case ATTRIBUTE_TYPE:
		{
			/* attribute type must not change first bit uf current byte ! */
			if (this->current_bit != 1)
			{
				this->logger->log(this->logger, ERROR, "ATTRIBUTE FORMAT flag is not set");
				/* first bit has to be set! */
				return;
			}
			/* get value of attribute format flag */
			u_int8_t attribute_format_flag = *(this->out_position) & 0x80;
			/* get attribute type value as 16 bit integer*/
			u_int16_t int16_val = htons(*((u_int16_t*)(this->data_struct + offset)));
			/* last bit must be unset */
			int16_val = int16_val & 0xFF7F;
			
			int16_val = int16_val | attribute_format_flag;
			this->logger->log(this->logger, RAW|LEVEL2, "   => %d", int16_val);
			/* write bytes to buffer (set bit is overwritten)*/				
			this->write_bytes_to_buffer(this,&int16_val,sizeof(u_int16_t));
			this->current_bit = 0;
			break;
			
		}
		case U_INT_16:
		case CONFIGURATION_ATTRIBUTE_LENGTH:
		{
			u_int16_t int16_val = htons(*((u_int16_t*)(this->data_struct + offset)));
			this->logger->log_bytes(this->logger, RAW|LEVEL2, "   =>", (void*)&int16_val, sizeof(int16_val));
			this->write_bytes_to_buffer(this,&int16_val,sizeof(u_int16_t));
			break;
		}
		case U_INT_32:
		{
			u_int32_t int32_val = htonl(*((u_int32_t*)(this->data_struct + offset)));
			this->logger->log_bytes(this->logger, RAW|LEVEL2, "   =>", (void*)&int32_val, sizeof(int32_val));
			this->write_bytes_to_buffer(this,&int32_val,sizeof(u_int32_t));
			break;
		}
		case U_INT_64:
		{
			/* 64 bit integers are written as two 32 bit integers */
			u_int32_t int32_val_low = htonl(*((u_int32_t*)(this->data_struct + offset)));
			u_int32_t int32_val_high = htonl(*((u_int32_t*)(this->data_struct + offset) + 1));
			this->logger->log_bytes(this->logger, RAW|LEVEL2, "   => (low)", (void*)&int32_val_low, sizeof(int32_val_low));
			this->logger->log_bytes(this->logger, RAW|LEVEL2, "   => (high)", (void*)&int32_val_high, sizeof(int32_val_high));
			/* TODO add support for big endian machines */
			this->write_bytes_to_buffer(this,&int32_val_high,sizeof(u_int32_t));
			this->write_bytes_to_buffer(this,&int32_val_low,sizeof(u_int32_t));
			break;
		}
		
		case IKE_SPI:
		{
			/* 64 bit are written as they come :-) */
			this->write_bytes_to_buffer(this,(this->data_struct + offset),sizeof(u_int64_t));
			this->logger->log_bytes(this->logger, RAW|LEVEL2, "   =>", (void*)(this->data_struct + offset), sizeof(u_int64_t));
			break;
		}
		default:
		{
			this->logger->log(this->logger, ERROR, "U_INT Type %s is not supported", mapping_find(encoding_type_m,int_type));
			return;
		}
	}
}

/**
 * Implementation of private_generator_t.generate_reserved_field.
 */
static void generate_reserved_field(private_generator_t *this,int bits)
{
	/* only one bit or 8 bit fields are supported */
	if ((bits != 1) && (bits != 8))
	{
		this->logger->log(this->logger, ERROR, "Reserved field of %d bits cannot be generated", bits);
		return ;
	}
	/* make sure enough space is available in buffer */
	this->make_space_available(this,bits);
	
	if (bits == 1)
	{	
		/* one bit processing */
		u_int8_t reserved_bit = ~(1 << (7 - this->current_bit));
		*(this->out_position) = *(this->out_position) & reserved_bit;
		if (this->current_bit == 0)
		{
			/* memory must be zero */
			*(this->out_position) = 0x00;
		}


		this->current_bit++;
		if (this->current_bit >= 8)
		{
			this->current_bit = this->current_bit % 8;
			this->out_position++;
		}
	}
	else
	{
		/* one byte processing*/
		if (this->current_bit > 0)
		{
			this->logger->log(this->logger, ERROR, 
								"Reserved field cannot be written cause allignement of current bit is %d",
								this->current_bit);
			return;
		}
		*(this->out_position) = 0x00;
		this->out_position++;
	}
}

/**
 * Implementation of private_generator_t.generate_flag.
 */
static void generate_flag (private_generator_t *this,u_int32_t offset)
{
	/* value of current flag */
	u_int8_t flag_value;
	/* position of flag in current byte */
	u_int8_t flag;
	
	/* if the value in the data_struct is TRUE, flag_value is set to 1, 0 otherwise */
	flag_value = (*((bool *) (this->data_struct + offset))) ? 1 : 0;
	/* get flag position */
	flag = (flag_value << (7 - this->current_bit));
	
	/* make sure one bit is available in buffer */
	this->make_space_available(this,1);
	if (this->current_bit == 0)
	{
		/* memory must be zero */
		*(this->out_position) = 0x00;
	}

	*(this->out_position) = *(this->out_position) | flag;
	
	
	this->logger->log(this->logger, RAW|LEVEL2, "   => %d", *(this->out_position));

	this->current_bit++;
	if (this->current_bit >= 8)
	{
		this->current_bit = this->current_bit % 8;
		this->out_position++;
	}
}

/**
 * Implementation of private_generator_t.generate_from_chunk.
 */
static void generate_from_chunk (private_generator_t *this,u_int32_t offset)
{
	if (this->current_bit != 0)
	{
		this->logger->log(this->logger, ERROR, "can not generate a chunk at Bitpos %d", this->current_bit);
		return ;
	}
	
	/* position in buffer */
	chunk_t *attribute_value = (chunk_t *)(this->data_struct + offset);
	
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "   =>", *attribute_value);
	
	/* use write_bytes_to_buffer function to do the job */
	this->write_bytes_to_buffer(this,attribute_value->ptr,attribute_value->len);
}

/**
 * Implementation of private_generator_t.make_space_available.
 */
static void make_space_available (private_generator_t *this, size_t bits)
{
	while (((this->get_current_buffer_space(this) * 8) - this->current_bit) < bits)
	{
		/* must increase buffer */
		size_t old_buffer_size = this->get_current_buffer_size(this);
		size_t new_buffer_size = old_buffer_size + GENERATOR_DATA_BUFFER_INCREASE_VALUE;
		size_t out_position_offset = ((this->out_position) - (this->buffer));

		this->logger->log(this->logger, CONTROL|LEVEL3, "increased gen buffer from %d to %d byte", 
							old_buffer_size, new_buffer_size);
		
		/* Reallocate space for new buffer */
		this->buffer = realloc(this->buffer,new_buffer_size);

		this->out_position = (this->buffer + out_position_offset);
		this->roof_position = (this->buffer + new_buffer_size);
	}
}

/**
 * Implementation of private_generator_t.write_bytes_to_buffer.
 */
static void write_bytes_to_buffer (private_generator_t *this,void * bytes, size_t number_of_bytes)
{
	int i;
	u_int8_t *read_position = (u_int8_t *) bytes;
	
	this->make_space_available(this,number_of_bytes * 8);

	for (i = 0; i < number_of_bytes; i++)
	{
		*(this->out_position) = *(read_position);
		read_position++;
		this->out_position++;
	}
}

/**
 * Implementation of private_generator_t.write_bytes_to_buffer_at_offset.
 */
static void write_bytes_to_buffer_at_offset (private_generator_t *this,void * bytes,size_t number_of_bytes,u_int32_t offset)
{
	int i;
	u_int8_t *read_position = (u_int8_t *) bytes;
	u_int8_t *write_position;
	u_int32_t free_space_after_offset = (this->get_current_buffer_size(this) - offset);

	/* check first if enough space for new data is available */	
	if (number_of_bytes > free_space_after_offset)
	{
		this->make_space_available(this,(number_of_bytes - free_space_after_offset) * 8);
	}
	
	write_position = this->buffer + offset;
	for (i = 0; i < number_of_bytes; i++)
	{
		*(write_position) = *(read_position);
		read_position++;
		write_position++;
	}
}

/**
 * Implementation of private_generator_t.write_to_chunk.
 */
static void write_to_chunk (private_generator_t *this,chunk_t *data)
{
	size_t data_length = this->get_current_data_length(this);
	u_int32_t header_length_field = data_length;
	
	/* write length into header length field */
	if (this->header_length_position_offset > 0)
	{
		u_int32_t int32_val = htonl(header_length_field);
		this->write_bytes_to_buffer_at_offset(this,&int32_val,sizeof(u_int32_t),this->header_length_position_offset);
	}

	if (this->current_bit > 0)
	data_length++;
	data->ptr = malloc(data_length);
	memcpy(data->ptr,this->buffer,data_length);
	data->len = data_length;
	
	this->logger->log_chunk(this->logger, RAW|LEVEL3, "generated data of this generator", *data);
}

/**
 * Implementation of private_generator_t.generate_payload.
 */
static void generate_payload (private_generator_t *this,payload_t *payload)
{
	int i;
	this->data_struct = payload;
	size_t rule_count;
	encoding_rule_t *rules;
	payload_type_t payload_type;
	u_int8_t *payload_start;
	
	/* get payload type */
	payload_type = payload->get_type(payload);
	/* spi size has to get reseted */
	this->last_spi_size = 0;
	
	payload_start = this->out_position;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "generating payload of type %s",
											mapping_find(payload_type_m,payload_type));
	
	/* each payload has its own encoding rules */
	payload->get_encoding_rules(payload,&rules,&rule_count);

	for (i = 0; i < rule_count;i++)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "  generating rule %d %s",
							i, mapping_find(encoding_type_m,rules[i].type));
		switch (rules[i].type)
		{
			/* all u int values, IKE_SPI,TS_TYPE and ATTRIBUTE_TYPE are generated in generate_u_int_type */
			case U_INT_4:
			case U_INT_8:
			case U_INT_16:
			case U_INT_32:
			case U_INT_64:
			case IKE_SPI:
			case TS_TYPE:
			case ATTRIBUTE_TYPE:
			case CONFIGURATION_ATTRIBUTE_LENGTH:
			{
				this->generate_u_int_type(this,rules[i].type,rules[i].offset);
				break;
			}
			case RESERVED_BIT:
			{
				this->generate_reserved_field(this,1);
				break;
			}
			case RESERVED_BYTE:
			{
				this->generate_reserved_field(this,8);
				break;
			} 
			case FLAG:
			{
				this->generate_flag(this,rules[i].offset);
				break;
			}
			case PAYLOAD_LENGTH:
			{
				/* position of payload lenght field is temporary stored */
				this->last_payload_length_position_offset = this->get_current_buffer_offset(this);
				/* payload length is generated like an U_INT_16 */
				this->generate_u_int_type(this,U_INT_16,rules[i].offset);
				break;
			}
			case HEADER_LENGTH:
			{
				/* position of header length field is temporary stored */			
				this->header_length_position_offset = this->get_current_buffer_offset(this);	
				/* header length is generated like an U_INT_32 */
				this->generate_u_int_type(this,U_INT_32,rules[i].offset);
				break;
			}
			case SPI_SIZE:
				/* spi size is handled as 8 bit unsigned integer */
				this->generate_u_int_type(this,U_INT_8,rules[i].offset);
				/* last spi size is temporary stored */
				this->last_spi_size = *((u_int8_t *)(this->data_struct + rules[i].offset));
				break;
			case ADDRESS:
			{
				/* the Address value is generated from chunk */
				this->generate_from_chunk(this,rules[i].offset);
				break;
			}
			case SPI:
			{
				/* the SPI value is generated from chunk */
				this->generate_from_chunk(this,rules[i].offset);
				break;
			}
			case KEY_EXCHANGE_DATA:
			case NOTIFICATION_DATA:
			case NONCE_DATA:
			case ID_DATA:
			case AUTH_DATA:
			case CERT_DATA:
			case CERTREQ_DATA:
			case SPIS:
			case CONFIGURATION_ATTRIBUTE_VALUE:
			case VID_DATA:
			case EAP_MESSAGE:
			{
				u_int32_t payload_length_position_offset;
				u_int16_t length_of_payload;
				u_int16_t header_length = 0;
				u_int16_t length_in_network_order;

				switch(rules[i].type)
				{
					case KEY_EXCHANGE_DATA:
						header_length = KE_PAYLOAD_HEADER_LENGTH;
						break;
					case NOTIFICATION_DATA:
						header_length = NOTIFY_PAYLOAD_HEADER_LENGTH + this->last_spi_size ;
						break;
					case NONCE_DATA:
						header_length = NONCE_PAYLOAD_HEADER_LENGTH;
						break;
					case ID_DATA:
						header_length = ID_PAYLOAD_HEADER_LENGTH;
						break;
					case AUTH_DATA:
						header_length = AUTH_PAYLOAD_HEADER_LENGTH;
						break;
					case CERT_DATA:
						header_length = CERT_PAYLOAD_HEADER_LENGTH;
						break;
					case CERTREQ_DATA:
						header_length = CERTREQ_PAYLOAD_HEADER_LENGTH;
						break;
					case SPIS:
						header_length = DELETE_PAYLOAD_HEADER_LENGTH;
						break;
					case VID_DATA:
						header_length = VENDOR_ID_PAYLOAD_HEADER_LENGTH;
						break;
					case CONFIGURATION_ATTRIBUTE_VALUE:
						header_length = CONFIGURATION_ATTRIBUTE_HEADER_LENGTH;
						break;
					case EAP_MESSAGE:
						header_length = EAP_PAYLOAD_HEADER_LENGTH;
						break;
					default:
						break;
				}
				
				/* the data value is generated from chunk */
				this->generate_from_chunk(this,rules[i].offset);

				payload_length_position_offset = this->last_payload_length_position_offset;
				
				
				/* Length of payload is calculated */
				length_of_payload = header_length + ((chunk_t *)(this->data_struct + rules[i].offset))->len;

				length_in_network_order = htons(length_of_payload);			
				this->write_bytes_to_buffer_at_offset(this,&length_in_network_order,sizeof(u_int16_t),payload_length_position_offset);
				break;
			}
			case PROPOSALS:
			{
				/* before iterative generate the transforms, store the current payload length position */
				u_int32_t payload_length_position_offset = this->last_payload_length_position_offset;
				/* Length of SA_PAYLOAD is calculated */
				u_int16_t length_of_sa_payload = SA_PAYLOAD_HEADER_LENGTH;
				u_int16_t int16_val;
				/* proposals are stored in a linked list and so accessed */
				linked_list_t *proposals = *((linked_list_t **)(this->data_struct + rules[i].offset));

				iterator_t *iterator;
				/* create forward iterator */
				iterator = proposals->create_iterator(proposals,TRUE);
				/* every proposal is processed (iterative call )*/
				while (iterator->has_next(iterator))
				{
					payload_t *current_proposal;
					u_int32_t before_generate_position_offset;
					u_int32_t after_generate_position_offset;
					
					iterator->current(iterator,(void **)&current_proposal);

					before_generate_position_offset = this->get_current_buffer_offset(this);
					this->public.generate_payload(&(this->public),current_proposal);
					after_generate_position_offset = this->get_current_buffer_offset(this);
					
					/* increase size of transform */
					length_of_sa_payload += (after_generate_position_offset - before_generate_position_offset);
				}
				iterator->destroy(iterator);
				
				int16_val = htons(length_of_sa_payload);
				this->write_bytes_to_buffer_at_offset(this,&int16_val,sizeof(u_int16_t),payload_length_position_offset);
				break;
			}	
			case TRANSFORMS:
			{	
				/* before iterative generate the transforms, store the current length position */
				u_int32_t payload_length_position_offset = this->last_payload_length_position_offset;
				u_int16_t length_of_proposal = PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH + this->last_spi_size;
				u_int16_t int16_val;
				linked_list_t *transforms = *((linked_list_t **)(this->data_struct + rules[i].offset));
				iterator_t *iterator;
								
				/* create forward iterator */
				iterator = transforms->create_iterator(transforms,TRUE);
				while (iterator->has_next(iterator))
				{
					payload_t *current_transform;
					u_int32_t before_generate_position_offset;
					u_int32_t after_generate_position_offset;
					
					iterator->current(iterator,(void **)&current_transform);
					
					before_generate_position_offset = this->get_current_buffer_offset(this);
					this->public.generate_payload(&(this->public),current_transform);
					after_generate_position_offset = this->get_current_buffer_offset(this);
					
					/* increase size of transform */
					length_of_proposal += (after_generate_position_offset - before_generate_position_offset);
				}
				
				iterator->destroy(iterator);
								
				int16_val = htons(length_of_proposal);
				this->write_bytes_to_buffer_at_offset(this,&int16_val,sizeof(u_int16_t),payload_length_position_offset);
				
				break;
			}	
			case TRANSFORM_ATTRIBUTES:
			{
				/* before iterative generate the transform attributes, store the current length position */
				u_int32_t transform_length_position_offset = this->last_payload_length_position_offset;

				u_int16_t length_of_transform = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
				u_int16_t int16_val;
				linked_list_t *transform_attributes =*((linked_list_t **)(this->data_struct + rules[i].offset));

				iterator_t *iterator;
				/* create forward iterator */
				iterator = transform_attributes->create_iterator(transform_attributes,TRUE);
				while (iterator->has_next(iterator))
				{
					payload_t *current_attribute;
					u_int32_t before_generate_position_offset;
					u_int32_t after_generate_position_offset;
					
					iterator->current(iterator,(void **)&current_attribute);
					
					before_generate_position_offset = this->get_current_buffer_offset(this);
					this->public.generate_payload(&(this->public),current_attribute);
					after_generate_position_offset = this->get_current_buffer_offset(this);
					
					/* increase size of transform */
					length_of_transform += (after_generate_position_offset - before_generate_position_offset);
				}
				
				iterator->destroy(iterator);
				
				int16_val = htons(length_of_transform);
				this->write_bytes_to_buffer_at_offset(this,&int16_val,sizeof(u_int16_t),transform_length_position_offset);
				
				break;
			}
			case CONFIGURATION_ATTRIBUTES:
			{
				/* before iterative generate the configuration attributes, store the current length position */
				u_int32_t configurations_length_position_offset = this->last_payload_length_position_offset;

				u_int16_t length_of_configurations = CP_PAYLOAD_HEADER_LENGTH;
				u_int16_t int16_val;
				linked_list_t *configuration_attributes =*((linked_list_t **)(this->data_struct + rules[i].offset));

				iterator_t *iterator;
				/* create forward iterator */
				iterator = configuration_attributes->create_iterator(configuration_attributes,TRUE);
				while (iterator->has_next(iterator))
				{
					payload_t *current_attribute;
					u_int32_t before_generate_position_offset;
					u_int32_t after_generate_position_offset;
					
					iterator->current(iterator,(void **)&current_attribute);
					
					before_generate_position_offset = this->get_current_buffer_offset(this);
					this->public.generate_payload(&(this->public),current_attribute);
					after_generate_position_offset = this->get_current_buffer_offset(this);
					
					/* increase size of transform */
					length_of_configurations += (after_generate_position_offset - before_generate_position_offset);
				}
				
				iterator->destroy(iterator);
				
				int16_val = htons(length_of_configurations);
				this->write_bytes_to_buffer_at_offset(this,&int16_val,sizeof(u_int16_t),configurations_length_position_offset);
				
				break;
			}	
			case ATTRIBUTE_FORMAT:
			{
				this->generate_flag(this,rules[i].offset);
				/* Attribute format is a flag which is stored in context*/
				this->attribute_format = *((bool *) (this->data_struct + rules[i].offset));
				break;
			}	

			case ATTRIBUTE_LENGTH_OR_VALUE:
			{
				if (this->attribute_format == FALSE)
				{
					this->generate_u_int_type(this,U_INT_16,rules[i].offset);
					/* this field hold the length of the attribute */
					this->attribute_length = *((u_int16_t *)(this->data_struct + rules[i].offset));
				}
				else
				{
					this->generate_u_int_type(this,U_INT_16,rules[i].offset);
				}
				break;
			}
			case ATTRIBUTE_VALUE:
			{
				if (this->attribute_format == FALSE)
				{
					this->logger->log(this->logger, CONTROL|LEVEL3, "attribute value has not fixed size");
					/* the attribute value is generated */
					this->generate_from_chunk(this,rules[i].offset);
				}
				break;
			}
			case TRAFFIC_SELECTORS:
			{
				/* before iterative generate the traffic_selectors, store the current payload length position */
				u_int32_t payload_length_position_offset = this->last_payload_length_position_offset;
				/* Length of SA_PAYLOAD is calculated */
				u_int16_t length_of_ts_payload = TS_PAYLOAD_HEADER_LENGTH;
				u_int16_t int16_val;
				/* traffic selectors are stored in a linked list and so accessed */
				linked_list_t *traffic_selectors = *((linked_list_t **)(this->data_struct + rules[i].offset));

				iterator_t *iterator;
				/* create forward iterator */
				iterator = traffic_selectors->create_iterator(traffic_selectors,TRUE);
				/* every proposal is processed (iterative call )*/
				while (iterator->has_next(iterator))
				{
					payload_t *current_traffic_selector_substructure;
					u_int32_t before_generate_position_offset;
					u_int32_t after_generate_position_offset;
					
					iterator->current(iterator,(void **)&current_traffic_selector_substructure);

					before_generate_position_offset = this->get_current_buffer_offset(this);
					this->public.generate_payload(&(this->public),current_traffic_selector_substructure);
					after_generate_position_offset = this->get_current_buffer_offset(this);
					
					/* increase size of transform */
					length_of_ts_payload += (after_generate_position_offset - before_generate_position_offset);
				}
				iterator->destroy(iterator);
				
				int16_val = htons(length_of_ts_payload);
				this->write_bytes_to_buffer_at_offset(this,&int16_val,sizeof(u_int16_t),payload_length_position_offset);
				break;
			}	
			
			case ENCRYPTED_DATA:
			{
				this->generate_from_chunk(this, rules[i].offset);
				break;
			}
			default:
				this->logger->log(this->logger, ERROR, "field type %s is not supported",
									mapping_find(encoding_type_m,rules[i].type));
				return;
		}
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, "generating %s payload finished.", 
					  mapping_find(payload_type_m, payload_type));
	this->logger->log_bytes(this->logger, RAW|LEVEL3, "generated data for this payload",
							payload_start, this->out_position-payload_start);
}

/**
 * Implementation of generator_t.destroy.
 */
static status_t destroy(private_generator_t *this)
{
	free(this->buffer);
	free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
generator_t *generator_create()
{
	private_generator_t *this;

	this = malloc_thing(private_generator_t);

	/* initiate public functions */
	this->public.generate_payload = (void(*)(generator_t*, payload_t *)) generate_payload;
	this->public.destroy = (void(*)(generator_t*)) destroy;
	this->public.write_to_chunk = (void (*) (generator_t *,chunk_t *)) write_to_chunk;
	
	
	/* initiate private functions */
	this->get_current_buffer_size = get_current_buffer_size;
	this->get_current_buffer_space = get_current_buffer_space;
	this->get_current_data_length = get_current_data_length;
	this->get_current_buffer_offset = get_current_buffer_offset;
	this->generate_u_int_type = generate_u_int_type;
	this->generate_reserved_field = generate_reserved_field;
	this->generate_flag = generate_flag;
	this->generate_from_chunk = generate_from_chunk;
	this->make_space_available = make_space_available;
	this->write_bytes_to_buffer = write_bytes_to_buffer;
	this->write_bytes_to_buffer_at_offset = write_bytes_to_buffer_at_offset;


	/* allocate memory for buffer */
	this->buffer = malloc(GENERATOR_DATA_BUFFER_SIZE);

	/* initiate private variables */
	this->out_position = this->buffer;
	this->roof_position = this->buffer + GENERATOR_DATA_BUFFER_SIZE;
	this->data_struct = NULL;
	this->current_bit = 0;
	this->last_payload_length_position_offset = 0;
	this->header_length_position_offset = 0;
	this->logger = logger_manager->get_logger(logger_manager, GENERATOR);

	return &(this->public);
}
