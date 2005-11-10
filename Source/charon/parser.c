/**
 * @file parser.c
 *
 * @brief Generic parser class used to parse IKEv2-Header and Payload
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
#include <arpa/inet.h>

#include "allocator.h"
#include "types.h"
#include "parser.h"
#include "logger.h"


typedef struct private_parser_context_s private_parser_context_t;

struct private_parser_context_s {
	/**
	 * Public members
	 */
	parser_context_t public;

	/**
	 * Current bit for reading in input data
	 */
	u_int8_t bit_pos;
	
	/**
	 * Current byte for reading in input data
	 */
	u_int8_t *byte_pos;
	
	/**
	 * input data to parse
	 */
	u_int8_t *input;
	
	/**
	 * roof of input
	 */
	u_int8_t *input_roof;
	
	
};

static status_t parser_context_destroy(private_parser_context_t *this)
{
	allocator_free(this);
	
	return SUCCESS;	
}

static private_parser_context_t *parser_context_create(chunk_t input)
{
	private_parser_context_t *this = allocator_alloc_thing(private_parser_context_t);
	if (this == NULL)
	{
		return NULL;	
	}
	
	this->public.destroy = (status_t(*)(parser_context_t*)) parser_context_destroy;
	
	this->input = input.ptr;
	this->byte_pos = input.ptr;
	this->bit_pos = 0;
	this->input_roof = input.ptr + input.len;
	
	return this;
}



/**
 * Private data of a parser_t object
 */
typedef struct private_parser_s private_parser_t;

struct private_parser_s {
	/**
	 * Public part of a generator object
	 */
	 parser_t public;

	/**
	 * list of payloads and their description
	 */
	payload_info_t **payload_infos;
	
	/**
	 * logger object
	 */
	logger_t *logger;

	
};

static private_parser_context_t *create_context(private_parser_t *this, chunk_t data)
{
	private_parser_context_t *context = parser_context_create(data);
	
	return context;
}

static status_t parse_payload(private_parser_t *this, private_parser_context_t *context, payload_type_t payload_type, void **data_struct)
{
	payload_info_t *payload_info = NULL;
	
	/* find payload in null terminated list*/
	payload_info = *(this->payload_infos);
	while (payload_info)
	{
		if (payload_info->payload_type == payload_type)
		{
			void *output;
			int current;
			
			/* ok, do the parsing */
			output = allocator_alloc(payload_info->data_struct_length);
			
			for (current = 0; current < payload_info->encoding_rules_count; current++)
			{
				encoding_rule_t *rule = &(payload_info->ecoding_rules[current]);
				switch (rule->type)
				{
					case U_INT_4:
					{
						u_int8_t *output_pos = output + rule->offset;
						if (context->byte_pos + sizeof(u_int8_t) > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse U_INT_4");
							allocator_free(output);
							return PARSE_ERROR;
						}
						switch (context->bit_pos)
						{
							case 0:
								*output_pos = *(context->byte_pos) >> 4;
								context->bit_pos = 4;
								break;
							case 4:	
								*output_pos = *(context->byte_pos) & 0x0F;
								context->bit_pos = 0;
								context->byte_pos++;
								break;
							default:
								this->logger->log(this->logger, ERROR, "found rule U_INT_4 on bitpos %d", context->bit_pos);
								allocator_free(output);
								return PARSE_ERROR;
						}
						break;
					}
					case U_INT_8:
					{
						u_int8_t *output_pos = output + rule->offset;
						if (context->byte_pos + sizeof(u_int8_t)  > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse U_INT_8");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_8 on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}

						*output_pos = *(context->byte_pos);
						context->byte_pos++;
						break;
					}
					case U_INT_16:
					{
						u_int16_t *output_pos = output + rule->offset;
						if (context->byte_pos + sizeof(u_int16_t) > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse U_INT_16");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_16 on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}
						if ((int)context->byte_pos % 2)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_16 on odd bytepos");
							allocator_free(output);
							return PARSE_ERROR;
						}
						*output_pos = ntohs(*((u_int16_t*)context->byte_pos));
						context->byte_pos += 2;
						break;					
					}
					case U_INT_32:
					{
						u_int32_t *output_pos = output + rule->offset;
						if (context->byte_pos + sizeof(u_int32_t) > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse U_INT_32");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_32 on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}
						if ((int)context->byte_pos % 4)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_32 on unaligned bytepos");
							allocator_free(output);
							return PARSE_ERROR;
						}
						*output_pos = ntohl(*((u_int32_t*)context->byte_pos));
						context->byte_pos += 4;
						break;		
					}
					case U_INT_64:
					{
						u_int32_t *output_pos = output + rule->offset;
						if (context->byte_pos + 2 * sizeof(u_int32_t) > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse U_INT_64");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_64 on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}
						if ((int)context->byte_pos % 8)
						{
							this->logger->log(this->logger, ERROR, "found rule U_INT_64 on unaligned bytepos");
							allocator_free(output);
							return PARSE_ERROR;
						}
						/* assuming little endian host order */
						*(output_pos + 1) = ntohl(*((u_int32_t*)context->byte_pos));
						context->byte_pos += 4;
						*output_pos = ntohl(*((u_int32_t*)context->byte_pos));
						context->byte_pos += 4;
						
						break;	
					}
					case RESERVED_BIT:
					{
						if (context->byte_pos > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse RESERVED_BIT");
							allocator_free(output);
							return PARSE_ERROR;
						}
						context->bit_pos = (context->bit_pos + 1) % 8;
						if (context->bit_pos == 0) 
						{
							context->byte_pos++;	
						}
						break;
					}
					case RESERVED_BYTE:
					{
						if (context->byte_pos > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse RESERVED_BYTE");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule RESERVED_BYTE on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}
						context->byte_pos++;	
						break;
					}
					case FLAG:
					{
						bool *output_pos = output + rule->offset;
						u_int8_t mask;
						if (context->byte_pos > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse FLAG");
							allocator_free(output);
							return PARSE_ERROR;
						}
						mask = 0x01 << (7 - context->bit_pos);
						*output_pos = *context->byte_pos & mask;
					
						if (*output_pos)
						{
							/* set to a "clean", comparable true */
							*output_pos = TRUE;
						} 
						context->bit_pos = (context->bit_pos + 1) % 8;
						if (context->bit_pos == 0) 
						{
							context->byte_pos++;	
						}
						break;
					}
					case LENGTH:
					{
						u_int32_t *output_pos = output + rule->offset;
						if (context->byte_pos + sizeof(u_int32_t) > context->input_roof)
						{
							this->logger->log(this->logger, ERROR, "not enough input to parse LENGTH");
							allocator_free(output);
							return PARSE_ERROR;
						}
						if (context->bit_pos)
						{
							this->logger->log(this->logger, ERROR, "found rule LENGTH on bitpos %d", context->bit_pos);
							allocator_free(output);
							return PARSE_ERROR;
						}
						if ((int)context->byte_pos % 4)
						{
							this->logger->log(this->logger, ERROR, "found rule LENGTH on unaligned bytepos");
							allocator_free(output);
							return PARSE_ERROR;
						}
						*output_pos = ntohl(*((u_int32_t*)context->byte_pos));
						context->byte_pos += 4;
						break;		
					
					}
					case SPI_SIZE:
					{
						
					}
					default:
					{
						this->logger->log(this->logger, ERROR, "parser found unknown type");
						allocator_free(output);
						return PARSE_ERROR;
					}
				}	
			}
			
			*data_struct = output;
			return SUCCESS;
		}
		payload_info++;
	}
	
	this->logger->log(this->logger, ERROR, "Payload not supported");
	return NOT_SUPPORTED;
}

static status_t destroy(private_parser_t *this)
{
	this->logger->destroy(this->logger);
	allocator_free(this);	
	
	return SUCCESS;
}

parser_t *parser_create(payload_info_t **payload_infos)
{
	private_parser_t *this = allocator_alloc_thing(private_parser_t);
	
	if (this == NULL)
	{
		return NULL;
	}
	
	this->logger = logger_create("parser", ALL);
	if (this->logger == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	this->public.create_context = (parser_context_t*(*)(parser_t*,chunk_t)) create_context;
	this->public.parse_payload = (status_t(*)(parser_t*,parser_context_t*,payload_type_t,void**)) parse_payload;
	this->public.destroy = (status_t(*)(parser_t*)) destroy;
	
	this->payload_infos = payload_infos;	
	
	
	return (parser_t*)this;
}
