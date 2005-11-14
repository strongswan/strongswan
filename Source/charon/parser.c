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

#include "parser.h"

#include "types.h"
#include "definitions.h"
#include "globals.h"
#include "utils/allocator.h"
#include "utils/logger.h"
#include "payloads/payload.h"

/**
 * @private data stored in a context
 * 
 * contains pointers and counters to store current state
 */
typedef struct private_parser_s private_parser_t;

struct private_parser_s {
	/**
	 * Public members
	 */
	parser_t public;

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
	
	/**
	 * logger object
	 */
	logger_t *logger;
	
	
};

/**
 * implementation of parser_context_t.parse_payload
 */
static status_t parse_payload(private_parser_t *this, payload_type_t payload_type, payload_t **payload)
{
	
	this->logger->log(this->logger, CONTROL, "parsing %s payload", mapping_find(payload_type_t_mappings, payload_type));
	
	/* find payload in null terminated list*/

	payload_t *pld;
	void *output;
	int current;
	encoding_rule_t *rule;
	size_t rule_count;
	
	/* ok, do the parsing */
	pld = payload_create(payload_type);
	if (pld == NULL)
	{
		this->logger->log(this->logger, ERROR, "  payload %s not supported", mapping_find(payload_type_t_mappings, payload_type));
		return NOT_SUPPORTED;	
	}
	/* base pointer for output, avoids casting in every rule */
	output = pld;
	
	pld->get_encoding_rules(pld, &rule, &rule_count);
	
	for (current = 0; current < rule_count; current++)
	{
		this->logger->log(this->logger, CONTROL_MORE, "  parsing rule %d %s", 
							current, mapping_find(encoding_type_t_mappings, rule->type));
		switch (rule->type)
		{
			case U_INT_4:
			{
				u_int8_t *output_pos = output + rule->offset;
				if (this->byte_pos + sizeof(u_int8_t)  > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				switch (this->bit_pos)
				{
					case 0:
						*output_pos = *(this->byte_pos) >> 4;
						this->bit_pos = 4;
						break;
					case 4:	
						*output_pos = *(this->byte_pos) & 0x0F;
						this->bit_pos = 0;
						this->byte_pos++;
						break;
					default:
						this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
											current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
						pld->destroy(pld);
						return PARSE_ERROR;
				}
				break;
			}
			case U_INT_8:
			{
				u_int8_t *output_pos = output + rule->offset;
				if (this->byte_pos + sizeof(u_int8_t)  > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}

				*output_pos = *(this->byte_pos);
				this->byte_pos++;
				break;
			}
			case U_INT_16:
			{
				u_int16_t *output_pos = output + rule->offset;
				if (this->byte_pos + sizeof(u_int16_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if ((int)this->byte_pos % 2)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos odd bytepos", 
											current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				*output_pos = ntohs(*((u_int16_t*)this->byte_pos));
				this->byte_pos += 2;
				break;					
			}
			case U_INT_32:
			{
				u_int32_t *output_pos = output + rule->offset;
				if (this->byte_pos + sizeof(u_int32_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if ((int)this->byte_pos % 4)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on unaligned bytepos", 
											current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				*output_pos = ntohl(*((u_int32_t*)this->byte_pos));
				this->byte_pos += 4;
				break;		
			}
			case U_INT_64:
			{
				u_int32_t *output_pos = output + rule->offset;
				if (this->byte_pos + 2 * sizeof(u_int32_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if ((int)this->byte_pos % 8)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on unaligned bytepos", 
											current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				/* assuming little endian host order */
				*(output_pos + 1) = ntohl(*((u_int32_t*)this->byte_pos));
				this->byte_pos += 4;
				*output_pos = ntohl(*((u_int32_t*)this->byte_pos));
				this->byte_pos += 4;
				
				break;	
			}
			case RESERVED_BIT:
			{
				if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				this->bit_pos = (this->bit_pos + 1) % 8;
				if (this->bit_pos == 0) 
				{
					this->byte_pos++;	
				}
				break;
			}
			case RESERVED_BYTE:
			{
				if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				this->byte_pos++;	
				break;
			}
			case FLAG:
			{
				bool *output_pos = output + rule->offset;
				u_int8_t mask;
				if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				mask = 0x01 << (7 - this->bit_pos);
				*output_pos = *this->byte_pos & mask;
			
				if (*output_pos)
				{
					/* set to a "clean", comparable true */
					*output_pos = TRUE;
				} 
				this->bit_pos = (this->bit_pos + 1) % 8;
				if (this->bit_pos == 0) 
				{
					this->byte_pos++;	
				}
				break;
			}
			case HEADER_LENGTH:
			{
				u_int32_t *output_pos = output + rule->offset;
				if (this->byte_pos + sizeof(u_int32_t) > this->input_roof)
				{
					this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
										current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if (this->bit_pos)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
										current, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				if ((int)this->byte_pos % 4)
				{
					this->logger->log(this->logger, ERROR, "  found rule %d %s on unaligned bytepos", 
											current, mapping_find(encoding_type_t_mappings, rule->type));
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				*output_pos = ntohl(*((u_int32_t*)this->byte_pos));
				this->byte_pos += 4;
				break;		
			
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "  no rule to parse rule %d %s (%d)", current, mapping_find(payload_type_t_mappings, payload_type), payload_type);
				pld->destroy(pld);
				return PARSE_ERROR;
			}
		}
		/* process next rulue */
		rule++;
	}
	
	*payload = pld;
	return SUCCESS;
}

/**
 * implementation of parser_t.destroy
 */
static status_t destroy(private_parser_t *this)
{
	global_logger_manager->destroy_logger(global_logger_manager,this->logger);
	allocator_free(this);	
	
	return SUCCESS;
}

/*
 * see header file
 */
parser_t *parser_create(chunk_t data)
{
	private_parser_t *this = allocator_alloc_thing(private_parser_t);
	
	if (this == NULL)
	{
		return NULL;
	}
	
	this->logger = global_logger_manager->create_logger(global_logger_manager, PARSER, NULL);
	this->logger->enable_level(this->logger, ALL);
	
	
	if (this->logger == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	
	this->public.parse_payload = (status_t(*)(parser_t*,payload_type_t,payload_t**)) parse_payload;
	this->public.destroy = (status_t(*)(parser_t*)) destroy;
	
	
	this->input = data.ptr;
	this->byte_pos = data.ptr;
	this->bit_pos = 0;
	this->input_roof = data.ptr + data.len;
	
	return (parser_t*)this;
}

