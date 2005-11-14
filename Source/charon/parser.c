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
#include "utils/linked_list.h"
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
	
	status_t (*parse_uint4) (private_parser_t*,encoding_rule_t*,int,u_int8_t*);
	status_t (*parse_uint8) (private_parser_t*,encoding_rule_t*,int,u_int8_t*);
	status_t (*parse_uint15) (private_parser_t*,encoding_rule_t*,int,u_int16_t*);
	status_t (*parse_uint16) (private_parser_t*,encoding_rule_t*,int,u_int16_t*);
	status_t (*parse_uint32) (private_parser_t*,encoding_rule_t*,int,u_int32_t*);
	status_t (*parse_uint64) (private_parser_t*,encoding_rule_t*,int,u_int32_t*);
	status_t (*parse_bit) (private_parser_t*,encoding_rule_t*,int,bool*);
	status_t (*parse_list) (private_parser_t*,encoding_rule_t*,int,linked_list_t**,payload_type_t,size_t);
	status_t (*parse_chunk) (private_parser_t*,encoding_rule_t*,int,chunk_t*,size_t);

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


static status_t parse_uint4(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int8_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t)  > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	switch (this->bit_pos)
	{
		case 0:
			/* caller interested in result ? */
			if (output_pos != NULL)
			{
				*output_pos = *(this->byte_pos) >> 4;
			}
			this->bit_pos = 4;
			break;
		case 4:	
			/* caller interested in result ? */
			if (output_pos != NULL)
			{
				*output_pos = *(this->byte_pos) & 0x0F;
			}
			this->bit_pos = 0;
			this->byte_pos++;
			break;
		default:
			this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
								rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
			return PARSE_ERROR;
	}
	
	if (output_pos != NULL)
	{
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	
	
	return SUCCESS;
}

static status_t parse_uint8(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int8_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t)  > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}

	/* caller interested in result ? */
	if (output_pos != NULL)
	{
		*output_pos = *(this->byte_pos);
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	this->byte_pos++;
	
	
	
	return SUCCESS;
}

static status_t parse_uint15(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int16_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int16_t) > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	if (this->bit_pos != 1)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	/* caller interested in result ? */
	if (output_pos != NULL)
	{
		*output_pos = ntohs(*((u_int16_t*)this->byte_pos)) & 0xEFFF;
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	this->byte_pos += 2;
	this->bit_pos = 0;
	
	
	
	return SUCCESS;
}


static status_t parse_uint16(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int16_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int16_t) > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	/* caller interested in result ? */
	if (output_pos != NULL)
	{
		*output_pos = ntohs(*((u_int16_t*)this->byte_pos));
		
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	this->byte_pos += 2;
	
	
	return SUCCESS;
}

static status_t parse_uint32(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int32_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int32_t) > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	/* caller interested in result ? */
	if (output_pos != NULL)
	{
		*output_pos = ntohl(*((u_int32_t*)this->byte_pos));
		
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	this->byte_pos += 4;
	
	
	return SUCCESS;
}

static status_t parse_uint64(private_parser_t *this, encoding_rule_t *rule, int rule_number, u_int32_t *output_pos)
{
	if (this->byte_pos + 2 * sizeof(u_int32_t) > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	/* caller interested in result ? */
	if (output_pos != NULL)
	{
		/* assuming little endian host order */
		*(output_pos + 1) = ntohl(*((u_int32_t*)this->byte_pos));
		*output_pos = ntohl(*(((u_int32_t*)this->byte_pos) + 1));
		
		this->logger->log_bytes(this->logger, RAW, "   =>", (void*)output_pos, 8);
	}
	this->byte_pos += 8;
	
	
	
	return SUCCESS;
}


static status_t parse_bit(private_parser_t *this, encoding_rule_t *rule, int rule_number, bool *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;
	}
	/* caller interested in result ? */
	if (output_pos != NULL)
	{	
		u_int8_t mask;
		mask = 0x01 << (7 - this->bit_pos);
		*output_pos = *this->byte_pos & mask;
	
		if (*output_pos)
		{
			/* set to a "clean", comparable true */
			*output_pos = TRUE;
		}
		
		this->logger->log(this->logger, RAW, "   => %d", *output_pos);
	}
	this->bit_pos = (this->bit_pos + 1) % 8;
	if (this->bit_pos == 0) 
	{
		this->byte_pos++;	
	}
	

	return SUCCESS;
}

static status_t parse_list(private_parser_t *this, encoding_rule_t *rule, int rule_number, linked_list_t **output_pos, payload_type_t payload_type, size_t length)
{
	linked_list_t * list = *output_pos;
	
	if (length < 0)
	{
		this->logger->log(this->logger, ERROR, "  invalid length for rule %d %s", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type));
		return PARSE_ERROR;	
	}
	
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	
	while (length > 0)
	{
		u_int8_t *pos_before = this->byte_pos;
		payload_t *payload;
		status_t status;
		status = this->public.parse_payload((parser_t*)this, payload_type, &payload);
		if (status != SUCCESS)
		{
			return status;	
		}
		list->insert_last(list, payload);
		length -= this->byte_pos - pos_before;
	}
	*output_pos = list;
	return SUCCESS;	
}


static status_t parse_chunk(private_parser_t *this, encoding_rule_t *rule, int rule_number, chunk_t *output_pos, size_t length)
{
	if (this->byte_pos + length > this->input_roof)
	{
		this->logger->log(this->logger, ERROR, "  not enough input to parse rule %d %s, SPI_LENGTH: %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), length);
		return PARSE_ERROR;
	}
	if (this->bit_pos)
	{
		this->logger->log(this->logger, ERROR, "  found rule %d %s on bitpos %d", 
							rule_number, mapping_find(encoding_type_t_mappings, rule->type), this->bit_pos);
		return PARSE_ERROR;
	}
	if (output_pos != NULL)
	{
		output_pos->len = length;
		output_pos->ptr = allocator_alloc(length);
		if (output_pos->ptr == NULL)
		{
			return OUT_OF_RES;	
		}
		memcpy(output_pos->ptr, this->byte_pos, length);
		
		this->logger->log_bytes(this->logger, RAW, "   =>", output_pos->ptr, length);
	}
	this->byte_pos += length;
	
	return SUCCESS;
}

/**
 * implementation of parser_context_t.parse_payload
 */
static status_t parse_payload(private_parser_t *this, payload_type_t payload_type, payload_t **payload)
{
	payload_t *pld;
	void *output;
	size_t rule_count, payload_length, spi_size, attribute_length;
	bool attribute_format;
	int current;
	encoding_rule_t *rule;
	
	this->logger->log(this->logger, CONTROL, "parsing %s payload", mapping_find(payload_type_t_mappings, payload_type));
	
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
				if (this->parse_uint4(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case U_INT_8:
			{
				if (this->parse_uint8(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case U_INT_16:
			{
				if (this->parse_uint16(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;					
			}
			case U_INT_32:
			{
				if (this->parse_uint32(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;		
			}
			case U_INT_64:
			{
				if (this->parse_uint64(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;	
			}
			case RESERVED_BIT:
			{
				if (this->parse_bit(this, rule, current, NULL) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;	
			}
			case RESERVED_BYTE:
			{
				if (this->parse_uint8(this, rule, current, NULL) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case FLAG:
			{
				if (this->parse_bit(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;	
			}
			case PAYLOAD_LENGTH:
			{
				if (this->parse_uint16(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				payload_length = *(u_int16_t*)(output + rule->offset);
				break;							
			}
			case HEADER_LENGTH:
			{
				if (this->parse_uint32(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;							
			}
			case SPI_SIZE:
			{
				if (this->parse_uint8(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				spi_size = *(u_int8_t*)(output + rule->offset);
				break;							
			}
			case SPI:
			{
				if (this->parse_chunk(this, rule, current, output + rule->offset, spi_size) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;							
			}
			case PROPOSALS:
			{
				size_t proposals_length = payload_length - 4;
				if (this->parse_list(this, rule, current, output + rule->offset, PROPOSAL_SUBSTRUCTURE, proposals_length) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				//TODO check if next_payloads are correct?
				break;							
			}
			case TRANSFORMS:
			{
				size_t transforms_length = payload_length - spi_size - 8;
				if (this->parse_list(this, rule, current, output + rule->offset, TRANSFORM_SUBSTRUCTURE, transforms_length) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				//TODO check if we have the desired transforms count
				break;							
			}
			case TRANSFORM_ATTRIBUTES:
			{
				size_t transform_a_length = payload_length - 8;
				if (this->parse_list(this, rule, current, output + rule->offset, TRANSFORM_ATTRIBUTE, transform_a_length) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;							
			}
			case ATTRIBUTE_FORMAT:
			{
				if (this->parse_bit(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_format = *(bool*)(output + rule->offset);
				break;
			}
			case ATTRIBUTE_TYPE:
			{
				if (this->parse_uint15(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_format = *(bool*)(output + rule->offset);
				break;
			}
			case ATTRIBUTE_LENGTH_OR_VALUE:
			{	
				this->logger->log_bytes(this->logger, RAW, "ATTRIBUTE_LENGTH_OR_VALUE", this->byte_pos, 2);
	
				if (this->parse_uint16(this, rule, current, output + rule->offset) != SUCCESS) 
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_length = *(u_int16_t*)(output + rule->offset);
				this->logger->log_bytes(this->logger, RAW, "ATTRIBUTE_LENGTH_OR_VALUE", output + rule->offset, 2);
	
				break;
			}
			case ATTRIBUTE_VALUE:
			{
				if (attribute_format == FALSE)
				{
					if (this->parse_chunk(this, rule, current, output + rule->offset, attribute_length) != SUCCESS) 
					{
						pld->destroy(pld);
						return PARSE_ERROR;
					}
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "  no rule to parse rule %d %s (%d)", current, mapping_find(encoding_type_t_mappings, rule->type), rule->type);
				pld->destroy(pld);
				return PARSE_ERROR;
			}
		}
		/* process next rulue */
		rule++;
	}
	
	*payload = pld;
	
	this->logger->log(this->logger, CONTROL, "parsing %s successful", mapping_find(payload_type_t_mappings, payload_type));
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
	this->logger->enable_level(this->logger, CONTROL|CONTROL_MORE|ERROR|RAW);
	
	
	if (this->logger == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	
	this->public.parse_payload = (status_t(*)(parser_t*,payload_type_t,payload_t**)) parse_payload;
	this->public.destroy = (status_t(*)(parser_t*)) destroy;
	
		
	this->parse_uint4 = parse_uint4;
	this->parse_uint8 = parse_uint8;
	this->parse_uint15 = parse_uint15;
	this->parse_uint16 = parse_uint16;
	this->parse_uint32 = parse_uint32;
	this->parse_uint64 = parse_uint64;
	this->parse_bit = parse_bit;
	this->parse_list = parse_list;
	this->parse_chunk = parse_chunk;
	
	
	this->input = data.ptr;
	this->byte_pos = data.ptr;
	this->bit_pos = 0;
	this->input_roof = data.ptr + data.len;
	
	return (parser_t*)this;
}

