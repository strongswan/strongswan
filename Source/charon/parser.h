/**
 * @file parser.h
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

#ifndef PARSER_H_
#define PARSER_H_

#include "types.h"
#include "encodings.h"


typedef struct parser_context_s parser_context_t;

struct parser_context_s {

	status_t (*destroy) (parser_context_t *this);
	
};


/**
 * @brief A parser_t object which parses payloads of specific type
 */
typedef struct parser_s parser_t;

struct parser_s {

	/**
	 * @brief parses a chunk and generates a usable data struct
	 *
	 * Remember: Header and substructures are also seen as payloads
	 *
	 * @param parser		parser Object
	 * @param payload_type	definition of payload including encoding_rule
	 * @param data			chunk of data to parse
	 * @param[out]			allocated structure with parsed data
	 * @return 			
	 * 						- SUCCESSFUL if succeeded,
	 * 		   				- NOT_SUPPORTED if payload_type is not supported
	 * 						- OUT_OF_RES if out of ressources
	 * 						- PARSE_ERROR if corrupted data found
	 */
	parser_context_t *(*create_context) (parser_t *this, chunk_t data);
	status_t (*parse_payload) (parser_t *this, parser_context_t* context, payload_type_t payload_type, void **data_struct);
	
	/**
	 * @brief Destroys a parser object
	 *
	 * @param parser		parser object
	 * @return 				
	 * 						- SUCCESSFUL in any case
	 */
	status_t (*destroy) (parser_t *this);
};

/**
 * Constructor to create a parser
 *
 */
parser_t *parser_create(payload_info_t **payload_infos);

#endif /*PARSER_H_*/
