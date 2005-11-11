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
#include "encodings/encodings.h"

/**
 * @brief The parser context stores state information for a parsing session.
 */
typedef struct parser_context_s parser_context_t;

struct parser_context_s {
	/**
	 * @brief destructor of parsing_context
	 * 
	 * called it when finished a parsing session
	 * 
	 * @param this		the parser_context_t to destroy
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*destroy) (parser_context_t *this);
};


/**
 * @brief A parser_t object which parses payloads of specific type
 */
typedef struct parser_s parser_t;

struct parser_s {
	
	/**
	 * @brief generates a context for parsing
	 *
	 * a context is used for a parsing session. It safes the state, such as
	 * parsing position, available size, ...
	 *
	 * @param parser			parser Object
	 * @param chunk				chunk of data to parse in this session
	 * @return 					the parsing_context, or NULL if failed
	 */

	parser_context_t *(*create_context) (parser_t *this, chunk_t data);
	
	/**
	 * @brief parses the next payload in the current context
	 * 
	 * @warning caller is responsible for freeing allocated data_struct
	 *
	 * @param parser			parser Object
	 * @param payload_type		payload to parse
	 * @param[out] data_struct	pointer where parsed data will be allocated
	 * @param context			the parsing context, describing the current parsing session
	 * @return 			
	 * 							- SUCCESSFUL if succeeded,
	 * 		   					- NOT_SUPPORTED if payload_type is not supported
	 * 							- OUT_OF_RES if out of ressources
	 * 							- PARSE_ERROR if corrupted data found
	 */
	status_t (*parse_payload) (parser_t *this, payload_type_t payload_type, void **data_struct, parser_context_t* context);
	
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
 * @brief Constructor to create a parser
 * 
 * The parser uses a set of payload_infos to know how to
 * parse different payloads.
 * 
 * @param payload_infos			list of payload_info_t 
 *
 */
parser_t *parser_create(payload_info_t **payload_infos);

#endif /*PARSER_H_*/
