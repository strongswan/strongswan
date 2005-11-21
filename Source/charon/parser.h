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
#include "payloads/encodings.h"
#include "payloads/payload.h"


/**
 * @brief A parser_t object which parses payloads
 * 
 * A parser is used for parsing one chunk of data. Multiple
 * payloads can be parsed out of the chunk using parse_payload.
 * The parser remains the state until destroyed.
 */
typedef struct parser_s parser_t;

struct parser_s {
	
	/**
	 * @brief parses the next payload
	 * 
	 * @warning caller is responsible for freeing allocated payload
	 * 
	 * Rules for parsing are described in the payload definition.
	 *
	 * @param this				parser Object
	 * @param payload_type		payload type to parse
	 * @param[out] payload		pointer where parsed payload was allocated
	 * @return 			
	 * 							- SUCCESSFUL if succeeded,
	 * 		   					- NOT_SUPPORTED if payload_type is not supported
	 * 							- OUT_OF_RES if out of ressources
	 * 							- PARSE_ERROR if corrupted/invalid data found
	 */
	status_t (*parse_payload) (parser_t *this, payload_type_t payload_type, payload_t **payload);
	
	/**
	 * @brief Resets the current parser context
	 *
	 * @param parser		parser object
	 * @return 				
	 * 						- SUCCESSFUL in any case
	 */
	status_t (*reset_context) (parser_t *this);
	
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
 * @param data				chunk of data to parse with this parser object
 * @return 					the parser, or NULL if failed
 *
 */
parser_t *parser_create(chunk_t data);

#endif /*PARSER_H_*/
