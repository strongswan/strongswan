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



/**
 * @brief A parser_t object which parses payloads of specific type
 */
typedef struct parser_s parser_t;

struct parser_s {

	/**
	 * @brief Generates a specific payload from given data struct
	 *
	 * Remember: Header and substructures are also seen as payloads
	 *
	 * @param generator generator object
	 * @return SUCCESSFUL if succeeded,
	 * 		   NOT_SUPPORTED if payload_type is not supported
	 * 		   OUT_OF_RES if out of ressources
	 */
	status_t (*parse_payload) (parser_t *this, payload_type_t payload_type, chunk_t *data, void *data_struct);

	/**
	 * @brief Destroys a generator object
	 *
	 * @param generator generator object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (parser_t *this);
};

/**
 * Constructor to create a parser
 *
 */
parser_t *parser_create(payload_info_t ** payload_infos);

#endif /*PARSER_H_*/
