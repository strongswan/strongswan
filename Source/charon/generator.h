/**
 * @file generator.h
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

#ifndef GENERATOR_H_
#define GENERATOR_H_

#include "types.h"
#include "payloads/encodings.h"
#include "payloads/payload.h"

/**
 * Generating is done in a data buffer.
 * This is thehe start size of this buffer in Bytes.
 */
#define GENERATOR_DATA_BUFFER_SIZE 10

/**
 * Number of bytes to increase the buffer, if it is to small.
 */
#define GENERATOR_DATA_BUFFER_INCREASE_VALUE 5

/**
 *A generator_t object which generates payloads of specific type.
 */
typedef struct generator_s generator_t;

struct generator_s {
	
	/**
	 * @brief Generates a specific payload from given payload object.
	 *
	 * Remember: Header and substructures are also handled as payloads.
	 *
	 * @param this 				generator_t object
	 * @param[in] payload 		interface payload_t implementing object
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 		   					- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_payload) (generator_t *this,payload_t *payload);
	
	/**
	 * Writes all generated data of current generator context to a chunk
	 *
	 * @param this 				generator_t object
 * 	 * @param[out] data 			chunk to write the data to
	 * @return 
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_to_chunk) (generator_t *this,chunk_t *data);

	/**
	 * @brief Destroys a generator_t object.
	 *
	 * @param this 		generator_t object
	 * 
	 * @return 			always success
	 */
	status_t (*destroy) (generator_t *this);
};

/**
 * Constructor to create a generator
 *
 */
generator_t * generator_create();

#endif /*GENERATOR_H_*/
