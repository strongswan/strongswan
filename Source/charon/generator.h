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
#define GENERATOR_DATA_BUFFER_SIZE 3000

/**
 * Number of bytes to increase the buffer, if it is to small.
 */
#define GENERATOR_DATA_BUFFER_INCREASE_VALUE 1000

/**
 * Used for generator operations internaly to store a generator context.
 */
typedef struct generator_context_s generator_context_t;

struct generator_context_s {
	/**
	 * @brief Destroys a generator_infos_t object and its containing buffer
	 *
	 * @param generator_infos_t generator_infos_t object
	 * @return 					always SUCCESSFUL
	 */
	status_t (*destroy) (generator_context_t *this);
};



/**
 *A generator_t object which generates payloads of specific type.
 */
typedef struct generator_s generator_t;

struct generator_s {
	
	/**
	 * Creates a generator_context_t object holding necessary informations
	 * for generating (buffer, data_struct, etc).
	 * 
	 * After using, this context has to get destroyed!
	 *
	 * @param data_struct 	data struct where the specific payload informations are stored
	 * @return 				
	 * 						- pointer to created generator_infos_t object
	 * 						- NULL if memory allocation failed
	 */
	generator_context_t * (*create_context) (generator_t *this);

	/**
	 * @brief Generates a specific payload from given data struct.
	 *
	 * Remember: Header and substructures are also handled as payloads.
	 *
	 * @param this 					generator_t object
	 * @param payload_type 			payload type to generate using the given data struct
	 * @param[in] data_struct 		data struct where the needed data for generating are stored
	 * @param 						generator_context 	generator context to use when generating
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 		   					- NOT_SUPPORTED if payload_type is not supported
	 * 		   					- OUT_OF_RES if out of ressources
	 */
	status_t (*generate_payload) (generator_t *this,payload_type_t payload_type,void * data_struct,generator_context_t *generator_context);
	
	/**
	 * Writes all generated data of current context to a chunk
	 *
	 * @param this 				generator_t object
	 * @param generator_context 	generator context to use when generating
 * 	 * @param[out] data 			chunk to write the data to
	 * @return 
	 * @return 
	 * 							- SUCCESSFUL if succeeded
	 * 							- OUT_OF_RES otherwise
	 */
	status_t (*write_to_chunk) (generator_t *this,generator_context_t *generator_context, chunk_t *data);

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
 * @param payload_infos		pointer to the payload_info_t-array containing
 * 							all the payload informations needed to 
 * 							automatic generate a specific payload
 */
generator_t * generator_create();

#endif /*GENERATOR_H_*/
