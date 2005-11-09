/**
 * @file generator.h
 * 
 * @brief Generic generator class used to generate IKEv2-Header and Payload
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
#include "encodings.h"

/**
 * Data Buffer for generating has start size of 3000 Bytes
 */
#define GENERATOR_DATA_BUFFER_SIZE 3000

/**
 * @brief A generator_t-object which generates payloads of specific type
 */
typedef struct generator_s generator_t;

struct generator_s { 	

	/**
	 * @brief Generates a specific payload from given data struct
	 * 
	 * Remember: Header and substructures are also seen as payloads
	 * 
	 * @param generator generator object
	 * @param payload_type payload type to generate using the given data struct
	 * @param[in] data_struct Data struct where the needed data for generating are stored
	 * @param[out] output pointer to a chunk_t where the data are generated to
	 * @return SUCCESSFUL if succeeded,
	 * 		   NOT_SUPPORTED if payload_type is not supported
	 * 		   OUT_OF_RES if out of ressources
	 */
	status_t (*generate_payload) (generator_t *this,payload_type_t payload_type,void * data_struct, chunk_t *data);

	/**
	 * @brief Destroys a generator object
	 * 
	 * @param generator generator object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (generator_t *this);
};

/**
 * Constructor to create a generator
 * 
 * @param payload_infos	pointer to the payload_info_t-array containing
 * all the payload informations needed to automatic generate a specific payload
 */
generator_t * generator_create(payload_info_t ** payload_infos);

#endif /*GENERATOR_H_*/
