/**
 * @file generator.h
 *
 * @brief Interface of generator_t.
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

#include <types.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/payload.h>

/**
 * Generating is done in a data buffer.
 * This is thehe start size of this buffer in bytes.
 */
#define GENERATOR_DATA_BUFFER_SIZE 500

/**
 * Number of bytes to increase the buffer, if it is to small.
 */
#define GENERATOR_DATA_BUFFER_INCREASE_VALUE 500

typedef struct generator_t generator_t;

/**
 *A generator_t object which generates payloads of specific type.
 * 
 * @ingroup encoding
 */
struct generator_t {
	
	/**
	 * @brief Generates a specific payload from given payload object.
	 *
	 * Remember: Header and substructures are also handled as payloads.
	 *
	 * @param this 				generator_t object
	 * @param[in] payload 		interface payload_t implementing object
	 */
	void (*generate_payload) (generator_t *this,payload_t *payload);
	
	/**
	 * Writes all generated data of current generator context to a chunk.
	 *
	 * @param this 				generator_t object
 	 * @param[out] data 			chunk to write the data to
	 */
	void (*write_to_chunk) (generator_t *this,chunk_t *data);

	/**
	 * @brief Destroys a generator_t object.
	 *
	 * @param this 		generator_t object
	 */
	void (*destroy) (generator_t *this);
};

/**
 * Constructor to create a generator.
 * 
 * Returns a new generator_t object.
 * 
 * @ingroup encoding
 */
generator_t * generator_create();

#endif /*GENERATOR_H_*/
