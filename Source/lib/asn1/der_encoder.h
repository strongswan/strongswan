/**
 * @file der_encoder.h
 *
 * @brief Interface of der_encoder_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef DER_ENCODER_H_
#define DER_ENCODER_H_

#include <types.h>

typedef struct der_encoder_t der_encoder_t;

/**
 * @brief Decode der_encoded bytes to usable structures.
 * 
 * @b Constructors:
 *  - der_encoder_create()
 * 
 * @ingroup asn1
 */
struct der_encoder_t {
	
	status_t encode(der_encoder_t *this, void *input, chunk_t output);

	/**
	 * @brief Destroys a der_encoder object.
	 *
	 * @param der_encoder 	calling object
	 */
	void (*destroy) (der_encoder_t *this);
};


/**
 * @brief Create a der_encoder instance.
 * 
 * @return	der_encoder_t object
 * 
 * @ingroup ans1
 */
der_encoder_t * der_encoder_create(asn1_rule_t *rules);

#endif /* DER_ENCODER_H_ */
