/**
 * @file der_decoder.h
 *
 * @brief Interface of der_decoder_t.
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

#ifndef DER_DECODER_H_
#define DER_DECODER_H_

#include <types.h>
#include <asn1/asn1.h>

typedef struct der_decoder_t der_decoder_t;

/**
 * @brief Decode der_encoded bytes to usable structures.
 * 
 * @b Constructors:
 *  - der_decoder_create()
 * 
 * @ingroup asn1
 */
struct der_decoder_t {
	
	status_t (*decode) (der_decoder_t *this, chunk_t input, void *output);

	/**
	 * @brief Destroys a der_decoder object.
	 *
	 * @param der_decoder 	calling object
	 */
	void (*destroy) (der_decoder_t *this);
};


/**
 * @brief Create a der_decoder instance.
 * 
 * @return	der_decoder_t object
 * 
 * @ingroup ans1
 */
der_decoder_t * der_decoder_create(asn1_rule_t* rules);

#endif /* DER_DECODER_H_ */
