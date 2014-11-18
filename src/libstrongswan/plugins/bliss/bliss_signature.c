/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "bliss_signature.h"


typedef struct private_bliss_signature_t private_bliss_signature_t;

/**
 * Private data of a bliss_signature_t object.
 */
struct private_bliss_signature_t {
	/**
	 * Public interface for this signer.
	 */
	bliss_signature_t public;

	/**
	 * BLISS signature parameter set
	 */
	bliss_param_set_t *set;

	/**
	 * BLISS signature vector z1 of size n
	 */
	int32_t *z1;

	/**
	 * BLISS signature vector z2d of size n
	 */
	int16_t *z2d;

	/**
	 * Indices of sparse BLISS challenge vector c of size kappa
	 */
	uint16_t *c_indices;

	/**
	 * Compressed encoding of BLISS signature
	 */
	chunk_t encoding;

};

METHOD(bliss_signature_t, get_encoding, chunk_t,
	private_bliss_signature_t *this)
{
	if (this->encoding.len == 0)
	{
		uint8_t *pos;
		int i;

		this->encoding = chunk_alloc(this->set->kappa * sizeof(uint16_t) +
									 this->set->n * sizeof(int16_t) +
									 this->set->n * sizeof(int8_t)),
		pos = this->encoding.ptr;

		for (i = 0; i < this->set->kappa; i++)
		{
			htoun16(pos, this->c_indices[i]);
			pos += 2;
		}
		for (i = 0; i < this->set->n; i++)
		{
			htoun16(pos, (uint16_t)this->z1[i]);
			pos += 2;
		}
		for (i = 0; i < this->set->n; i++)
		{
			*pos++ = (uint8_t)this->z2d[i];
		}
		DBG2(DBG_LIB, "generated BLISS signature (%u bytes)", 
					   this->encoding.len);
	}
	return chunk_clone(this->encoding);
}

METHOD(bliss_signature_t, get_parameters, void,
	private_bliss_signature_t *this, int32_t **z1, int16_t **z2d,
	uint16_t **c_indices)
{
	*z1 = this->z1;
	*z2d = this->z2d;
	*c_indices = this->c_indices;
}

METHOD(bliss_signature_t, destroy, void,
	private_bliss_signature_t *this)
{
	free(this->z1);
	free(this->z2d);
	free(this->c_indices);
	free(this->encoding.ptr);
	free(this);
}

/**
 * See header.
 */
bliss_signature_t *bliss_signature_create(bliss_param_set_t *set)
{
	private_bliss_signature_t *this;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.get_parameters = _get_parameters,
			.destroy = _destroy,
		},
		.set = set,
		.z1  = malloc(set->n * sizeof(int32_t)),
		.z2d = malloc(set->n * sizeof(int16_t)),
		.c_indices = malloc(set->n * sizeof(uint16_t)),
	);

	return &this->public;
}

/**
 * See header.
 */
bliss_signature_t *bliss_signature_create_from_data(bliss_param_set_t *set,
													chunk_t encoding)
{
	private_bliss_signature_t *this;
	uint8_t *pos;
	int i;

	if (encoding.len != set->kappa * sizeof(uint16_t) +
						set->n * sizeof(int16_t) + set->n * sizeof(int8_t))
	{
		DBG1(DBG_LIB, "incorrect BLISS signature size");
		return NULL;
	}

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.get_parameters = _get_parameters,
			.destroy = _destroy,
		},
		.set = set,
		.z1  = malloc(set->n * sizeof(int32_t)),
		.z2d = malloc(set->n * sizeof(int16_t)),
		.c_indices = malloc(set->n * sizeof(uint16_t)),
		.encoding = chunk_clone(encoding),
	);

	pos = encoding.ptr;

	for (i = 0; i < set->kappa; i++)
	{
		this->c_indices[i] = untoh16(pos);
		pos += 2;
	}
	for (i = 0; i < set->n; i++)
	{
		this->z1[i] = (int16_t)untoh16(pos);
		pos += 2;
	}
	for (i = 0; i < set->n; i++)
	{
		this->z2d[i] = (int8_t)(*pos++);
	}

	return &this->public;
}
