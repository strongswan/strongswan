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
#include "bliss_bitpacker.h"


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

};

METHOD(bliss_signature_t, get_encoding, chunk_t,
	private_bliss_signature_t *this)
{
	bliss_bitpacker_t *packer;
	uint16_t z2d_bits;
	chunk_t encoding;
	int i;

	z2d_bits = this->set->z1_bits - this->set->d;

	packer = bliss_bitpacker_create(this->set->n * this->set->z1_bits +
									this->set->n * z2d_bits +
									this->set->kappa * this->set->n_bits);

	for (i = 0; i < this->set->n; i++)
	{
		packer->write_bits(packer, this->z1[i], this->set->z1_bits);
	}
	for (i = 0; i < this->set->n; i++)
	{
		packer->write_bits(packer, this->z2d[i], z2d_bits);
	}
	for (i = 0; i < this->set->kappa; i++)
	{
		packer->write_bits(packer, this->c_indices[i], this->set->n_bits);
	}
	encoding = packer->extract_buf(packer);

	DBG2(DBG_LIB, "generated BLISS signature (%u bits encoded in %u bytes)",
				   packer->get_bits(packer), encoding.len);
	packer->destroy(packer);

	return encoding;
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
	bliss_bitpacker_t *packer;
	uint32_t z1_sign, z1_mask;
	uint16_t z2d_sign, z2d_mask, value, z1_bits, z2d_bits;
	int i;

	z1_bits  = set->z1_bits;
	z2d_bits = set->z1_bits - set->d;

	if (8 * encoding.len < set->n * set->z1_bits + set->n * z2d_bits +
						   set->kappa * set->n_bits)
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
	);

	packer = bliss_bitpacker_create_from_data(encoding);

	z1_sign =   1 << (z1_bits - 1);
	z1_mask = ((1 << (32 - z1_bits)) - 1) << z1_bits;

	for (i = 0; i < set->n; i++)
	{
		packer->read_bits(packer, &value, z1_bits);
		this->z1[i] = value & z1_sign ? value | z1_mask : value;
	}

	z2d_sign =   1 << (z2d_bits - 1);
	z2d_mask = ((1 << (16 - z2d_bits)) - 1) << z2d_bits;

	for (i = 0; i < set->n; i++)
	{
		packer->read_bits(packer, &value, z2d_bits);
		this->z2d[i] = value & z2d_sign ? value | z2d_mask : value;
	}
	for (i = 0; i < set->kappa; i++)
	{
		packer->read_bits(packer, &value, set->n_bits);
		this->c_indices[i] = value;
	}
	packer->destroy(packer);

	return &this->public;
}
