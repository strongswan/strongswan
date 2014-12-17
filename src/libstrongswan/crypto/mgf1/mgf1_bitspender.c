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

#include "mgf1_bitspender.h"

#include <crypto/mgf1/mgf1.h>

typedef struct private_mgf1_bitspender_t private_mgf1_bitspender_t;

/**
 * Private data structure for mgf1_bitspender_t object
 */
struct private_mgf1_bitspender_t {
	/**
	 * Public interface.
	 */
	mgf1_bitspender_t public;

	/**
	 * MGF1 bit mask generator
	 */
	mgf1_t *mgf1;

	/**
	 * Octet storage (accommodates up to 64 octets)
	 */
	uint8_t octets[HASH_SIZE_SHA512];

	/**
	 * Length of the returned hash value in octets
	 */
	int hash_len;

	/**
	 * Number of generated octets
	 */
	int octets_count;

	/**
	 * Number of available octets
	 */
	int octets_left;

	/**
	 * Bit storage (accommodates up to 32 bits)
	 */
	uint32_t bits;

	/**
	 * Number of available bits
	 */
	int bits_left;

	/**
	 * Byte storage (accommodates up to 4 bytes)
	 */
	uint8_t bytes[4];

	/**
	 * Number of available bytes
	 */
	int bytes_left;

};

METHOD(mgf1_bitspender_t, get_bits, bool,
	private_mgf1_bitspender_t *this, int bits_needed, uint32_t *bits)
{
	int bits_now;

	*bits = 0x00000000;

	if (bits_needed == 0)
	{
		/* trivial */
		return TRUE;
	}
	if (bits_needed > 32)
	{
		/* too many bits requested */
		return FALSE;
	}

	while (bits_needed)
	{
		if (this->bits_left == 0)
		{
			if (this->octets_left == 0)
			{
				/* get another block from MGF1 */
				if (!this->mgf1->get_mask(this->mgf1, this->hash_len,
													  this->octets))
				{
					/* no block available */
					return FALSE;
				}
				this->octets_left = this->hash_len;
				this->octets_count += this->hash_len;
			}
			this->bits = untoh32(this->octets + this->hash_len -
												this->octets_left);
			this->bits_left = 32;
			this->octets_left -= 4;
		}
		if (bits_needed > this->bits_left)
		{
			bits_now = this->bits_left;
			this->bits_left = 0;
			bits_needed -= bits_now;
		}
		else
		{
			bits_now = bits_needed;
			this->bits_left -= bits_needed;
			bits_needed = 0;
		}
		if (bits_now == 32)
		{
			*bits = this->bits;
		}
		else
		{
			*bits <<= bits_now;
			*bits |= this->bits >> this->bits_left;
			if (this->bits_left)
			{
				this->bits &= 0xffffffff >> (32 - this->bits_left);
			}
		}
	}
	return TRUE;
}

METHOD(mgf1_bitspender_t, get_byte, bool,
	private_mgf1_bitspender_t *this, uint8_t *byte)
{
	if (this->bytes_left == 0)
	{
		if (this->octets_left == 0)
		{
			/* get another block from MGF1 */
			if (!this->mgf1->get_mask(this->mgf1, this->hash_len, this->octets))
			{
				/* no block available */
				return FALSE;
			}
			this->octets_left = this->hash_len;
			this->octets_count += this->hash_len;
		}
		memcpy(this->bytes, this->octets + this->hash_len -	this->octets_left, 4);
		this->bytes_left = 4;
		this->octets_left -= 4;
	}
	*byte = this->bytes[4 - this->bytes_left--];

	return TRUE;
}

METHOD(mgf1_bitspender_t, destroy, void,
	private_mgf1_bitspender_t *this)
{
	DBG2(DBG_LIB, "mgf1 generated %u octets", this->octets_count);
	memwipe(this->octets, sizeof(this->octets));
	this->mgf1->destroy(this->mgf1);
	free(this);
}

/**
 * See header.
 */
mgf1_bitspender_t *mgf1_bitspender_create(hash_algorithm_t alg, chunk_t seed,
										  bool hash_seed)
{
	private_mgf1_bitspender_t *this;
	mgf1_t *mgf1;

	mgf1 = mgf1_create(alg, seed, hash_seed);
	if (!mgf1)
	{
	    return NULL;
	}
	DBG2(DBG_LIB, "mgf1 based on %N is seeded with %u octets",
				   hash_algorithm_short_names, alg, seed.len);

	INIT(this,
		.public = {
			.get_bits = _get_bits,
			.get_byte = _get_byte,
			.destroy = _destroy,
		},
		.mgf1 = mgf1,
		.hash_len = mgf1->get_hash_size(mgf1),
	);

	return &this->public;
}
