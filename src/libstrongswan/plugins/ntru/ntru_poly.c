/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2009-2013  Security Innovation
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

#include "ntru_poly.h"
#include "ntru_mgf1.h"

#include <utils/debug.h>
#include <utils/test.h>

typedef struct private_ntru_poly_t private_ntru_poly_t;

/**
 * Private data of an ntru_poly_t object.
 */
struct private_ntru_poly_t {

	/**
	 * Public ntru_poly_t interface.
	 */
	ntru_poly_t public;

	/**
	 * Array containing the indices of the non-zero coefficients
	 */
	uint16_t *indices;

	/**
	 * Number of non-zero coefficients
	 */
	uint32_t indices_len;

};

METHOD(ntru_poly_t, get_size, size_t,
	private_ntru_poly_t *this)
{
	return this->indices_len;
}

METHOD(ntru_poly_t, get_indices, uint16_t*,
	private_ntru_poly_t *this)
{
	return this->indices;
}

METHOD(ntru_poly_t, destroy, void,
	private_ntru_poly_t *this)
{
	memwipe(this->indices, this->indices_len);
	free(this->indices);
	free(this);
}

/*
 * Described in header.
 */
ntru_poly_t *ntru_poly_create(hash_algorithm_t alg, chunk_t seed,
							  uint8_t c_bits, uint16_t limit, 
    						  uint16_t poly_len, uint32_t indices_count,
							  bool is_product_form)
{
	private_ntru_poly_t *this;
	size_t hash_len, octet_count = 0, i, num_polys, num_indices[3], indices_len;
	uint8_t octets[HASH_SIZE_SHA512], *used, num_left = 0, num_needed;
	uint16_t index, left = 0;
	int poly_i = 0, index_i = 0;
	ntru_mgf1_t *mgf1;

	DBG2(DBG_LIB, "MGF1 is seeded with %u bytes", seed.len);
	mgf1 = ntru_mgf1_create(alg, seed, TRUE);
	if (!mgf1)
	{
	    return NULL;
	}
	i = hash_len = mgf1->get_hash_size(mgf1);

	if (is_product_form)
	{
		num_polys = 3;
		num_indices[0] = 0xff &  indices_count;
		num_indices[1] = 0xff & (indices_count >> 8);
		num_indices[2] = 0xff & (indices_count >> 16);
		indices_len = num_indices[0] + num_indices[1] + num_indices[2];
	}
	else
	{
		num_polys = 1;
		num_indices[0] = indices_count;
		indices_len = indices_count;
	}
	used = malloc(poly_len);

	INIT(this,
		.public = {
			.get_size = _get_size,
			.get_indices = _get_indices,
			.destroy = _destroy,
		},
		.indices_len = indices_len,
		.indices = malloc(indices_len * sizeof(uint16_t)),
	);

	/* generate indices for all polynomials */
	while (poly_i < num_polys)
	{
		memset(used, 0, poly_len);

		/* generate indices for a single polynomial */
		while (num_indices[poly_i])
		{
			/* generate a random candidate index with a size of c_bits */		
			do
			{
				/* use any leftover bits first */
				index = num_left ? left << (c_bits - num_left) : 0;

				/* get the rest of the bits needed from new octets */
				num_needed = c_bits - num_left;

				while (num_needed)
				{
					if (i == hash_len)
					{
						/* get another block from MGF1 */
						if (!mgf1->get_mask(mgf1, hash_len, octets))
						{
							mgf1->destroy(mgf1);
							destroy(this);
							free(used);
							return NULL;
						}
						octet_count += hash_len;
						i = 0;
					}
					left = octets[i++];

					if (num_needed <= 8)
					{
						/* all bits needed to fill the index are in this octet */
						index |= left >> (8 - num_needed);
						num_left = 8 - num_needed;
						num_needed = 0;
						left &= 0xff >> (8 - num_left);
					}
					else
					{
						/* more than one octet will be needed */
						index |= left << (num_needed - 8);
						num_needed -= 8;
					}
				}
			}
			while (index >= limit);

			/* form index and check if unique */
			index %= poly_len;
			if (!used[index])
			{
				used[index] = 1;
				this->indices[index_i++] = index;
				num_indices[poly_i]--;
			}
		}
		poly_i++;
	}

	DBG2(DBG_LIB, "MGF1 generates %u octets to derive %u indices",
				   octet_count, this->indices_len);
	mgf1->destroy(mgf1);
	free(used);

	return &this->public;
}

EXPORT_FUNCTION_FOR_TESTS(ntru, ntru_poly_create);
