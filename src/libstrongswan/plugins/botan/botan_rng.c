/*
 * Copyright (C) 2018 René Korthaus
 * Rohde & Schwarz Cybersecurity GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "botan_rng.h"

#include <botan/build.h>

#ifdef BOTAN_HAS_HMAC_DRBG

#include <botan/ffi.h>

typedef struct private_botan_random_t private_botan_random_t;

/**
 * Private data of an botan_rng_t object.
 */
struct private_botan_random_t {

	/**
	 * Public botan_rnd_t interface.
	 */
	botan_random_t public;

	/**
	 * RNG quality of this instance
	 */
	rng_quality_t quality;

	/**
	 * RNG type
	 */
	const char* rng_name;
};

METHOD(rng_t, get_bytes, bool,
	private_botan_random_t *this, size_t bytes, uint8_t *buffer)
{
	botan_rng_t rng;
	if (botan_rng_init(&rng, this->rng_name))
	{
		return FALSE;
	}

	if (botan_rng_get(rng, buffer, bytes))
	{
		botan_rng_destroy(rng);
		return FALSE;
	}

	botan_rng_destroy(rng);
	return TRUE;
}

METHOD(rng_t, allocate_bytes, bool,
	private_botan_random_t *this, size_t bytes, chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	if (!get_bytes(this, chunk->len, chunk->ptr))
	{
		chunk_free(chunk);
		return FALSE;
	}
	return TRUE;
}

METHOD(rng_t, destroy, void,
	private_botan_random_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
botan_random_t *botan_rng_create(rng_quality_t quality)
{
	private_botan_random_t *this;
	const char* rng_name;

	switch (quality)
	{
		case RNG_WEAK:
		case RNG_STRONG:
			rng_name = "user";
			break;
		case RNG_TRUE:
			rng_name = "system";
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.rng = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.destroy = _destroy,
			},
		},
		.quality = quality,
		.rng_name = rng_name,
	);

	return &this->public;
}

#endif
