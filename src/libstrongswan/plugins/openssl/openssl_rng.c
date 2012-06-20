/*
 * Copyright (C) 2012 Aleksandr Grinberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <debug.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "openssl_rng.h"
#include "openssl_plugin.h"

typedef struct private_openssl_rng_t private_openssl_rng_t;

/**
 * Private data of openssl_rng_t
 */
struct private_openssl_rng_t {

	/**
	 * Public part of this class.
	 */
	openssl_rng_t public;

	/**
	 * Quality of randomness
	 */
	rng_quality_t quality;
};

METHOD(rng_t, get_bytes, void, private_openssl_rng_t *this, size_t bytes, u_int8_t *buffer)
{
	u_int32_t ret=0;

	if (this->quality == RNG_STRONG)
	{
		ret = RAND_bytes( (char*)buffer, bytes);
	}
	else
	{
		ret = RAND_pseudo_bytes( (char*)buffer, bytes);
	}
	
	if (ret == 0)
	{
		DBG1(DBG_LIB, "getting randomness from openssl failed.");
	}
}

METHOD(rng_t, allocate_bytes, void, private_openssl_rng_t *this, size_t bytes, chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	get_bytes(this, chunk->len, chunk->ptr);
}

METHOD(rng_t, destroy, void, private_openssl_rng_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
openssl_rng_t *openssl_rng_create(rng_quality_t quality)
{
	private_openssl_rng_t *this;

	INIT(this,
		.public = {
			.rng = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.destroy = _destroy,
			},
		},
	);

	this->quality = quality;
	
	return &this->public;
}
