/*
 * Copyright (C) 2012 Aleksandr Grinberg
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

#include <library.h>
#include <utils/debug.h>

#include <gmalg.h>

#include "gmalg_rng.h"

typedef struct private_gmalg_rng_t private_gmalg_rng_t;

/**
 * Private data of gmalg_rng_t
 */
struct private_gmalg_rng_t {

	/**
	 * Public part of this class.
	 */
	gmalg_rng_t public;

	/**
	 * Quality of randomness
	 */
	rng_quality_t quality;

	/*
	 * the cipher ddevice handle
	 */
	void *hDeviceHandle;
};

METHOD(rng_t, get_bytes, bool,
	private_gmalg_rng_t *this, size_t bytes, uint8_t *buffer)
{
	bool rc = 1;

	GMALG_GenerateRandom(this->hDeviceHandle, bytes, buffer);
	return rc;
}

METHOD(rng_t, allocate_bytes, bool,
	private_gmalg_rng_t *this, size_t bytes, chunk_t *chunk)
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
	private_gmalg_rng_t *this)
{
	GMALG_CloseDevice(this->hDeviceHandle);
	free(this);
}

/*
 * Described in header.
 */
gmalg_rng_t *gmalg_rng_create(rng_quality_t quality)
{
	private_gmalg_rng_t *this;

	INIT(this,
		.public = {
			.rng = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.destroy = _destroy,
			},
		},
		.quality = quality,
	);

	GMALG_OpenDevice(&this->hDeviceHandle);

	return &this->public;
}
