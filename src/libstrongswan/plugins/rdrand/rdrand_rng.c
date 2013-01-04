/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "rdrand_rng.h"

typedef struct private_rdrand_rng_t private_rdrand_rng_t;

/**
 * Private data of an rdrand_rng_t object.
 */
struct private_rdrand_rng_t {

	/**
	 * Public rdrand_rng_t interface.
	 */
	rdrand_rng_t public;

	/**
	 * Quality we produce RNG data
	 */
	rng_quality_t quality;
};

/**
 * Retries for failed RDRAND instructions
 */
#define MAX_TRIES 16

/**
 * After how many bytes should we reseed for RNG_STRONG
 * (must be a power of two >= 8)
 */
#define FORCE_RESEED 16

/**
 * Get a two byte word using RDRAND
 */
static bool rdrand16(u_int16_t *out)
{
	u_char res;
	int i;

	for (i = 0; i < MAX_TRIES; i++)
	{
		asm("rdrand %0;"
			"setc %1;"
			: "=r"(*out), "=qm"(res));

		if (res)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Get a four byte word using RDRAND
 */
static bool rdrand32(u_int32_t *out)
{
	u_char res;
	int i;

	for (i = 0; i < MAX_TRIES; i++)
	{
		asm("rdrand %0;"
			"setc %1;"
			: "=r"(*out), "=qm"(res));

		if (res)
		{
			return TRUE;
		}
	}
	return FALSE;
}

#ifdef __x86_64__
/**
 * Get a eight byte word using RDRAND
 */
static bool rdrand64(u_int64_t *out)
{
	u_char res;
	int i;

	for (i = 0; i < MAX_TRIES; i++)
	{
		asm("rdrand %0;"
			"setc %1;"
			: "=r"(*out), "=qm"(res));

		if (res)
		{
			return TRUE;
		}
	}
	return FALSE;
}
#endif /* __x86_64__ */

/**
 * Get a one byte word using RDRAND
 */
static bool rdrand8(u_int8_t *out)
{
	u_int16_t u16;

	if (!rdrand16(&u16))
	{
		return FALSE;
	}
	*out = u16;
	return TRUE;
}

/**
 * Enforce a DRNG reseed by reading 511 128-bit samples
 */
static bool reseed()
{
	int i;

#ifdef __x86_64__
	u_int64_t tmp;

	for (i = 0; i < 511 * 16 / sizeof(u_int64_t); i++)
	{
		if (!rdrand64(&tmp))
		{
			return FALSE;
		}
	}
#else /* __i386__ */
	u_int32_t tmp;

	for (i = 0; i < 511 * 16 / sizeof(u_int32_t); i++)
	{
		if (!rdrand32(&tmp))
		{
			return FALSE;
		}
	}
#endif /* __x86_64__ / __i386__ */
	return TRUE;
}

METHOD(rng_t, get_bytes, bool,
	private_rdrand_rng_t *this, size_t bytes, u_int8_t *buffer)
{
	chunk_t chunk;

	chunk = chunk_create(buffer, bytes);

	if (this->quality == RNG_STRONG)
	{
		if (!reseed())
		{
			return FALSE;
		}
	}

	/* align to 2 byte */
	if (chunk.len >= sizeof(u_int8_t))
	{
		if ((uintptr_t)chunk.ptr % 2)
		{
			if (!rdrand8((u_int8_t*)chunk.ptr))
			{
				return FALSE;
			}
			chunk = chunk_skip(chunk, sizeof(u_int8_t));
		}
	}

	/* align to 4 byte */
	if (chunk.len >= sizeof(u_int16_t))
	{
		if ((uintptr_t)chunk.ptr % 4)
		{
			if (!rdrand16((u_int16_t*)chunk.ptr))
			{
				return FALSE;
			}
			chunk = chunk_skip(chunk, sizeof(u_int16_t));
		}
	}

#ifdef __x86_64__

	/* align to 8 byte */
	if (chunk.len >= sizeof(u_int32_t))
	{
		if ((uintptr_t)chunk.ptr % 8)
		{
			if (!rdrand32((u_int32_t*)chunk.ptr))
			{
				return FALSE;
			}
			chunk = chunk_skip(chunk, sizeof(u_int32_t));
		}
	}

	/* fill with 8 byte words */
	while (chunk.len >= sizeof(u_int64_t))
	{
		if (this->quality == RNG_STRONG && chunk.len % FORCE_RESEED)
		{
			if (!reseed())
			{
				return FALSE;
			}
		}
		if (!rdrand64((u_int64_t*)chunk.ptr))
		{
			return FALSE;
		}
		chunk = chunk_skip(chunk, sizeof(u_int64_t));
	}

	/* append 4 byte word */
	if (chunk.len >= sizeof(u_int32_t))
	{
		if (!rdrand32((u_int32_t*)chunk.ptr))
		{
			return FALSE;
		}
		chunk = chunk_skip(chunk, sizeof(u_int32_t));
	}

#else /* __i386__ */

	/* fill with 4 byte words */
	while (chunk.len >= sizeof(u_int32_t))
	{
		if (this->quality == RNG_STRONG && chunk.len % FORCE_RESEED)
		{
			if (!reseed())
			{
				return FALSE;
			}
		}
		if (!rdrand32((u_int32_t*)chunk.ptr))
		{
			return FALSE;
		}
		chunk = chunk_skip(chunk, sizeof(u_int32_t));
	}

#endif /* __x86_64__ / __i386__ */

	if (this->quality == RNG_STRONG)
	{
		if (!reseed())
		{
			return FALSE;
		}
	}

	/* append 2 byte word */
	if (chunk.len >= sizeof(u_int16_t))
	{
		if (!rdrand16((u_int16_t*)chunk.ptr))
		{
			return FALSE;
		}
		chunk = chunk_skip(chunk, sizeof(u_int16_t));
	}

	/* append 1 byte word */
	if (chunk.len >= sizeof(u_int8_t))
	{
		if (!rdrand8((u_int8_t*)chunk.ptr))
		{
			return FALSE;
		}
		chunk = chunk_skip(chunk, sizeof(u_int8_t));
	}

	return TRUE;
}

METHOD(rng_t, allocate_bytes, bool,
	private_rdrand_rng_t *this, size_t bytes, chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	if (get_bytes(this, bytes, chunk->ptr))
	{
		return TRUE;
	}
	free(chunk->ptr);
	return FALSE;
}

METHOD(rng_t, destroy, void,
	private_rdrand_rng_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
rdrand_rng_t *rdrand_rng_create(rng_quality_t quality)
{
	private_rdrand_rng_t *this;

	switch (quality)
	{
		case RNG_WEAK:
		case RNG_STRONG:
			break;
		case RNG_TRUE:
		default:
			/* not yet */
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
	);

	return &this->public;
}
