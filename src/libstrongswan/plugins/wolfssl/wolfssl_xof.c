/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2021 Andreas Steffen, strongSec GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

#include "wolfssl_common.h"

#include <wolfssl/version.h>

/* the Absorb and SqueezeBlocks functions were added with 5.5.1 */
#if (defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)) && \
	LIBWOLFSSL_VERSION_HEX >= 0x05005001

#include <wolfssl/wolfcrypt/sha3.h>

#include "wolfssl_xof.h"

#define KECCAK_STATE_SIZE 200   /* 1600 bits */

typedef struct private_xof_t private_xof_t;

/**
 * Helper struct to avoid switch statements all over the place
 */
typedef struct {
	int (*init)(wc_Shake*, void*, int);
	int (*absorb)(wc_Shake*, const byte*, word32);
	int (*squeeze)(wc_Shake*, byte*, word32);
	void (*free)(wc_Shake*);
	size_t block_size;
} shake_impl_t;

#ifdef WOLFSSL_SHAKE128
static const shake_impl_t shake128 = {
	.init		= wc_InitShake128,
	.absorb		= wc_Shake128_Absorb,
	.squeeze	= wc_Shake128_SqueezeBlocks,
	.free		= wc_Shake128_Free,
	.block_size	= WC_SHA3_128_BLOCK_SIZE,
};
#endif

#ifdef WOLFSSL_SHAKE256
static const shake_impl_t shake256 = {
	.init		= wc_InitShake256,
	.absorb		= wc_Shake256_Absorb,
	.squeeze	= wc_Shake256_SqueezeBlocks,
	.free		= wc_Shake256_Free,
	.block_size	= WC_SHA3_256_BLOCK_SIZE,
};
#endif

/**
 * Private data
 */
struct private_xof_t {

	/**
	 * Public interface.
	 */
	xof_t public;

	/**
	 * XOF algorithm
	 */
	ext_out_function_t algorithm;

	/**
	 * Implementation based on the type
	 */
	const shake_impl_t *impl;

	/**
	 * Internal context
	 */
	wc_Shake shake;

	/**
	 * Bytes available in the cached block
	 */
	size_t available;

	/**
	 * Cached squeezed block partially handed out already
	 */
	uint8_t cache[KECCAK_STATE_SIZE];
};

METHOD(xof_t, get_type, ext_out_function_t,
	private_xof_t *this)
{
	return this->algorithm;
}

METHOD(xof_t, get_bytes, bool,
	private_xof_t *this, size_t out_len, uint8_t *buffer)
{
	size_t index = 0, len, blocks;

	/* copy data from the cached block first if any */
	len = min(out_len, this->available);
	if (len)
	{
		memcpy(buffer, this->cache + this->impl->block_size - this->available,
			   len);
		index += len;
		this->available -= len;
	}

	/* squeeze complete blocks directly to the output buffer first */
	blocks = (out_len - index) / this->impl->block_size;
	if (blocks)
	{
		if (this->impl->squeeze(&this->shake, buffer + index, blocks) != 0)
		{
			return FALSE;
		}
		index += blocks * this->impl->block_size;
	}

	/* squeeze another block if we need some more output bytes */
	len = out_len - index;
	if (len)
	{
		if (this->impl->squeeze(&this->shake, this->cache, 1) != 0)
		{
			return FALSE;
		}
		memcpy(buffer + index, this->cache, len);
		this->available = this->impl->block_size - len;
	}
	return TRUE;
}

METHOD(xof_t, allocate_bytes, bool,
	private_xof_t *this, size_t out_len, chunk_t *chunk)
{
	*chunk = chunk_alloc(out_len);
	if (!get_bytes(this, out_len, chunk->ptr))
	{
		chunk_free(chunk);
		return FALSE;
	}
	return TRUE;
}

METHOD(xof_t, get_block_size, size_t,
	private_xof_t *this)
{
	return this->impl->block_size;
}

METHOD(xof_t, get_seed_size, size_t,
	private_xof_t *this)
{
	return KECCAK_STATE_SIZE - this->impl->block_size;
}

METHOD(xof_t, set_seed, bool,
	private_xof_t *this, chunk_t seed)
{
	this->available = 0;

	if (this->impl->init(&this->shake, NULL, INVALID_DEVID) != 0 ||
		this->impl->absorb(&this->shake, seed.ptr, seed.len) != 0)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(xof_t, destroy, void,
	private_xof_t *this)
{
	this->impl->free(&this->shake);
	memwipe(this->cache, sizeof(this->cache));
	free(this);
}

/*
 * Described in header
 */
xof_t *wolfssl_xof_create(ext_out_function_t algorithm)
{
	private_xof_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.get_bytes = _get_bytes,
			.allocate_bytes = _allocate_bytes,
			.get_block_size = _get_block_size,
			.get_seed_size = _get_seed_size,
			.set_seed = _set_seed,
			.destroy = _destroy,
		},
		.algorithm = algorithm,
	);

	switch (algorithm)
	{
#ifdef WOLFSSL_SHAKE128
		case XOF_SHAKE_128:
			this->impl = &shake128;
			break;
#endif
#ifdef WOLFSSL_SHAKE256
		case XOF_SHAKE_256:
			this->impl = &shake256;
			break;
#endif
		default:
			free(this);
			return NULL;
	}
	if (this->impl->init(&this->shake, NULL, INVALID_DEVID) != 0)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

#endif /* (WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256) && LIBWOLFSSL_VERSION_HEX */
