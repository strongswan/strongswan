/*
 * Copyright (C) 2020 Tobias Brunner
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

#include <openssl/evp.h>

/* SHA3 was added with 1.1.1 */
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_SHAKE)

#include "openssl_xof.h"

#define KECCAK_STATE_SIZE 200 /* 1600 bits*/

typedef struct private_xof_t private_xof_t;

/**
 * Private data
 */
struct private_xof_t {

	/**
	 * Public interface.
	 */
	xof_t public;

	/**
	 * XOF algorithm to be used
	 */
	ext_out_function_t algorithm;

	/**
	 * Internal type reference
	 */
	const EVP_MD *md;

	/**
	 * Internal context
	 */
	EVP_MD_CTX *ctx;
};

METHOD(xof_t, get_type, ext_out_function_t,
	private_xof_t *this)
{
	return this->algorithm;
}

METHOD(xof_t, get_bytes, bool,
	private_xof_t *this, size_t out_len, uint8_t *buffer)
{
	return EVP_DigestFinalXOF(this->ctx, buffer, out_len) == 1;
}

METHOD(xof_t, allocate_bytes, bool,
	private_xof_t *this, size_t out_len, chunk_t *chunk)
{
	*chunk = chunk_alloc(out_len);
	return EVP_DigestFinalXOF(this->ctx, chunk->ptr, out_len) == 1;
}

METHOD(xof_t, get_block_size, size_t,
	private_xof_t *this)
{
	return EVP_MD_block_size(this->md);
}

METHOD(xof_t, get_seed_size, size_t,
	private_xof_t *this)
{
	return KECCAK_STATE_SIZE - EVP_MD_block_size(this->md);
}

METHOD(xof_t, set_seed, bool,
	private_xof_t *this, chunk_t seed)
{
	return EVP_DigestInit_ex(this->ctx, this->md, NULL) == 1 &&
		   EVP_DigestUpdate(this->ctx, seed.ptr, seed.len) == 1;
}

METHOD(xof_t, destroy, void,
	private_xof_t *this)
{
	EVP_MD_CTX_free(this->ctx);
	free(this);
}

/*
 * Described in header
 */
xof_t *openssl_xof_create(ext_out_function_t algorithm)
{
	private_xof_t *this;
	const EVP_MD *md;

	switch (algorithm)
	{
		case XOF_SHAKE_128:
			md = EVP_shake128();
			break;
		case XOF_SHAKE_256:
			md = EVP_shake256();
			break;
		default:
			return NULL;
	}

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
		.md = md,
		.ctx = EVP_MD_CTX_new(),
	);
	return &this->public;
}

#endif /* OPENSSL_NO_ECDH */
