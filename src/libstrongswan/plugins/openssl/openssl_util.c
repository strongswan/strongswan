/*
 * Copyright (C) 2008 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include "openssl_util.h"

#include <debug.h>

#include <openssl/evp.h>

/**
 * Described in header.
 */
bool openssl_hash_chunk(int hash_type, chunk_t data, chunk_t *hash)
{
	EVP_MD_CTX *ctx;
	bool ret = FALSE;
	const EVP_MD *hasher = EVP_get_digestbynid(hash_type);
	if (!hasher)
	{
		return FALSE;
	}
	
	ctx = EVP_MD_CTX_create();	
	if (!ctx)
	{
		goto error;
	}
	
	if (!EVP_DigestInit_ex(ctx, hasher, NULL))
	{
		goto error;
	}
	
	if (!EVP_DigestUpdate(ctx, data.ptr, data.len))
	{
		goto error;
	}
	
	*hash = chunk_alloc(hasher->md_size);
	if (!EVP_DigestFinal_ex(ctx, hash->ptr, NULL))
	{
		chunk_free(hash);
		goto error;
	}
	
	ret = TRUE;
error:
	if (ctx)
	{
		EVP_MD_CTX_destroy(ctx);
	}
	return ret;
}

/**
 * Described in header.
 */
bool openssl_bn_cat(int len, BIGNUM *a, BIGNUM *b, chunk_t *chunk)
{
	int offset;
	
	chunk->len = len * 2;
	chunk->ptr = malloc(chunk->len);
	memset(chunk->ptr, 0, chunk->len);
	
	offset = len - BN_num_bytes(a);
	if (!BN_bn2bin(a, chunk->ptr + offset))
	{
		goto error;
	}
	
	offset = len - BN_num_bytes(b);
	if (!BN_bn2bin(b, chunk->ptr + len + offset))
	{
		goto error;
	}
	
	return TRUE;
error:
	chunk_free(chunk);
	return FALSE;
}


/**
 * Described in header.
 */
bool openssl_bn_split(chunk_t chunk, BIGNUM *a, BIGNUM *b)
{
	int len;
	
	if ((chunk.len % 2) != 0)
	{
		return FALSE;
	}
	
	len = chunk.len / 2;
	
	if (!BN_bin2bn(chunk.ptr, len, a) ||
		!BN_bin2bn(chunk.ptr + len, len, b))
	{
		return FALSE;
	}
	
	return TRUE;
}
