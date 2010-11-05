/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "af_alg_hasher.h"

#include <unistd.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_alg.h>

#include <debug.h>

#ifndef AF_ALG
#define AF_ALG		38
#endif /* AF_ALG */

typedef struct private_af_alg_hasher_t private_af_alg_hasher_t;

/**
 * Private data of af_alg_hasher_t
 */
struct private_af_alg_hasher_t {

	/**
	 * Public part of this class.
	 */
	af_alg_hasher_t public;

	/**
	 * Transform fd
	 */
	int tfm;

	/**
	 * Current operation fd, -1 if none
	 */
	int op;

	/**
	 * Size of the hash
	 */
	size_t size;
};

/**
 * Get the kernel algorithm string and hash size for our identifier
 */
static size_t lookup_alg(hash_algorithm_t algo, char *name)
{
	static struct {
		hash_algorithm_t id;
		char *name;
		size_t size;
	} algs[] = {
		{HASH_MD4 ,			"md4",			HASH_SIZE_MD4 		},
		{HASH_MD5 ,			"md5",			HASH_SIZE_MD5 		},
		{HASH_SHA1,			"sha1",			HASH_SIZE_SHA1		},
		{HASH_SHA224,		"sha224",		HASH_SIZE_SHA224	},
		{HASH_SHA256,		"sha256",		HASH_SIZE_SHA256	},
		{HASH_SHA384,		"sha384",		HASH_SIZE_SHA384	},
		{HASH_SHA512,		"sha512",		HASH_SIZE_SHA512	},
	};
	int i;

	for (i = 0; i < countof(algs); i++)
	{
		if (algs[i].id == algo)
		{
			strcpy(name, algs[i].name);
			return algs[i].size;
		}
	}
	return 0;
}

METHOD(hasher_t, get_hash_size, size_t,
	private_af_alg_hasher_t *this)
{
	return this->size;
}

METHOD(hasher_t, reset, void,
	private_af_alg_hasher_t *this)
{
	if (this->op != -1)
	{
		close(this->op);
		this->op = -1;
	}
}

METHOD(hasher_t, get_hash, void,
	private_af_alg_hasher_t *this, chunk_t chunk, u_int8_t *hash)
{
	ssize_t len;

	while (this->op == -1)
	{
		this->op = accept(this->tfm, NULL, 0);
		if (this->op == -1)
		{
			DBG1(DBG_LIB, "opening AF_ALG hasher failed: %s", strerror(errno));
			sleep(1);
		}
	}
	do
	{
		len = send(this->op, chunk.ptr, chunk.len, hash ? 0 : MSG_MORE);
		if (len == -1)
		{
			DBG1(DBG_LIB, "writing to AF_ALG hasher failed: %s", strerror(errno));
			sleep(1);
		}
		else
		{
			chunk = chunk_skip(chunk, len);
		}
	}
	while (chunk.len);
	if (hash)
	{
		while (read(this->op, hash, this->size) != this->size)
		{
			DBG1(DBG_LIB, "reading AF_ALG hasher failed: %s", strerror(errno));
			sleep(1);
		}
		reset(this);
	}
}

METHOD(hasher_t, allocate_hash, void,
	private_af_alg_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(get_hash_size(this));
		get_hash(this, chunk, hash->ptr);
	}
	else
	{
		get_hash(this, chunk, NULL);
	}
}

METHOD(hasher_t, destroy, void,
	private_af_alg_hasher_t *this)
{
	if (this->op != -1)
	{
		close(this->op);
	}
	close(this->tfm);
	free(this);
}

/*
 * Described in header
 */
af_alg_hasher_t *af_alg_hasher_create(hash_algorithm_t algo)
{
	private_af_alg_hasher_t *this;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};
	size_t size;

	size = lookup_alg(algo, sa.salg_name);
	if (!size)
	{	/* not supported by kernel */
		return NULL;
	}

	INIT(this,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
		.tfm = socket(AF_ALG, SOCK_SEQPACKET, 0),
		.op = -1,
		.size = size,
	);

	if (this->tfm == -1)
	{
		DBG1(DBG_LIB, "opening AF_ALG socket failed: %s", strerror(errno));
		free(this);
		return NULL;
	}
	if (bind(this->tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		DBG1(DBG_LIB, "binding AF_ALG socket for '%s' failed: %s",
			 sa.salg_name, strerror(errno));
		destroy(this);
		return NULL;
	}
	return &this->public;
}
