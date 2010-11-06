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

#include "af_alg_crypter.h"

#include <unistd.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_alg.h>

#include <debug.h>

#ifndef AF_ALG
#define AF_ALG		38
#endif /* AF_ALG */

#ifndef SOL_ALG
#define SOL_ALG 279
#endif /* SOL_ALG */

typedef struct private_af_alg_crypter_t private_af_alg_crypter_t;

/**
 * Private data of af_alg_crypter_t
 */
struct private_af_alg_crypter_t {

	/**
	 * Public part of this class.
	 */
	af_alg_crypter_t public;

	/**
	 * Transform fd
	 */
	int tfm;

	/**
	 * Size of the truncated signature
	 */
	size_t block_size;

	/**
	 * Size of the keymat
	 */
	size_t keymat_size;

	/**
	 * Size of initialization vector
	 */
	size_t iv_size;
};

/**
 * Get the kernel algorithm string and block/key size for our identifier
 */
static size_t lookup_alg(encryption_algorithm_t algo, char *name,
						 size_t key_size, size_t *keymat_size, size_t *iv_size)
{
	static struct {
		encryption_algorithm_t id;
		char *name;
		size_t block_size;
		/* key size of the algorithm */
		size_t key_size;
		/* size of the keying material (key + nonce for ctr mode) */
		size_t keymat_size;
		size_t iv_size;
	} algs[] = {
		{ENCR_DES,			"cbc(des)",					 8,	 8,	 8,	 8,	},
		{ENCR_3DES,			"cbc(des3_ede)",			 8,	24,	24,	 8,	},
		{ENCR_AES_CBC,		"cbc(aes)",					16,	16,	16,	16,	},
		{ENCR_AES_CBC,		"cbc(aes)",					16,	24,	24,	16,	},
		{ENCR_AES_CBC,		"cbc(aes)",					16,	32,	32,	16,	},
		{ENCR_AES_CTR,		"rfc3686(ctr(aes))",		 1,	16,	20,	 8,	},
		{ENCR_AES_CTR,		"rfc3686(ctr(aes))",		 1,	24,	28,	 8,	},
		{ENCR_AES_CTR,		"rfc3686(ctr(aes))",		 1,	32,	36,	 8,	},
		{ENCR_CAMELLIA_CBC,	"cbc(camellia)",			16,	16,	16,	16,	},
		{ENCR_CAMELLIA_CBC,	"cbc(camellia)",			16,	24,	24,	16,	},
		{ENCR_CAMELLIA_CBC,	"cbc(camellia)",			16,	32,	32,	16,	},
		{ENCR_CAMELLIA_CTR,	"rfc3686(ctr(camellia))",	 1,	16,	20,	 8,	},
		{ENCR_CAMELLIA_CTR,	"rfc3686(ctr(camellia))",	 1,	24,	28,	 8,	},
		{ENCR_CAMELLIA_CTR,	"rfc3686(ctr(camellia))",	 1,	32,	36,	 8,	},
	};
	int i;

	for (i = 0; i < countof(algs); i++)
	{
		if (algs[i].id == algo &&
			(key_size == 0 || algs[i].key_size == key_size))
		{
			strcpy(name, algs[i].name);
			*keymat_size = algs[i].keymat_size;
			*iv_size = algs[i].iv_size;
			return algs[i].block_size;
		}
	}
	return 0;
}

/**
 * Do the en-/decryption operation
 */
static void crypt(private_af_alg_crypter_t *this, u_int32_t type, chunk_t iv,
				  chunk_t in, char *out)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(type)) +
			 CMSG_SPACE(offsetof(struct af_alg_iv, iv) + iv.len)];
	ssize_t len;
	int op;

	while ((op = accept(this->tfm, NULL, 0)) == -1)
	{
		DBG1(DBG_LIB, "accepting AF_ALG crypter failed: %s", strerror(errno));
		sleep(1);
	}

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(type));
	*(u_int32_t*)CMSG_DATA(cmsg) = type;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + iv.len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = iv.len;
	memcpy(ivm->iv, iv.ptr, iv.len);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (in.len)
	{
		iov.iov_base = in.ptr;
		iov.iov_len = in.len;

		len = sendmsg(op, &msg, 0);
		if (len == -1)
		{
			DBG1(DBG_LIB, "writing to AF_ALG crypter failed: %s",
				 strerror(errno));
			sleep(1);
			continue;
		}
		if (read(op, out, len) != len)
		{
			DBG1(DBG_LIB, "reading from AF_ALG crypter failed: %s",
				 strerror(errno));
		}
		in = chunk_skip(in, len);
		/* no IV for subsequent data chunks */
		msg.msg_controllen = 0;
	}
	close(op);
}

METHOD(crypter_t, decrypt, void,
	private_af_alg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		crypt(this, ALG_OP_DECRYPT, iv, data, dst->ptr);
	}
	else
	{
		crypt(this, ALG_OP_DECRYPT, iv, data, data.ptr);
	}
}

METHOD(crypter_t, encrypt, void,
	private_af_alg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		crypt(this, ALG_OP_ENCRYPT, iv, data, dst->ptr);
	}
	else
	{
		crypt(this, ALG_OP_ENCRYPT, iv, data, data.ptr);
	}
}

METHOD(crypter_t, get_block_size, size_t,
	private_af_alg_crypter_t *this)
{
	return this->block_size;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_af_alg_crypter_t *this)
{
	return this->iv_size;
}

METHOD(crypter_t, get_key_size, size_t,
	private_af_alg_crypter_t *this)
{
	return this->keymat_size;
}

METHOD(crypter_t, set_key, void,
	private_af_alg_crypter_t *this, chunk_t key)
{
	if (setsockopt(this->tfm, SOL_ALG, ALG_SET_KEY, key.ptr, key.len) == -1)
	{
		DBG1(DBG_LIB, "setting AF_ALG key %B failed: %s", &key, strerror(errno));
	}
}

METHOD(crypter_t, destroy, void,
	private_af_alg_crypter_t *this)
{
	close(this->tfm);
	free(this);
}

/*
 * Described in header
 */
af_alg_crypter_t *af_alg_crypter_create(encryption_algorithm_t algo,
										size_t key_size)
{
	private_af_alg_crypter_t *this;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};
	size_t block_size, keymat_size, iv_size;

	block_size = lookup_alg(algo, sa.salg_name, key_size,
							&keymat_size, &iv_size);
	if (!block_size)
	{	/* not supported by kernel */
		return NULL;
	}

	INIT(this,
		.public = {
			.crypter = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.block_size = block_size,
		.keymat_size = keymat_size,
		.iv_size = iv_size,
		.tfm = socket(AF_ALG, SOCK_SEQPACKET, 0),
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
