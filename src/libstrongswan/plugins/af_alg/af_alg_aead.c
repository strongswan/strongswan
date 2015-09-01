/*
 * Copyright (C) 2015 Tobias Brunner
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

#include "af_alg_aead.h"
#include "af_alg_ops.h"

#include <crypto/iv/iv_gen_seq.h>

typedef struct private_af_alg_aead_t private_af_alg_aead_t;

/**
 * Private data of af_alg_aead_t
 */
struct private_af_alg_aead_t {

	/**
	 * Public part of this class.
	 */
	af_alg_aead_t public;

	/**
	 * Instantiated algorithm
	 */
	encryption_algorithm_t algo;

	/**
	 * AF_ALG operations
	 */
	af_alg_ops_t *ops;

	/**
	 * IV generator
	 */
	iv_gen_t *iv_gen;

	/**
	 * Size of integrity check value
	 */
	size_t icv_size;

	/**
	 * Size of initialization vector
	 */
	size_t iv_size;

	/**
	 * Size of the key
	 */
	size_t key_size;

	/**
	 * Salt value (part of the keymat)
	 */
	chunk_t salt;
};

/**
 * Algorithm database
 */
static struct {
	encryption_algorithm_t id;
	char *name;
	size_t icv_size;
	size_t key_size;
	size_t iv_size;
	size_t salt_size;
} algs[AF_ALG_AEAD] = {
	{ENCR_AES_CCM_ICV8,			"ccm(aes)",						 8, 16,	8, 3},
	{ENCR_AES_CCM_ICV8,			"ccm(aes)",						 8, 24,	8, 3},
	{ENCR_AES_CCM_ICV8,			"ccm(aes)",						 8, 32,	8, 3},
	{ENCR_AES_CCM_ICV12,		"ccm(aes)",						12, 16,	8, 3},
	{ENCR_AES_CCM_ICV12,		"ccm(aes)",						12, 24,	8, 3},
	{ENCR_AES_CCM_ICV12,		"ccm(aes)",						12, 32,	8, 3},
	{ENCR_AES_CCM_ICV16,		"ccm(aes)",					 	16, 16,	8, 3},
	{ENCR_AES_CCM_ICV16,		"ccm(aes)",					 	16, 24,	8, 3},
	{ENCR_AES_CCM_ICV16,		"ccm(aes)",					 	16, 32,	8, 3},
	{ENCR_AES_GCM_ICV8,			"gcm(aes)",						 8, 16,	8, 4},
	{ENCR_AES_GCM_ICV8,			"gcm(aes)",						 8, 24,	8, 4},
	{ENCR_AES_GCM_ICV8,			"gcm(aes)",						 8, 32,	8, 4},
	{ENCR_AES_GCM_ICV12,		"gcm(aes)",						12, 16,	8, 4},
	{ENCR_AES_GCM_ICV12,		"gcm(aes)",						12, 24,	8, 4},
	{ENCR_AES_GCM_ICV12,		"gcm(aes)",						12, 32,	8, 4},
	{ENCR_AES_GCM_ICV16,		"gcm(aes)",						16, 16,	8, 4},
	{ENCR_AES_GCM_ICV16,		"gcm(aes)",						16, 24,	8, 4},
	{ENCR_AES_GCM_ICV16,		"gcm(aes)",						16, 32,	8, 4},
	{ENCR_CHACHA20_POLY1305,	"rfc7539(chacha20,poly1305)",	16, 32,	8, 4},
};

/**
 * See header.
 */
void af_alg_aead_probe(plugin_feature_t *features, int *pos)
{
	af_alg_ops_t *ops;
	int i;

	for (i = 0; i < countof(algs); i++)
	{
		ops = af_alg_ops_create("aead", algs[i].name);
		if (ops)
		{
			ops->destroy(ops);
			features[(*pos)++] = PLUGIN_PROVIDE(AEAD, algs[i].id,
												algs[i].key_size);
		}
	}
}

/**
 * Get the kernel algorithm string and different sizes for our identifier
 */
static size_t lookup_alg(encryption_algorithm_t algo, char **name,
						 size_t *key_size, size_t *salt_size, size_t *iv_size)
{
	int i;

	for (i = 0; i < countof(algs); i++)
	{
		if (algs[i].id == algo &&
			(*key_size == 0 || *key_size == algs[i].key_size) &&
			(*salt_size == 0 || *salt_size == algs[i].salt_size))
		{
			*name = algs[i].name;
			*key_size = algs[i].key_size;
			*salt_size = algs[i].salt_size;
			*iv_size = algs[i].iv_size;
			return algs[i].icv_size;
		}
	}
	return 0;
}

/**
 * Prepare the IV as required by the individual algorithms
 */
static chunk_t prepare_iv(private_af_alg_aead_t *this, chunk_t iv)
{
	switch (this->algo)
	{
		case ENCR_AES_CCM_ICV8:
		case ENCR_AES_CCM_ICV12:
		case ENCR_AES_CCM_ICV16:
			return chunk_cat("cccc", chunk_from_chars(0x03), this->salt, iv,
							 chunk_from_chars(0x00,0x00,0x00,0x00));
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
		case ENCR_CHACHA20_POLY1305:
			return chunk_cat("cc", this->salt, iv);
	}
}

METHOD(aead_t, encrypt, bool,
	private_af_alg_aead_t *this, chunk_t data, chunk_t assoc, chunk_t iv,
	chunk_t *dst)
{
	chunk_t out;
	bool success;

	out = data;
	if (dst)
	{
		out = *dst = chunk_alloc(data.len + this->icv_size);
		out.len -= this->icv_size;
	}
	iv = prepare_iv(this, iv);
	success = this->ops->crypt_aead(this->ops, ALG_OP_ENCRYPT, iv, data, assoc,
									this->icv_size, out);
	chunk_clear(&iv);
	return success;
}

METHOD(aead_t, decrypt, bool,
	private_af_alg_aead_t *this, chunk_t data, chunk_t assoc, chunk_t iv,
	chunk_t *dst)
{
	chunk_t out;
	bool success;

	if (data.len < this->icv_size)
	{
		return FALSE;
	}
	data.len -= this->icv_size;
	out = data;
	if (dst)
	{
		/* due to how the Linux AEAD API works we need space for the ICV,
		 * when decrypting in-place we already have that space allocated */
		out = chunk_alloc(data.len + this->icv_size);
		out.len -= this->icv_size;
		*dst = out;
	}
	iv = prepare_iv(this, iv);
	success =  this->ops->crypt_aead(this->ops, ALG_OP_DECRYPT, iv, data, assoc,
									 this->icv_size, out);
	chunk_clear(&iv);
	return success;
}

METHOD(aead_t, get_block_size, size_t,
	private_af_alg_aead_t *this)
{
	return 1;
}

METHOD(aead_t, get_icv_size, size_t,
	private_af_alg_aead_t *this)
{
	return this->icv_size;
}

METHOD(aead_t, get_iv_size, size_t,
	private_af_alg_aead_t *this)
{
	return this->iv_size;
}

METHOD(aead_t, get_key_size, size_t,
	private_af_alg_aead_t *this)
{
	return this->key_size + this->salt.len;
}

METHOD(aead_t, get_iv_gen, iv_gen_t*,
	private_af_alg_aead_t *this)
{
	return this->iv_gen;
}

METHOD(aead_t, set_key, bool,
	private_af_alg_aead_t *this, chunk_t key)
{
	if (key.len != get_key_size(this))
	{
		return FALSE;
	}
	key.len -= this->salt.len;
	this->salt = chunk_clone(chunk_create(key.ptr + key.len,
										  this->salt.len));
	return this->ops->set_key(this->ops, key);
}

METHOD(aead_t, destroy, void,
	private_af_alg_aead_t *this)
{
	this->iv_gen->destroy(this->iv_gen);
	this->ops->destroy(this->ops);
	chunk_clear(&this->salt);
	free(this);
}

/*
 * Described in header
 */
af_alg_aead_t *af_alg_aead_create(encryption_algorithm_t algo,
								  size_t key_size, size_t salt_size)
{
	private_af_alg_aead_t *this;
	size_t icv_size, iv_size;
	char *name;

	icv_size = lookup_alg(algo, &name, &key_size, &salt_size, &iv_size);
	if (!icv_size)
	{	/* not supported by kernel */
		return NULL;
	}

	INIT(this,
		.public = {
			.aead = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_icv_size = _get_icv_size,
				.get_iv_size = _get_iv_size,
				.get_iv_gen = _get_iv_gen,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.algo = algo,
		.ops = af_alg_ops_create("aead", name),
		/* use sequential IVs for all supported algorithms */
		.iv_gen = iv_gen_seq_create(),
		.icv_size = icv_size,
		.key_size = key_size,
		.iv_size = iv_size,
		.salt = {
			.len = salt_size,
		},
	);

	if (!this->ops || !this->ops->set_icv_length(this->ops, icv_size))
	{
		free(this);
		return NULL;
	}
	return &this->public;
}
