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

#include "botan_rsa_private_key.h"

#include <botan/build.h>

#ifdef BOTAN_HAS_RSA

#include "botan_util.h"

#include <botan/ffi.h>

#include <utils/debug.h>

typedef struct private_botan_rsa_private_key_t private_botan_rsa_private_key_t;

/**
 * Private data of a botan_rsa_private_key_t object.
 */
struct private_botan_rsa_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	botan_rsa_private_key_t public;

	/**
	 * Botan private key
	 */
	botan_privkey_t key;


	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * Get the binary representation of a named RSA parameter
 */
static int botan_rsa_get_field(botan_privkey_t *key, const char *field_name,
							   chunk_t *value)
{
	botan_mp_t field;
	if (botan_mp_init(&field))
	{
		return -1;
	}

	if (botan_privkey_get_field(field, *key, field_name))
	{
		botan_mp_destroy(field);
		return -1;
	}

	size_t field_size = 0;
	if (botan_mp_num_bytes(field, &field_size))
	{
		botan_mp_destroy(field);
		return -1;
	}

	if (field_size == 0)
	{
		botan_mp_destroy(field);
		return -1;
	}

	*value = chunk_alloc(field_size);
	if (botan_mp_to_bin(field, value->ptr))
	{
		botan_mp_destroy(field);
		chunk_clear(value);
		return -1;
	}

	botan_mp_destroy(field);
	return 0;
}

/**
 * Build RSA signature
 */
static bool build_rsa_signature(private_botan_rsa_private_key_t *this,
		const char* hash_and_padding, chunk_t data, chunk_t* signature)
{
	botan_pk_op_sign_t sign_op;

	if (botan_pk_op_sign_create(&sign_op, this->key, hash_and_padding, 0))
	{
		return FALSE;
	}

	botan_rng_t rng;
	if (botan_rng_init(&rng, "user"))
	{
		botan_pk_op_sign_destroy(sign_op);
		return FALSE;
	}

	/* get size of signature first */
	if (botan_pk_op_sign_update(sign_op, data.ptr, data.len))
	{
		botan_rng_destroy(rng);
		botan_pk_op_sign_destroy(sign_op);
		return FALSE;
	}

	signature->len = 0;
	if (botan_pk_op_sign_finish(sign_op, rng, NULL, &signature->len)
	    != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
	{
		botan_rng_destroy(rng);
		botan_pk_op_sign_destroy(sign_op);
		return FALSE;
	}

	/* now get the signature */
	*signature = chunk_alloc(signature->len);
	if (botan_pk_op_sign_update(sign_op, data.ptr, data.len))
	{
		chunk_free(signature);
		botan_rng_destroy(rng);
		botan_pk_op_sign_destroy(sign_op);
		return FALSE;
	}

	if (botan_pk_op_sign_finish(sign_op, rng, signature->ptr, &signature->len))
	{
		chunk_free(signature);
		botan_rng_destroy(rng);
		botan_pk_op_sign_destroy(sign_op);
		return FALSE;
	}

	botan_rng_destroy(rng);
	botan_pk_op_sign_destroy(sign_op);
	return TRUE;
}

/**
 * Build an EMSA PKCS1 signature described in PKCS#1
 */
static bool build_emsa_pkcs1_signature(private_botan_rsa_private_key_t *this,
		const char* hash_and_padding, chunk_t data, chunk_t* signature)
{
	return build_rsa_signature(this, hash_and_padding, data, signature);
}

static bool botan_get_hash(hash_algorithm_t hash, char* hash_str)
{
	switch (hash)
	{
		case HASH_SHA1:
			sprintf(hash_str, "SHA-1");
			break;
		case HASH_SHA224:
			sprintf(hash_str, "SHA-224");
			break;
		case HASH_SHA256:
			sprintf(hash_str, "SHA-256");
			break;
		case HASH_SHA384:
			sprintf(hash_str, "SHA-384");
			break;
		case HASH_SHA512:
			sprintf(hash_str, "SHA-512");
			break;
		default:
			return FALSE;
	}

	return TRUE;
}

/**
 * Build an EMSA PSS signature described in PKCS#1
 */
static bool build_emsa_pss_signature(private_botan_rsa_private_key_t *this,
									 rsa_pss_params_t *params, chunk_t data,
									 chunk_t *sig)
{
	char* hash_and_padding, *hash, *mgf1_hash;
	char* salt_len = NULL;
	size_t len;
	bool success = FALSE;

	if (!params)
	{
		return FALSE;
	}

	/* botan currently does not support passing the mgf1 hash */
	if (params->hash != params->mgf1_hash)
	{
		DBG1(DBG_LIB, "passing mgf1 hash not supported via botan");
		return FALSE;
	}

	hash = malloc(8);
	if (!botan_get_hash(params->hash, hash))
	{
		free(hash);
		return FALSE;
	}

	mgf1_hash = malloc(8);
	if (!botan_get_hash(params->mgf1_hash, mgf1_hash))
	{
		free(hash);
		free(mgf1_hash);
		return FALSE;
	}

	if (params->salt_len > RSA_PSS_SALT_LEN_DEFAULT)
	{
		salt_len = malloc(6);
		snprintf(salt_len, 5, "%d", params->salt_len);
	}

	len = 24 + strlen(hash) + strlen(mgf1_hash);
	hash_and_padding = malloc(len+1);

	if (salt_len)
	{
		snprintf(hash_and_padding, len, "EMSA-PSS(%s,MGF1,%s)", hash, salt_len);
	}
	else
	{
		snprintf(hash_and_padding, len, "EMSA-PSS(%s,MGF1)", hash);
	}

	if (build_rsa_signature(this, hash_and_padding, data, sig))
	{
		success = TRUE;
	}

	if (salt_len)
		free(salt_len);
	free(hash);
	free(mgf1_hash);
	free(hash_and_padding);
	return success;
}

METHOD(private_key_t, get_type, key_type_t,
	private_botan_rsa_private_key_t *this)
{
	return KEY_RSA;
}

METHOD(private_key_t, sign, bool,
	private_botan_rsa_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(Raw)", data,
											  signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(SHA-1)", data,
											  signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_224:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(SHA-224)", data,
											  signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_256:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(SHA-256)", data,
											  signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_384:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(SHA-384)", data,
											  signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_512:
			return build_emsa_pkcs1_signature(this, "EMSA_PKCS1(SHA-512)", data,
											  signature);
		case SIGN_RSA_EMSA_PSS:
			return build_emsa_pss_signature(this, params, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported via botan",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool, private_botan_rsa_private_key_t *this,
	   encryption_scheme_t scheme, chunk_t crypto, chunk_t *plain)
{
	const char *padding;

	switch (scheme)
	{
		case ENCRYPT_RSA_PKCS1:
			padding = "PKCS1v15";
			break;
		case ENCRYPT_RSA_OAEP_SHA1:
			padding = "OAEP(SHA-1)";
			break;
		case ENCRYPT_RSA_OAEP_SHA224:
			padding = "OAEP(SHA-224)";
			break;
		case ENCRYPT_RSA_OAEP_SHA256:
			padding = "OAEP(SHA-256)";
			break;
		case ENCRYPT_RSA_OAEP_SHA384:
			padding = "OAEP(SHA-384)";
			break;
		case ENCRYPT_RSA_OAEP_SHA512:
			padding = "OAEP(SHA-512)";
			break;
		default:
			DBG1(DBG_LIB, "encryption scheme %N not supported via botan",
				 encryption_scheme_names, scheme);
			return FALSE;
	}

	botan_pk_op_decrypt_t decrypt_op;
	if (botan_pk_op_decrypt_create(&decrypt_op, this->key, padding, 0))
	{
		return FALSE;
	}

	/*
	 * get size of plaintext first
	 */
	if (botan_pk_op_decrypt(decrypt_op, NULL, &plain->len, crypto.ptr,
							crypto.len)
		!= BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
	{
		botan_pk_op_decrypt_destroy(decrypt_op);
		return FALSE;
	}

	/*
	 *  now get the plaintext
	 */
	*plain = chunk_alloc(plain->len);
	if (botan_pk_op_decrypt(decrypt_op, plain->ptr, &plain->len, crypto.ptr,
							crypto.len))
	{
		chunk_free(plain);
		botan_pk_op_decrypt_destroy(decrypt_op);
		return FALSE;
	}

	botan_pk_op_decrypt_destroy(decrypt_op);
	return TRUE;
}

METHOD(private_key_t, get_keysize, int,
	private_botan_rsa_private_key_t *this)
{
	botan_mp_t n;
	if (botan_mp_init(&n))
	{
		return -1;
	}

	if (botan_privkey_rsa_get_n(n, this->key))
	{
		return -1;
	}

	size_t bits = 0;
	if (botan_mp_num_bits(n, &bits))
	{
		botan_mp_destroy(n);
		return -1;
	}

	botan_mp_destroy(n);
	return bits;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_botan_rsa_private_key_t *this)
{
	chunk_t n, e;

	if (botan_rsa_get_field(&this->key, "n", &n))
	{
		return NULL;
	}

	if (botan_rsa_get_field(&this->key, "e", &e))
	{
		chunk_clear(&n);
		return NULL;
	}

	public_key_t *pub_key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY,
											   KEY_RSA, BUILD_RSA_MODULUS, n,
											   BUILD_RSA_PUB_EXP, e, BUILD_END);

	chunk_free(&n);
	chunk_free(&e);
	return pub_key;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_botan_rsa_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	chunk_t n, e;
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, &this->key, fingerprint))
	{
		return TRUE;
	}

	if (botan_rsa_get_field(&this->key, "n", &n))
	{
		return FALSE;
	}

	if (botan_rsa_get_field(&this->key, "e", &e))
	{
		chunk_clear(&n);
		return FALSE;
	}

	success = lib->encoding->encode(lib->encoding, type, &this->key,
									fingerprint, CRED_PART_RSA_MODULUS, n,
									CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
	chunk_free(&n);
	chunk_free(&e);
	return success;

}

METHOD(private_key_t, get_encoding, bool,
	private_botan_rsa_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			uint32_t format = BOTAN_PRIVKEY_EXPORT_FLAG_DER;
			if (type == PRIVKEY_PEM)
			{
				format = BOTAN_PRIVKEY_EXPORT_FLAG_PEM;
			}

			size_t bits = 0;
			if(botan_privkey_rsa_get_privkey(this->key, NULL, &bits, format))
			{
				return FALSE;
			}

			*encoding = chunk_alloc(bits);
			if(botan_privkey_rsa_get_privkey(this->key, encoding->ptr, &bits, format))
			{
				chunk_clear(encoding);
				return FALSE;
			}

			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_botan_rsa_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_botan_rsa_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (&this->key)
		{
			lib->encoding->clear_cache(lib->encoding, &this->key);
			botan_privkey_destroy(this->key);
		}
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_botan_rsa_private_key_t *create_empty()
{
	private_botan_rsa_private_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	return this;
}

/*
 * See header.
 */
botan_rsa_private_key_t *botan_rsa_private_key_gen(key_type_t type,
												   va_list args)
{
	private_botan_rsa_private_key_t *this;

	u_int key_size = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				key_size = va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!key_size)
	{
		return NULL;
	}

	botan_rng_t rng;
	if (botan_rng_init(&rng, "user"))
	{
		return NULL;
	}

	this = create_empty();

	if(botan_privkey_create_rsa(&this->key, rng, key_size))
	{
		botan_rng_destroy(rng);
		destroy(this);
		return NULL;
	}

	botan_rng_destroy(rng);
	return &this->public;
}

/**
 * Recover the primes from n, e and d using the algorithm described in
 * Appendix C of NIST SP 800-56B.
 */
static bool calculate_pq(botan_mp_t *n, botan_mp_t *e, botan_mp_t *d,
						 botan_mp_t *p, botan_mp_t *q)
{
	botan_mp_t k, one, r, zero, two, n1, x, y, g, rem;
	int i, t, j;
	bool success = TRUE;

	if (botan_mp_init(&k))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(&one))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_set_from_int(one, 1))
	{
		success = FALSE;
		goto error;
	}

	/* 1. k = de - 1 */
	if (botan_mp_mul(k, *d, *e) || botan_mp_sub(k, k, one))
	{
		success = FALSE;
		goto error;
	}

	/* k must be even */
	if (!botan_mp_is_even(k))
	{
		success = FALSE;
		goto error;
	}

	/* 2. k = 2^t * r, where r is the largest odd integer dividing k, and t >= 1 */
	if (botan_mp_init(&r))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_set_from_mp(r, k))
	{
		success = FALSE;
		goto error;
	}

	for (t = 0; !botan_mp_is_odd(r); t++)
	{
		if (botan_mp_rshift(r, r, 1))
		{
			success = FALSE;
			goto error;
		}
	}

	/* need 0, 2, n-1 below */
	if (botan_mp_init(&zero))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_set_from_int(zero, 0))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(&n1))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_sub(n1, *n, one))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(&g))
	{
		success = FALSE;
		goto error;
	}

	botan_rng_t rng;
	if (botan_rng_init(&rng, "user"))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(&two))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_set_from_int(two, 2))
	{
		success = FALSE;
		goto error;
	}

	for (i = 0; i < 100; i++)
	{
		/* 3a. generate a random integer g in the range [0, n-1] */
		if (botan_mp_rand_range(g, rng, zero, n1))
		{
			success = FALSE;
			goto error;
		}

		/* 3b. y = g^r mod n */
		if (botan_mp_init(&y))
		{
			success = FALSE;
			goto error;
		}

		if (botan_mp_powmod(y, g, r, *n))
		{
			success = FALSE;
			goto error;
		}

		/* 3c. If y = 1 or y = n – 1, try again */
		if (botan_mp_equal(y, one) || botan_mp_equal(y, n1))
		{
			continue;
		}

		if (botan_mp_init(&x))
		{
			success = FALSE;
			goto error;
		}

		for (j = 0; j < t; j++)
		{
			/* x = y^2 mod n */
			if (botan_mp_powmod(x, y, two, *n))
			{
				success = FALSE;
				goto error;
			}

			/* stop if x == 1 */
			if (botan_mp_equal(x, one))
			{
				goto done;
			}

			/* retry with new g if x = n-1 */
			if (botan_mp_equal(x, n1))
			{
				break;
			}

			/* let y = x */
			if(botan_mp_set_from_mp(y, x))
			{
				success = FALSE;
				goto error;
			}
		}
	}

done:
	/* 5. p = GCD(y – 1, n) and q = n/p */
	if (botan_mp_sub(y, y, one))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(p))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_gcd(*p, y, *n))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(q))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_init(&rem))
	{
		success = FALSE;
		goto error;
	}

	if (botan_mp_div(*q, rem, *n, *p))
	{
		success = FALSE;
		goto error;
	}

	if (!botan_mp_is_zero(rem))
	{
		success = FALSE;
		goto error;
	}

error:
	if (!success)
	{
		botan_mp_destroy(*p);
		botan_mp_destroy(*q);
	}

	botan_mp_destroy(k);
	botan_mp_destroy(one);
	botan_mp_destroy(r);
	botan_mp_destroy(zero);
	botan_mp_destroy(two);
	botan_mp_destroy(n1);
	botan_mp_destroy(x);
	botan_mp_destroy(y);
	botan_mp_destroy(rem);
	return success;
}

/*
 * See header
 */
botan_rsa_private_key_t *botan_rsa_private_key_load(key_type_t type,
													va_list args)
{
	private_botan_rsa_private_key_t *this;
	chunk_t n, e, d, p, q, blob;

	n = e = d = p = q = blob = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PRIV_EXP:
				d = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PRIME1:
				p = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PRIME2:
				q = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_EXP1:
			case BUILD_RSA_EXP2:
			case BUILD_RSA_COEFF:
				/* not required for botan */
				va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (blob.ptr)
	{
		this = create_empty();

		if (botan_privkey_load_rsa_pkcs1(&this->key, blob.ptr, blob.len))
		{
			destroy(this);
			return NULL;
		}

		return &this->public;
	}

	if (n.ptr && e.ptr && d.ptr)
	{
		botan_mp_t n_mp, e_mp, d_mp;
		if (chunk_to_botan_mp(n, &n_mp))
		{
			return NULL;
		}

		if (chunk_to_botan_mp(e, &e_mp))
		{
			botan_mp_destroy(n_mp);
			return NULL;
		}

		if (chunk_to_botan_mp(d, &d_mp))
		{
			botan_mp_destroy(n_mp);
			botan_mp_destroy(e_mp);
			return NULL;
		}

		botan_mp_t p_mp, q_mp;
		if (p.ptr && q.ptr)
		{
			if (chunk_to_botan_mp(p, &p_mp))
			{
				botan_mp_destroy(n_mp);
				botan_mp_destroy(e_mp);
				botan_mp_destroy(d_mp);
				return NULL;
			}

			if (chunk_to_botan_mp(q, &q_mp))
			{
				botan_mp_destroy(n_mp);
				botan_mp_destroy(e_mp);
				botan_mp_destroy(d_mp);
				botan_mp_destroy(p_mp);
				return NULL;
			}
		}
		else
		{
			// calculate p,q from n, e, d
			if (!calculate_pq(&n_mp, &e_mp, &d_mp, &p_mp, &q_mp))
			{
				botan_mp_destroy(n_mp);
				botan_mp_destroy(e_mp);
				botan_mp_destroy(d_mp);
				return NULL;
			}
		}

		this = create_empty();

		if (botan_privkey_load_rsa(&this->key, p_mp, q_mp, e_mp))
		{
			botan_mp_destroy(e_mp);
			botan_mp_destroy(p_mp);
			botan_mp_destroy(q_mp);
			destroy(this);
			return NULL;
		}

		botan_mp_destroy(e_mp);
		botan_mp_destroy(p_mp);
		botan_mp_destroy(q_mp);

		return &this->public;
	}

	return NULL;
}

#endif
