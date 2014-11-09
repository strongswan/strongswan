/*
 * Copyright (C) 2014 Andreas Steffen
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

#include "bliss_private_key.h"
#include "bliss_param_set.h"
#include "bliss_fft.h"

#include <crypto/mgf1/mgf1_bitspender.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>

#define _GNU_SOURCE
#include <stdlib.h>

typedef struct private_bliss_private_key_t private_bliss_private_key_t;

#define SECRET_KEY_TRIALS_MAX	30

/**
 * Functions shared with bliss_public_key class
 */
extern uint32_t* bliss_public_key_from_asn1(chunk_t object, int n);

extern chunk_t bliss_public_key_encode(uint32_t *pubkey, int n);

extern chunk_t bliss_public_key_info_encode(int oid, uint32_t *pubkey, int n);

extern bool bliss_public_key_fingerprint(int oid, uint32_t *pubkey, int n,
										 cred_encoding_type_t type, chunk_t *fp);

/**
 * Private data of a bliss_private_key_t object.
 */
struct private_bliss_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	bliss_private_key_t public;

	/**
	 * BLISS signature parameter set
	 */
	bliss_param_set_t *set;

	/**
	 * BLISS secret key S1 (coefficients of polynomial f)
	 */
	int8_t *s1;

	/**
	 * BLISS secret key S2 (coefficients of polynomial 2g + 1)
	 */
	int8_t *s2;

	/**
	 * BLISS public key a (coefficients of polynomial (2g + 1)/f)
	 */
	uint32_t *a;

	/**
	 * reference count
	 */
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_bliss_private_key_t *this)
{
	return KEY_BLISS;
}

METHOD(private_key_t, sign, bool,
	private_bliss_private_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_BLISS_WITH_SHA512:
			DBG2(DBG_LIB, "empty signature");
			*signature = chunk_empty;
			return TRUE;
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported with BLISS",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_bliss_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_bliss_private_key_t *this)
{
	return this->set->strength;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_bliss_private_key_t *this)
{
	public_key_t *public;
	chunk_t pubkey;

	pubkey = bliss_public_key_info_encode(this->set->oid, this->a,
										  this->set->n);
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_BLISS,
								BUILD_BLOB_ASN1_DER, pubkey, BUILD_END);
	free(pubkey.ptr);

	return public;
}

METHOD(private_key_t, get_encoding, bool,
	private_bliss_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			chunk_t s1_chunk, s2_chunk, pubkey;
			bool success = TRUE;

			pubkey = bliss_public_key_encode(this->a, this->set->n);

			/* Build private key as two polynomials with 8 bit coefficients */
			s1_chunk = chunk_create(this->s1, this->set->n);
			s2_chunk = chunk_create(this->s2, this->set->n);

			*encoding = asn1_wrap(ASN1_SEQUENCE, "mmss",
							asn1_build_known_oid(this->set->oid),
							pubkey,
							asn1_simple_object(ASN1_OCTET_STRING, s1_chunk),
							asn1_simple_object(ASN1_OCTET_STRING, s2_chunk)
						);

			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_BLISS_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_fingerprint, bool,
	private_bliss_private_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = bliss_public_key_fingerprint(this->set->oid, this->a,
										   this->set->n, type, fp);
	lib->encoding->cache(lib->encoding, type, this, *fp);

	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_bliss_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_bliss_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		free(this->s1);
		free(this->s2);
		free(this->a);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_bliss_private_key_t *bliss_private_key_create_empty(void)
{
	private_bliss_private_key_t *this;

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

/**
 * Compute the scalar product of a vector x with a negative wrapped vector y
 */
static int16_t wrapped_product(int8_t *x, int8_t *y, int n, int shift)
{
	int16_t product = 0;
	int i;

	for (i = 0; i < n - shift; i++)
	{
		product += x[i] * y[i + shift];
	}
	for (i = n - shift; i < n; i++)
	{
		product -= x[i] * y[i + shift - n];
	}
	return product;
}

/**
 * Apply a negative wrapped rotation to a vector x
 */
static void wrap(int16_t *x, int n, int shift, int16_t *x_wrapped)
{
	int i;

	for (i = 0; i < n - shift; i++)
	{
		x_wrapped[i + shift] = x[i];
	}
	for (i = n - shift; i < n; i++)
	{
		x_wrapped[i + shift - n] = -x[i];
	}
}

/**
 * int16_t compare function needed for qsort()
 */
static int compare(const int16_t *a, const int16_t *b)
{
	int16_t temp = *a - *b;

	if (temp > 0)
	{
		return 1;
	}
	else if (temp < 0)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

/**
 * Compute the Nk(S) norm of S = (s1, s2)
 */
static uint32_t nks_norm(int8_t *s1, int8_t *s2, int n, uint16_t kappa)
{
	int16_t t[n], t_wrapped[n], max_kappa[n];
	uint32_t nks = 0;
	int i, j;

	for (i = 0; i < n; i++)
	{
		t[i] = wrapped_product(s1, s1, n, i) + wrapped_product(s2, s2, n, i);
	}

	for (i = 0; i < n; i++)
	{
		wrap(t, n, i, t_wrapped);
		qsort(t_wrapped, n, sizeof(int16_t), (__compar_fn_t)compare);
		max_kappa[i] = 0;

		for (j = 1; j <= kappa; j++)
		{
			max_kappa[i] += t_wrapped[n - j];
		}
	}
	qsort(max_kappa, n, sizeof(int16_t), (__compar_fn_t)compare);

	for (i = 1; i <= kappa; i++)
	{
		nks += max_kappa[n - i];
	}
	return nks;
}

/**
 * Compute the inverse x1 of x modulo q as x^(-1) = x^(q-2) mod q
 */
static uint32_t invert(uint32_t x, uint16_t q)
{
	uint32_t x1, x2;
	uint16_t q2;
	int i, i_max;

	q2 = q - 2;
	x1 = (q2 & 1) ? x : 1;
	x2 = x;
	i_max = 15;

	while ((q2 & (1 << i_max)) == 0)
	{
		i_max--;
	}
	for (i = 1; i <= i_max; i++)
	{
		x2 = (x2 * x2) % q;

		if (q2 & (1 << i))
		{
			x1 = (x1 * x2) % q;
		}
	}

	return x1;
}

/**
 * Create a vector with sparse and small coefficients from seed
 */
static int8_t* create_vector_from_seed(private_bliss_private_key_t *this,
									   hash_algorithm_t alg, chunk_t seed)
{
	mgf1_bitspender_t *bitspender;
	uint32_t index, sign;
	int8_t *vector;
	int non_zero;

	bitspender = mgf1_bitspender_create(alg, seed, FALSE);
	if (!bitspender)
	{
	    return NULL;
	}

	vector = malloc(sizeof(int8_t) * this->set->n);
	memset(vector, 0x00, this->set->n);

	non_zero = this->set->non_zero1;
	while (non_zero)
	{
		index = bitspender->get_bits(bitspender, this->set->n_bits);
		if (index == MGF1_BITSPENDER_ERROR)
		{
			free(vector);
			return NULL;
		}
		if (vector[index] != 0)
		{
			continue;
		}

		sign = bitspender->get_bits(bitspender, 1);
		if (sign == MGF1_BITSPENDER_ERROR)
		{
			free(vector);
			return NULL;
		}
		vector[index] = sign ? 1 : -1;
		non_zero--;
	}

	non_zero = this->set->non_zero2;
	while (non_zero)
	{
		index = bitspender->get_bits(bitspender, this->set->n_bits);
		if (index == MGF1_BITSPENDER_ERROR)
		{
			free(vector);
			return NULL;
		}
		if (vector[index] != 0)
		{
			continue;
		}

		sign = bitspender->get_bits(bitspender, 1);
		if (sign == MGF1_BITSPENDER_ERROR)
		{
			free(vector);
			return NULL;
		}
		vector[index] = bitspender->get_bits(bitspender, 1) ? 2 : -2;
		non_zero--;
	}
	bitspender->destroy(bitspender);

	return vector;
}

/**
 * Generate the secret key S = (s1, s2) fulfilling the Nk(S) norm
 */
static bool create_secret(private_bliss_private_key_t *this, rng_t *rng,
						 int8_t **s1, int8_t **s2, int *trials)
{
	uint8_t seed_buf[32];
	uint8_t *f, *g;
	uint32_t l2_norm, nks;
	int i, n;
	chunk_t seed;
	size_t seed_len;
	hash_algorithm_t alg;

	n = this->set->n;
	*s1 = NULL;
	*s2 = NULL;

	/* Set MGF1 hash algorithm and seed length based on security strength */
	if (this->set->strength > 160)
	{
		alg = HASH_SHA256;
		seed_len = HASH_SIZE_SHA256;
	}
	else
	{
		alg = HASH_SHA1;
		seed_len = HASH_SIZE_SHA1;
	}
	seed = chunk_create(seed_buf, seed_len);

	while (*trials < SECRET_KEY_TRIALS_MAX)
	{
		(*trials)++;

		if (!rng->get_bytes(rng, seed_len, seed_buf))
		{
			return FALSE;
		}
		f = create_vector_from_seed(this, alg, seed);
		if (f == NULL)
		{
			return FALSE;
		}
		if (!rng->get_bytes(rng, seed_len, seed_buf))
		{
			free(f);
			return FALSE;
		}
		g = create_vector_from_seed(this, alg, seed);
		if (g == NULL)
		{
			free(f);
			return FALSE;
		}

		/* Compute 2g + 1 */
		for (i = 0; i < n; i++)
		{
			g[i] *= 2;
		}
		g[0] += 1;

		l2_norm = wrapped_product(f, f, n, 0) +  wrapped_product(g, g, n, 0);
		nks = nks_norm(f, g, n, this->set->kappa);
		DBG2(DBG_LIB, "l2 norm of s1||s2: %d, Nk(S): %u (%u max)",
					   l2_norm, nks, this->set->nks_max);
		if (nks < this->set->nks_max)
		{
			*s1 = f;
			*s2 = g;
			return TRUE;
		}
		free(f);
		free(g);
	}

	return FALSE;
}

/**
 * See header.
 */
bliss_private_key_t *bliss_private_key_gen(key_type_t type, va_list args)
{
	private_bliss_private_key_t *this;
	u_int key_size = 1;
	int i, n, trials = 0;
	uint32_t *A, *S1, *S2;
	uint16_t q;
	bool success = FALSE;
	bliss_param_set_t *set;
	bliss_fft_t *fft;
	rng_t *rng;

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

	/* Only BLISS-I and BLISS-IV are currently supported */
	set = bliss_param_set_get_by_id(key_size);
	if (!set)
	{
		DBG1(DBG_LIB, "BLISS parameter set %u not supported");
		return NULL;
	}

	/* Some shortcuts for often used variables */
	n = set->n;
	q = set->q;

	if (set->fft_params->n != n || set->fft_params->q != q)
	{
		DBG1(DBG_LIB, "FFT parameters do not match BLISS parameters");
		return NULL;
	}
	this = bliss_private_key_create_empty();
	this->set = set;

	/* We derive the public key from the private key using the FFT */
	fft = bliss_fft_create(set->fft_params);

	/* Some vectors needed to derive the publi key */
	S1 = malloc(n * sizeof(uint32_t));
	S2 = malloc(n * sizeof(uint32_t));
	A = malloc(n * sizeof(uint32_t));
	this->a = malloc(n * sizeof(uint32_t));

	/* Instantiate a true random generator */
	rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);

	/* Loop until we have an invertible polynomial s1 */
	do
	{
		if (!create_secret(this, rng, &this->s1, &this->s2, &trials))
		{
			break;
		}

		/* Convert signed arrays to unsigned arrays before FFT */
		for (i = 0; i < n; i++)
		{
			S1[i] = (this->s1[i] < 0) ? this->s1[i] + q :  this->s1[i];
			S2[i] = (this->s2[i] > 0) ? q - this->s2[i] : -this->s2[i];
		}
		fft->transform(fft, S1, S1, FALSE);
		fft->transform(fft, S2, S2, FALSE);

		success = TRUE;
		for (i = 0; i < n; i++)
		{
			if (S1[i] == 0)
			{
				DBG1(DBG_LIB, "S1[%d] is zero - s1 is not invertible", i);
				free(this->s1);
				free(this->s2);
				this->s1 = NULL;
				this->s2 = NULL;
				success = FALSE;
				break;
			}
			A[i] = invert(S1[i], q);
			A[i] = (S2[i] * A[i]) % q;
		}
	}
	while (!success && trials < SECRET_KEY_TRIALS_MAX);

	DBG1(DBG_LIB, "secret key generation %s after %d trial%s",
		 success ? "succeeded" : "failed", trials, (trials == 1) ? "" : "s");

	if (success)
	{
		fft->transform(fft, A, this->a, TRUE);

		DBG4(DBG_LIB, "   i   f   g     a     F     G     A");
		for (i = 0; i < n; i++)
		{
			DBG4(DBG_LIB, "%4d %3d %3d %5u %5u %5u %5u",
				 i, this->s1[i], this->s2[i], this->a[i], S1[i], S2[i], A[i]);
		}
	}
	else
	{
		destroy(this);
	}

	/* Cleanup */
	fft->destroy(fft);
	rng->destroy(rng);
	free(A);
	free(S1);
	free(S2);

	return success ? &this->public : NULL;
}

/**
 * ASN.1 definition of a BLISS private key
 */
static const asn1Object_t privkeyObjects[] = {
	{ 0, "BLISSPrivateKey",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1,   "keyType",			ASN1_OID,          ASN1_BODY }, /*  1 */
	{ 1,   "public",			ASN1_OCTET_STRING, ASN1_BODY }, /*  2 */
	{ 1,   "secret1",			ASN1_OCTET_STRING, ASN1_BODY }, /*  3 */
	{ 1,   "secret2",			ASN1_OCTET_STRING, ASN1_BODY }, /*  4 */
	{ 0, "exit",				ASN1_EOC,          ASN1_EXIT }
};
#define PRIV_KEY_TYPE			1
#define PRIV_KEY_PUBLIC			2
#define PRIV_KEY_SECRET1		3
#define PRIV_KEY_SECRET2		4

/**
 * See header.
 */
bliss_private_key_t *bliss_private_key_load(key_type_t type, va_list args)
{
	private_bliss_private_key_t *this;
	chunk_t key = chunk_empty, object;
	asn1_parser_t *parser;
	bool success = FALSE;
	int objectID, oid;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (key.len == 0)
	{
		return NULL;
	}
	this = bliss_private_key_create_empty();

	parser = asn1_parser_create(privkeyObjects, key);
	parser->set_flags(parser, FALSE, TRUE);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PRIV_KEY_TYPE:
				oid = asn1_known_oid(object);
				if (oid == OID_UNKNOWN)
				{
					goto end;
				}
				this->set = bliss_param_set_get_by_oid(oid);
				if (this->set == NULL)
				{
					goto end;
				}
				break;
			case PRIV_KEY_PUBLIC:
				if (object.len != 2*this->set->n)
				{
					goto end;
				}
				this->a = bliss_public_key_from_asn1(object, this->set->n);
				break;
			case PRIV_KEY_SECRET1:
				if (object.len != this->set->n)
				{
					goto end;
				}
				this->s1 = malloc(this->set->n);
				memcpy(this->s1, object.ptr, object.len);
				break;
			case PRIV_KEY_SECRET2:
				if (object.len != this->set->n)
				{
					goto end;
				}
				this->s2 = malloc(this->set->n);
				memcpy(this->s2, object.ptr, object.len);
				break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

