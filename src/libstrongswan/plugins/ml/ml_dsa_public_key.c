/*
 * Copyright (C) 2024 Andreas Steffen, strongSec GmbH
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

#include "ml_dsa_public_key.h"
#include "ml_dsa_params.h"
#include "ml_dsa_poly.h"
#include "ml_bitpacker.h"

#include <utils/debug.h>
#include <asn1/asn1.h>

typedef struct private_public_key_t private_public_key_t;

/**
 * Private data
 */
struct private_public_key_t {

	/**
	 * Public interface
	 */
	public_key_t public;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Parameter set.
	 */
	const ml_dsa_params_t *params;

	/**
	 * Public key
	 */
	chunk_t pubkey;

	/**
	 * SHAKE-128 instance.
	 */
	xof_t *G;

	/**
	 * SHAKE-256 instance.
	 */
	xof_t *H;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_public_key_t *this)
{
	return this->type;
}

/**
 * Decode the public key (pkDncode).
 *
 * Algorithm 23 in FIPS 204.
 */
static bool decode_public_key(private_public_key_t *this, chunk_t rho,
							  ml_dsa_poly_t *t1)
{
	const u_int k = this->params->k;
	u_int i, n;
	ml_bitpacker_t *bitpacker;
	chunk_t pk;

	pk = this->pubkey;
	memcpy(rho.ptr, pk.ptr, rho.len);
	pk = chunk_skip(pk, rho.len);

	/* unpack the vector t1 from the public key blob */
	bitpacker = ml_bitpacker_create_from_data(pk);
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &t1[i].f[n], ML_DSA_T1_BITS))
			{
				bitpacker->destroy(bitpacker);
				return FALSE;
			}
		}
	}
	bitpacker->destroy(bitpacker);

	return TRUE;
}

/**
 * Decodes a signature (sigDecode).
 *
 * Algorithm 27 in FIPS 204.
 */
static bool decode_signature(private_public_key_t *this, chunk_t signature,
							 chunk_t c_tilde, ml_dsa_poly_t *z, ml_dsa_poly_t *h)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const u_int gamma1_exp = this->params->gamma1_exp;
	const u_int omega = this->params->omega;
	const size_t sig_len = this->params->sig_len;
	ml_bitpacker_t *bitpacker;
	u_int i, j, n, first, index = 0;
	uint32_t value;
	chunk_t sig;

	if (signature.len != sig_len)
	{
		DBG1(DBG_LIB, "error: the size of the ML-DSA signature is %u bytes "
					  "instead of %u bytes", signature.len, sig_len);
		return FALSE;
	}
	sig = signature;

	/* extract byte string c_tilde */
	memcpy(c_tilde.ptr, sig.ptr, c_tilde.len);
	sig = chunk_skip(sig, c_tilde.len);

	/* decode vector of polynomials z from packed format */
	bitpacker = ml_bitpacker_create_from_data(sig);
	for (j = 0; j < l; j++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &value, 1 +  gamma1_exp))
			{
				bitpacker->destroy(bitpacker);
				chunk_free(&signature);
				return FALSE;
			}
			z[j].f[n] = (1 << gamma1_exp) - (int32_t)value;
		}
	}
	bitpacker->destroy(bitpacker);
	sig = chunk_skip(sig, 32 * (1 + gamma1_exp) * l);

	/* decode vector of polynomials with binary coefficients h (HintBitUnpack)
	 * Algorithm 21 in FIPS 204.
	 */
	memset(h, 0x00, k * ML_DSA_N * sizeof(int32_t));

	for (i = 0; i < k; i++)
	{
		if (sig.ptr[omega + i] < index)
		{
			DBG1(DBG_LIB, "error: signature with a decreasing maximum hint index");
			return FALSE;
		}
		if (sig.ptr[omega + i] > omega)
		{
			DBG1(DBG_LIB, "error: signature with an oversized maximum hint index");
			return FALSE;
		}

		first = index;
		while (index < sig.ptr[omega + i])
		{
			if (index > first && sig.ptr[index-1] >= sig.ptr[index])
			{
				DBG1(DBG_LIB, "error: signature with non-increasing hint positions");
				return FALSE;
			}
			h[i].f[sig.ptr[index++]] = 1;
		}
	}
	while (index < omega)
	{
		if (sig.ptr[index++] != 0x00)
		{
			DBG1(DBG_LIB, "error: signature with non-zeroed unused hint bit");
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Samples a polynomial with uniformly random coefficients in [0,Q-1]
 * by performing rejection sampling on a SHAKE-128 output stream G.
 *
 * Algorithm 30 in FIPS 204.
 */
static bool rej_ntt_poly(xof_t *G, chunk_t seed, ml_dsa_poly_t *a)
{
	uint8_t c[3];
	uint32_t t;
	u_int n = 0;

	if (!G->set_seed(G, seed))
	{
		return FALSE;
	}

	while (n < ML_DSA_N)
	{
		if (!G->get_bytes(G, sizeof(c), c))
		{
			return FALSE;
		}

		/* Algorithm 14 in FIPS 204 (CoeffFromThreeBytes) */
		t = (uint32_t)c[2] << 16 | (uint32_t)c[1] << 8 | (uint32_t)c[0];
		t &= 0x7fffff;

		if (t < ML_DSA_Q)
		{
			a->f[n++] = t;
		}
	}

	return TRUE;
}

/**
 * Samples a k x l matrix A.
 *
 * Algorithm 32 in FIPS 204.
 */
bool ml_dsa_expand_a(const ml_dsa_params_t *params, xof_t *G, chunk_t rho,
					 ml_dsa_poly_t *a)
{
	const u_int k = params->k;
	const u_int l = params->l;
	u_int i, j, ctr = 0;
	chunk_t seed;

	seed = chunk_alloca(ML_DSA_SEED_LEN + 2);
	memcpy(seed.ptr, rho.ptr, rho.len);

	for (i = 0; i < k; i++)
	{
		for (j = 0; j < l; j++)
		{
			seed.ptr[ML_DSA_SEED_LEN+1] = (uint8_t)i;
			seed.ptr[ML_DSA_SEED_LEN]   = (uint8_t)j;

			if (!rej_ntt_poly(G, seed, &a[ctr++]))
			{
				return FALSE;
			}
		}
	}

	return TRUE;
}

/**
 * samples a polynomial c with coefficients from {-1, 0, 1}
 * and Hamming weight tau <= 64.
 *
 * Algorithm 29 in FIPS 204.
 */
bool ml_dsa_sample_in_ball(xof_t *H, int32_t tau, chunk_t rho, ml_dsa_poly_t *c)
{
	uint8_t s[8], b;
	uint64_t signs = 0;
	u_int i;

	if (!H->set_seed(H, rho) ||
		!H->get_bytes(H, 8, s))
	{
		return FALSE;
	}
	for (i = 0; i < 8; i++)
	{
		signs |= (uint64_t)s[i] << 8*i;
	}
	for (i = 0; i < ML_DSA_N; i++)
	{
		c->f[i] = 0;
	}
	for (i = ML_DSA_N - tau; i < ML_DSA_N; i++)
	{
		do
		{
			if (!H->get_bytes(H, 1, &b))
			{
				return FALSE;
			}
		} while (b > i);

		c->f[i] = c->f[b];
		c->f[b] = 1 - 2*(signs & 1);
		signs >>= 1;
	}

	return TRUE;
}

/**
 * Encodes a polynomial vector w1 into a byte string.
 *
 * Algorithm 28 in FIPS 204.
 */
bool ml_dsa_w1_encode(u_int k, ml_dsa_poly_t *w1, chunk_t w1_enc, u_int d)
{
	ml_bitpacker_t *bitpacker;
	u_int j, n;

	bitpacker = ml_bitpacker_create(w1_enc);
	for (j = 0; j < k; j++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, w1[j].f[n], d))
			{
				bitpacker->destroy(bitpacker);
				return FALSE;
			}
		}
	}
	bitpacker->destroy(bitpacker);

	return TRUE;
}

METHOD(public_key_t, verify, bool,
	private_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const int32_t bound = (1 << this->params->gamma1_exp) - this->params->beta;
	pqc_params_t pqc_params;
	ml_dsa_poly_t a[k*l], t1[k], z[l], h[k], w1[k], c;
	chunk_t rho, c_tilde, c_tilde2, w1_enc, tr, seed, mu;

	if (key_type_from_signature_scheme(scheme) != this->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
					   signature_scheme_names, scheme);
		return FALSE;
	}

	rho      = chunk_alloca(ML_DSA_SEED_LEN);
	c_tilde  = chunk_alloca(this->params->lambda / 4);
	c_tilde2 = chunk_alloca(this->params->lambda / 4);
	w1_enc   = chunk_alloca(32 * this->params->gamma2_d * k);
	tr       = chunk_alloca(ML_DSA_TR_LEN);
	mu       = chunk_alloca(ML_DSA_MU_LEN);

	if (!decode_public_key(this, rho, t1) ||
		!decode_signature(this, signature, c_tilde, z, h) ||
		!ml_dsa_poly_check_bound_vec(l, z, bound) ||
		!ml_dsa_expand_a(this->params, this->G, rho, a))
	{
		return FALSE;
	}

	/* compute tr as a SHAKE-256 digest over the public key blob */
	if (!this->H->set_seed(this->H, this->pubkey) ||
		!this->H->get_bytes(this->H, ML_DSA_TR_LEN, tr.ptr))
	{
		return FALSE;
	}

	/* set PQC signature params */
	if (!pqc_params_create(params, &pqc_params))
	{
		return FALSE;
	}

	/* compute message representative mu */
	seed = chunk_cat("cmc", tr, pqc_params.pre_ctx, data);
	if (!this->H->set_seed(this->H, seed) ||
		!this->H->get_bytes(this->H, ML_DSA_MU_LEN, mu.ptr))
	{
		chunk_free(&seed);
		return FALSE;
	}
	chunk_free(&seed);

	/* verifier's challenge */
	if (!ml_dsa_sample_in_ball(this->H, this->params->tau, c_tilde, &c))
	{
		return FALSE;
	}

	/* compute w1 = a * z - c * 2^d * t1 */
 	ml_dsa_poly_ntt(&c);
	ml_dsa_poly_ntt_vec(l, z);
	ml_dsa_poly_mult_mat(k, l, a, z, w1);
	ml_dsa_poly_shift_left_vec(k, t1);
	ml_dsa_poly_ntt_vec(k, t1);
	ml_dsa_poly_mult_const_vec(k, &c, t1, t1);
	ml_dsa_poly_sub_vec(k, w1, t1, w1);
	ml_dsa_poly_reduce_vec(k, w1);
	ml_dsa_poly_inv_ntt_vec(k, w1);

	/* reconstruct w1 */
	ml_dsa_poly_cond_add_q_vec(k, w1);
	ml_dsa_poly_use_hint_vec(k, w1, h, w1, this->params->gamma2);

	/* compress the w1 vector into a byte string */
	if (!ml_dsa_w1_encode(k, w1, w1_enc, this->params->gamma2_d))
	{
		return FALSE;
	}

	/* compute commitment hash c_tilde2 */
	seed = chunk_cat("cc", mu, w1_enc);
	if (!this->H->set_seed(this->H, seed) ||
		!this->H->get_bytes(this->H, this->params->lambda/4, c_tilde2.ptr))
	{
		chunk_free(&seed);
		return FALSE;
	}
	chunk_free(&seed);

	return chunk_equals_const(c_tilde2, c_tilde);
}

METHOD(public_key_t, encrypt_, bool,
	private_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported", encryption_scheme_names,
		 scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_public_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->type);
}

/**
 * Generate two types of ML-DSA fingerprints.
 */
bool ml_dsa_fingerprint(chunk_t pubkey, key_type_t type,
						cred_encoding_type_t enc_type, chunk_t *fp)
{
	chunk_t encoding;
	hasher_t *hasher;

	*fp = chunk_empty;

	switch (enc_type)
	{
		case KEYID_PUBKEY_SHA1:
			encoding = chunk_clone(pubkey);
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			encoding = public_key_info_encode(pubkey, key_type_to_oid(type));
			break;
		default:
			return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, encoding, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported");
		DESTROY_IF(hasher);
		chunk_free(&encoding);
		return FALSE;
	}
	hasher->destroy(hasher);
	chunk_free(&encoding);

	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}

	success = ml_dsa_fingerprint(this->pubkey, this->type, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}

	return success;
}

METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = TRUE;
	int oid;

	oid = key_type_to_oid(this->type);
	*encoding = public_key_info_encode(this->pubkey, oid);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}

	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(public_key_t, destroy, void,
	private_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		DESTROY_IF(this->G);
		DESTROY_IF(this->H);
		chunk_free(&this->pubkey);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_public_key_t *create_empty(key_type_t type, chunk_t pubkey)
{
	private_public_key_t *this;
	const ml_dsa_params_t *params;

	params = ml_dsa_params_get(type);
	if (!params)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.get_type = _get_type,
			.verify = _verify,
			.encrypt = _encrypt_,
			.get_keysize = _get_keysize,
			.equals = public_key_equals,
			.get_fingerprint = _get_fingerprint,
			.has_fingerprint = public_key_has_fingerprint,
			.get_encoding = _get_encoding,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.type = type,
		.params = params,
		.pubkey = chunk_clone(pubkey),
		.G = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_128),
		.H = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_256),
		.ref = 1,
	);

	if (!this->G || !this->H)
	{
		destroy(this);
		return NULL;
	}

	return this;
}

/**
 * Check if ML-DSA key type is supported.
 */
bool ml_dsa_type_supported(key_type_t type)
{
	switch (type)
	{
		case KEY_ML_DSA_44:
		case KEY_ML_DSA_65:
		case KEY_ML_DSA_87:
			return TRUE;
		default:
			return FALSE;
	}
}

/*
 * Described in header
 */
public_key_t *ml_dsa_public_key_load(key_type_t type, va_list args)
{
	private_public_key_t *this;
	chunk_t pkcs1, blob = chunk_empty;
	size_t pubkey_len;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				pkcs1 = va_arg(args, chunk_t);
				type = public_key_info_decode(pkcs1, &blob);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!ml_dsa_type_supported(type) || blob.len == 0)
	{
		return NULL;
	}
	pubkey_len = get_public_key_size(type);
	if (blob.len != pubkey_len)
	{
		DBG1(DBG_LIB, "the size of the loaded ML-DSA public key is %u bytes "
					  "instead of %u bytes", blob.len, pubkey_len);
		return NULL;
	}

	this = create_empty(type, blob);
	if (!this)
	{
		return NULL;
	}

	return &this->public;
}
