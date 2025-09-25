/*
 * Copyright (C) 2024-2025 Andreas Steffen
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

#include "ml_dsa_private_key.h"
#include "ml_dsa_params.h"
#include "ml_dsa_poly.h"
#include "ml_utils.h"
#include "ml_bitpacker.h"

#include <library.h>
#include <utils/debug.h>
#include <asn1/asn1.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>
#include <credentials/keys/signature_params.h>

typedef struct private_private_key_t private_private_key_t;

/**
 * Private data
 */
struct private_private_key_t {

	/**
	 * Public interface
	 */
	private_key_t public;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Parameter set.
	 */
	const ml_dsa_params_t *params;

	/**
	 * Secret key seed
	 */
	chunk_t keyseed;

	/**
	 * Public key
	 */
	chunk_t pubkey;

	/**
	 * Private key
	 */
	chunk_t privkey;

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

/* from ml_dsa_public_key.c */
bool ml_dsa_expand_a(const ml_dsa_params_t *params, xof_t *G, chunk_t rho,
						ml_dsa_poly_t *a);

bool ml_dsa_sample_in_ball(xof_t *H, int32_t tau, chunk_t rho, ml_dsa_poly_t *c);

bool ml_dsa_w1_encode(u_int k, ml_dsa_poly_t *w1, chunk_t w1_enc, u_int d);

bool ml_dsa_fingerprint(chunk_t pubkey, key_type_t type,
						cred_encoding_type_t enc_type, chunk_t *fp);

bool ml_dsa_type_supported(key_type_t type);

/**
 * Decode the secret key (skDecode)
 *
 * Algorithm 25 in FIPS 204.
 */
static bool decode_secret_key(private_private_key_t *this, chunk_t rho,
							  chunk_t K, chunk_t tr, ml_dsa_poly_t *s1,
							  ml_dsa_poly_t *s2, ml_dsa_poly_t *t0)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const u_int d = this->params->d;
	const u_int eta = this->params->eta;
	u_int i, j, n;
	uint32_t value;
	ml_bitpacker_t *bitpacker;
	chunk_t sk;
	bool success = FALSE;

	sk = this->privkey;
	memcpy(rho.ptr, sk.ptr, rho.len);
	sk = chunk_skip(sk, rho.len);

	memcpy(K.ptr, sk.ptr, K.len);
	sk = chunk_skip(sk, K.len);

	memcpy(tr.ptr, sk.ptr, tr.len);
	sk = chunk_skip(sk, tr.len);

	/* unpack the vectors s1, s2 and t0 from the private key blob */
	bitpacker = ml_bitpacker_create_from_data(sk);
	for (j = 0; j < l; j++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &value, d) || value > 2*eta)
			{
				goto end;
			}
			s1[j].f[n] = eta - (int32_t)value;
		}
	}
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &value, d) || value > 2*eta)
			{
				goto end;
			}
			s2[i].f[n] = eta - (int32_t)value;
		}
	}
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &value, ML_DSA_D))
			{
				goto end;
			}
			t0[i].f[n] = (1 << (ML_DSA_D-1)) - (int32_t)value;
		}
	}
	success = TRUE;

end:
	bitpacker->destroy(bitpacker);

	return success;
}

/**
 * Samples a vector y such that each polynomial has coefficients between
 * -gamma1 + 1 and gamma1.
 *
 * Algorithm 34 in FIPS 204.
 */
static bool expand_mask(private_private_key_t *this, chunk_t rho, u_int nonce,
						ml_dsa_poly_t *y)
{
	const u_int gamma1_exp = this->params->gamma1_exp;
	const u_int l = this->params->l;
	ml_bitpacker_t *bitpacker;
	chunk_t v;
	uint32_t value;
	u_int j, n;

	v = chunk_alloca(32*(1 + gamma1_exp));

	for (j = 0; j < l; j++)
	{
		rho.ptr[ML_DSA_RHO_PP_LEN]   = nonce & 0x00ff;
		rho.ptr[ML_DSA_RHO_PP_LEN+1] = nonce++ >> 8;

		if (!this->H->set_seed(this->H, rho) ||
			!this->H->get_bytes(this->H, v.len, v.ptr))
		{
			return FALSE;
		}

		bitpacker = ml_bitpacker_create_from_data(v);
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->read_bits(bitpacker, &value, 1 + gamma1_exp))
			{
				bitpacker->destroy(bitpacker);
				return FALSE;
			}
			y[j].f[n] = (1 << gamma1_exp) - (int32_t)value;
		}
		bitpacker->destroy(bitpacker);
	}

	return TRUE;
}

/**
 * Encodes a signature into a byte string (sigEncode).
 *
 * Algorithm 26 in FIPS 204.
 */
static chunk_t encode_signature(private_private_key_t *this, chunk_t c_tilde,
								ml_dsa_poly_t *z, ml_dsa_poly_t *h)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const u_int gamma1_exp = this->params->gamma1_exp;
	const u_int omega = this->params->omega;
	ml_bitpacker_t *bitpacker;
	chunk_t signature, sig;
	u_int i, j, n, index = 0;

	signature = chunk_alloc(this->params->sig_len);
	sig = signature;

	/* encode byte string c_tilde */
	memcpy(sig.ptr, c_tilde.ptr, c_tilde.len);
	sig = chunk_skip(sig, c_tilde.len);

	/* encode vector of polynomials z in packed format */
	bitpacker = ml_bitpacker_create(sig);
	for (j = 0; j < l; j++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, (1 << gamma1_exp) - z[j].f[n],
												   1 +  gamma1_exp))
			{
				bitpacker->destroy(bitpacker);
				chunk_free(&signature);
				return chunk_empty;
			}
		}
	}
	bitpacker->destroy(bitpacker);
	sig = chunk_skip(sig, 32 * (1 + gamma1_exp) * l);

	/* encode vector of polynomials with binary coefficients h (HintBitPack)
	 * Algorithm 20 in FIPS 204.
	 */
	memset(sig.ptr, 0x00, omega);

	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (h[i].f[n] != 0)
			{
				sig.ptr[index++] = (uint8_t)n;
			}
		}
		sig.ptr[omega + i] = (uint8_t)index;
	}

	return signature;
}

METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{

	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const u_int gamma2 = this->params->gamma2;
	const u_int omega = this->params->omega;
	const int32_t bound1 = (1 << this->params->gamma1_exp) - this->params->beta;
	const int32_t bound2 = gamma2 - this->params->beta;
	pqc_params_t pqc_params;
	ml_dsa_poly_t a[k*l], s1[l], s2[k], t0[k];
	ml_dsa_poly_t y[l], z[l], w0[k], w1[k], h[k], c;
	chunk_t rho, K , tr, seed, mu, rnd, rho_pp, w1_enc, c_tilde;
	u_int kappa = 0;
	rng_t *rng;

	/* set empty signature in case of failure */
	*signature = chunk_empty;

	if (key_type_from_signature_scheme(scheme) != this->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
					   signature_scheme_names, scheme);
		return FALSE;
	}

	rho     = chunk_alloca(ML_DSA_SEED_LEN);
	K       = chunk_alloca(ML_DSA_K_LEN);
	tr      = chunk_alloca(ML_DSA_TR_LEN);
	rnd     = chunk_alloca(ML_DSA_RND_LEN);
	mu      = chunk_alloca(ML_DSA_MU_LEN);
	rho_pp  = chunk_alloca(ML_DSA_RHO_PP_LEN + 2);
	w1_enc  = chunk_alloca(32 * this->params->gamma2_d * k);
	c_tilde = chunk_alloca(this->params->lambda / 4);

	if (!decode_secret_key(this, rho, K, tr, s1, s2, t0) ||
		!ml_dsa_expand_a(this->params, this->G, rho, a))
	{
		goto cleanup;
	}

	ml_dsa_poly_ntt_vec(l, s1);
	ml_dsa_poly_ntt_vec(k, s2);
	ml_dsa_poly_ntt_vec(k, t0);

	/* set PQC signature params */
	if (!pqc_params_create(params, &pqc_params))
	{
		goto cleanup;
	}

	/* compute message representative mu */
	seed = chunk_cat("cmc", tr, pqc_params.pre_ctx, data);
	if (!this->H->set_seed(this->H, seed) ||
		!this->H->get_bytes(this->H, ML_DSA_MU_LEN, mu.ptr))
	{
		chunk_free(&seed);
		goto cleanup;
	}
	chunk_free(&seed);


	/* deterministic or randomized signature? */
	if 	(pqc_params.deterministic)
	{
		memset(rnd.ptr, 0x00, ML_DSA_RND_LEN);
	}
	else
	{
		rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
		if (!rng || !rng->get_bytes(rng, ML_DSA_RND_LEN, rnd.ptr))
		{
			DESTROY_IF(rng);
			goto cleanup;
		}
		rng->destroy(rng);
	}

	/* compute random private seed rho_pp */
	seed = chunk_cat("ccc", K, rnd, mu);
	if (!this->H->set_seed(this->H, seed) ||
		!this->H->get_bytes(this->H, ML_DSA_RHO_PP_LEN, rho_pp.ptr))
	{
		chunk_clear(&seed);
		goto cleanup;
	}
	chunk_clear(&seed);

	while (TRUE)
	{
		if (!expand_mask(this, rho_pp, kappa, y))
		{
			goto cleanup;
		}
		kappa += l;

		/* multiply vector y with matrix a via NTT resulting in vector w */
		ml_dsa_poly_copy_vec(l, y, z);
		ml_dsa_poly_ntt_vec(l, z);
		ml_dsa_poly_mult_mat(k, l, a, z, w1);
		ml_dsa_poly_reduce_vec(k, w1);
		ml_dsa_poly_inv_ntt_vec(k, w1);
		ml_dsa_poly_cond_add_q_vec(k, w1);

		/* decompose elements of vector w into high and low bits */
		ml_dsa_poly_decompose_vec(k, w1, w0, w1, gamma2);

		/* compress the w1 vector into a byte string */
		if (!ml_dsa_w1_encode(k, w1, w1_enc, this->params->gamma2_d))
		{
			goto cleanup;
		}

		/* compute commitment hash c_tilde */
		seed = chunk_cat("cc", mu, w1_enc);
		if (!this->H->set_seed(this->H, seed) ||
			!this->H->get_bytes(this->H, this->params->lambda/4, c_tilde.ptr))
		{
			chunk_clear(&seed);
			goto cleanup;
		}
		chunk_clear(&seed);

		/* verifier's challenge */
		if (!ml_dsa_sample_in_ball(this->H, this->params->tau, c_tilde, &c))
		{
			goto cleanup;
		}
		ml_dsa_poly_ntt(&c);

		/* compute z, reject if it reveals secret */
		ml_dsa_poly_mult_const_vec(l, &c, s1, z);
		ml_dsa_poly_inv_ntt_vec(l, z);
		ml_dsa_poly_add_vec(l, z, y, z);
		ml_dsa_poly_reduce_vec(l, z);

		if (!ml_dsa_poly_check_bound_vec(l, z, bound1))
		{
			continue;
		}

		/* check that subtracting cs2 does not change high bits of w and
		 * low bits do not reveal secret information
		 */
		ml_dsa_poly_mult_const_vec(k, &c, s2, h);
		ml_dsa_poly_inv_ntt_vec(k, h);
		ml_dsa_poly_sub_vec(k, w0, h, w0);
		ml_dsa_poly_reduce_vec(k, w0);

		if (!ml_dsa_poly_check_bound_vec(k, w0, bound2))
		{
			continue;
		}

		/* compute hints for w1 */
		ml_dsa_poly_mult_const_vec(k, &c, t0, h);
		ml_dsa_poly_inv_ntt_vec(k, h);
		ml_dsa_poly_reduce_vec(k, h);

		if (!ml_dsa_poly_check_bound_vec(k, h, gamma2))
		{
			continue;
		}

		ml_dsa_poly_add_vec(k, w0, h, w0);

		if (ml_dsa_poly_make_hint_vec(k, w0, w1, h, gamma2) > omega)
		{
			continue;
		}

		/* all checks passed - exit the loop */
		break;
	}

	*signature = encode_signature(this, c_tilde, z, h);

cleanup:
	memwipe(a, sizeof(a));
	memwipe(s1, sizeof(s1));
	memwipe(s2, sizeof(s2));
	memwipe(t0, sizeof(t0));
	memwipe(K.ptr, K.len);

	return signature->len > 0;
}

METHOD(private_key_t, decrypt, bool,
	private_private_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "ML-DSA private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_private_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->type);
}

METHOD(private_key_t, get_type, key_type_t,
	private_private_key_t *this)
{
	return this->type;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_private_key_t *this)
{
	return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
							  BUILD_BLOB, this->pubkey, BUILD_END);
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,	chunk_t *fp)
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

METHOD(private_key_t, get_encoding, bool,
	private_private_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;
			int oid = key_type_to_oid(this->type);

			*encoding = asn1_wrap(ASN1_SEQUENCE, "cmm",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(oid),
							asn1_wrap(ASN1_OCTET_STRING, "m",
								asn1_simple_object(ASN1_CONTEXT_S_0,
												   this->keyseed))
						);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}

			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(private_key_t, destroy, void,
	private_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		DESTROY_IF(this->G);
		DESTROY_IF(this->H);
		chunk_clear(&this->keyseed);
		chunk_clear(&this->privkey);
		chunk_free(&this->pubkey);
		free(this);
	}
}

/**
 * Generates an element of [-eta, eta] or rejects the sample.
 *
 * Algorithm 15 in FIPS 204.
 */
static bool coeff_from_half_byte(uint8_t b, uint8_t eta, int32_t *a)
{
	const int32_t eta_samples[] = {
		2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 2, 1, 0, -1, -2
	};

	if (eta == 2)
	{
		if (b >= 15)
		{
			return FALSE;  /* reject sample */
		}
		*a = eta_samples[b];
	}
	else if (eta == 4)
	{
		if (b >= 9)
		{
			return FALSE;  /* reject sample */
		}
		*a = 4 - (int32_t)b;
	}

	return TRUE;
}

/**
 * Samples an element with coefficients in [-eta, eta] computed via
 * rejection sampling on a SHAKE-256 output stream H.
 *
 * Algorithm 31 in FIPS 204.
 */
static bool rej_bounded_poly(private_private_key_t *this, chunk_t seed,
							 ml_dsa_poly_t *a)
{
	uint8_t c, c0, c1;
	u_int n = 0;

	if (!this->H->set_seed(this->H, seed))
	{
		return FALSE;
	}

	while (n < ML_DSA_N)
	{
		if (!this->H->get_bytes(this->H, 1, &c))
		{
			return FALSE;
		}

		/* form half bytes */
		c0 = c & 0x0f;
		c1 = c >> 4;
		if (coeff_from_half_byte(c0, this->params->eta, &a->f[n]))
		{
			if (++n == ML_DSA_N)
			{
				break;
			}
		}
		if (coeff_from_half_byte(c1, this->params->eta, &a->f[n]))
		{
			++n;
		}
	}
	return TRUE;
}

/**
 * Samples vectors s1 and s2, each with polynomial coordinates whose coefficients
 * are in the interval [-eta, eta].
 *
 * Algorithm 33 in FIPS 204.
 */
static bool expand_s(private_private_key_t *this, chunk_t rhoprime,
					 ml_dsa_poly_t *s1, ml_dsa_poly_t *s2)
{
	chunk_t seed;
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	u_int i, j;
	bool success = FALSE;

	seed = chunk_alloca(2*ML_DSA_SEED_LEN + 2);
	memcpy(seed.ptr, rhoprime.ptr, rhoprime.len);
	seed.ptr[2*ML_DSA_SEED_LEN+1] = 0;

	for (j = 0; j < l; j++)
	{
		seed.ptr[2*ML_DSA_SEED_LEN] = (uint8_t)j;
	    if (!rej_bounded_poly(this, seed, &s1[j]))
	    {
			goto cleanup;
	    }
	}
	for (i = 0; i < k; i++)
	{
		seed.ptr[2*ML_DSA_SEED_LEN] = (uint8_t)(l + i);
	    if (!rej_bounded_poly(this, seed, &s2[i]))
	    {
			goto cleanup;
	    }
	}
	success = TRUE;

cleanup:
	memwipe(seed.ptr, seed.len);

	return success;
}

/**
 * Encode the public key (pkEncode).
 *
 * Algorithm 22 in FIPS 204.
 */
static bool encode_public_key(private_private_key_t *this, chunk_t rho,
							  ml_dsa_poly_t *t1)
{
	const u_int k = this->params->k;
	u_int i, n;
	ml_bitpacker_t *bitpacker;
	chunk_t pk;

	pk = this->pubkey;
	memcpy(pk.ptr, rho.ptr, rho.len);
	pk = chunk_skip(pk, rho.len);

	/* pack the vector t1 into the public key blob */
	bitpacker = ml_bitpacker_create(pk);
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, t1[i].f[n], ML_DSA_T1_BITS))
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
 * Encode the secret key (skEncode).
 *
 * Algorithm 24 in FIPS 204.
 */
static bool encode_secret_key(private_private_key_t *this, chunk_t rho,
							  chunk_t K, ml_dsa_poly_t *s1, ml_dsa_poly_t *s2,
							  ml_dsa_poly_t *t0)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	const u_int d = this->params->d;
	const u_int eta = this->params->eta;
	u_int i, j, n;
	ml_bitpacker_t *bitpacker;
	chunk_t sk;
	bool success = FALSE;

	sk = this->privkey;
	memcpy(sk.ptr, rho.ptr, rho.len);
	sk = chunk_skip(sk, rho.len);

	memcpy(sk.ptr, K.ptr, K.len);
	sk = chunk_skip(sk, K.len);

	/* compute tr as a SHAKE-256 digest over the public key blob
	 * and put it in the private key blob
	 */
	if (!this->H->set_seed(this->H, this->pubkey) ||
		!this->H->get_bytes(this->H, ML_DSA_TR_LEN, sk.ptr))
	{
		return FALSE;
	}
	sk = chunk_skip(sk, ML_DSA_TR_LEN);

	/* pack the vectors s1, s2 and t0 into the private key blob*/
	bitpacker = ml_bitpacker_create(sk);
	for (j = 0; j < l; j++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, eta - s1[j].f[n], d))
			{
				goto end;
			}
		}
	}
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, eta - s2[i].f[n], d))
			{
				goto end;
			}
		}
	}
	for (i = 0; i < k; i++)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			if (!bitpacker->write_bits(bitpacker, (1 << (ML_DSA_D-1)) - t0[i].f[n],
														 ML_DSA_D))
			{
				goto end;
			}
		}
	}
	success = TRUE;

end:
	bitpacker->destroy(bitpacker);

	return success;
}

/**
 * Generates a public/private key pair from a seed
 *
 * Algorithm 6 in FIPS 204.
 */
static bool generate_keypair(private_private_key_t *this, chunk_t keyseed)
{
	const u_int k = this->params->k;
	const u_int l = this->params->l;
	ml_dsa_poly_t a[k*l], s1[l], s1_hat[l], s2[k], t1[k], t0[k];
	bool success = FALSE;

	/**
	 *  Mapping of seedbuf
	 *
	 *       0         32
	 *       +---------+
	 *  Init | keyseed |
	 *       +---------+
	 *       0          34
	 *       +----------+
	 *  In   |   seed   |
	 *       +----------+
	 *       0         32        64        96        128
	 *       +---------+-------------------+---------+
	 *  Out  |   rho   |      rhoprime     |    K    |
	 *       +---------+-------------------+---------+
	 */
	uint8_t seedbuf[4*ML_DSA_SEED_LEN];
	chunk_t seed =     { seedbuf,                       ML_DSA_SEED_LEN+2 };
	chunk_t rho  =     { seedbuf,                       ML_DSA_SEED_LEN };
	chunk_t rhoprime = { seedbuf +   ML_DSA_SEED_LEN, 2*ML_DSA_SEED_LEN };
	chunk_t K =        { seedbuf + 3*ML_DSA_SEED_LEN,   ML_DSA_K_LEN };

	/* keep a copy of the secret key seed */
	this->keyseed = keyseed;

	memcpy(seedbuf, keyseed.ptr, keyseed.len);
	seedbuf[ML_DSA_SEED_LEN]   = this->params->k;
	seedbuf[ML_DSA_SEED_LEN+1] = this->params->l;

	if (!this->H->set_seed(this->H, seed) ||
		!this->H->get_bytes(this->H, sizeof(seedbuf), seedbuf) ||
		!ml_dsa_expand_a(this->params, this->G, rho, a) ||
		!expand_s(this, rhoprime, s1, s2))
	{
		goto cleanup;
	}

	/* apply NTT to a copy of the s1 vector */
	ml_dsa_poly_copy_vec(l, s1, s1_hat);
	ml_dsa_poly_ntt_vec(l, s1_hat);

	/* multiply vector s1_hat with matrix a in the NTT domain */
	ml_dsa_poly_mult_mat(k, l, a, s1_hat, t1);

	/* reduce the elements of vector t1 to the range -6283008 <= r <= 6283008 */
	ml_dsa_poly_reduce_vec(k, t1);

	/* apply the inverse NTT to vector t1 */
	ml_dsa_poly_inv_ntt_vec(k, t1);

	/* add error vector s2 to t1 */
	ml_dsa_poly_add_vec(k, s2, t1, t1);

	/* make all polynomial coefficients positive by conditionally adding q */
	ml_dsa_poly_cond_add_q_vec(k, t1);

	/* decomposes t1 into (t1, t0) such that t1 ≡ t1 * 2^d + t0 mod q */
	ml_dsa_poly_power2round_vec(k, t1, t0, t1);

	success = encode_public_key(this, rho, t1) &&
			  encode_secret_key(this, rho, K, s1, s2, t0);

cleanup:
	memwipe(seedbuf, sizeof(seedbuf));
	memwipe(a, sizeof(a));
	memwipe(s1, sizeof(s1));
	memwipe(s1_hat, sizeof(s1_hat));
	memwipe(s2, sizeof(s2));
	memwipe(t0, sizeof(t0));

	return success;
}

/**
 * Generic private constructor
 */
static private_private_key_t *create_instance(key_type_t type)
{
	private_private_key_t *this;
	const ml_dsa_params_t *params;

	params = ml_dsa_params_get(type);
	if (!params)
	{
		return NULL;
	}

	INIT(this,
		.public = {
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
		.type = type,
		.params = params,
		.pubkey = chunk_alloc(get_public_key_size(type)),
		.privkey = chunk_alloc(params->privkey_len),
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

/*
 * Described in header
 */
private_key_t *ml_dsa_private_key_gen(key_type_t type, va_list args)
{
	private_private_key_t *this;
	chunk_t seed;
	rng_t *rng;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* just ignore the key size */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
	if (!rng || !rng->allocate_bytes(rng, ML_DSA_SEED_LEN, &seed))
	{
		DESTROY_IF(rng);
		return NULL;
	}
	rng->destroy(rng);

	this = create_instance(type);
	if (!this)
	{
		chunk_free(&seed);
		return NULL;
	}

	if (!generate_keypair(this, seed))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/*
 * Described in header
 */
private_key_t *ml_dsa_private_key_load(key_type_t type, va_list args)
{
	private_private_key_t *this;
	chunk_t priv = chunk_empty, seed = chunk_empty;
	int asn1_type;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				priv = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (priv.len == 0 || !ml_dsa_type_supported(type))
	{
		return NULL;
	}

	this = create_instance(type);
	if (!this)
	{
		return NULL;
	}

	if (priv.len == ML_DSA_SEED_LEN)
	{
		asn1_type = ASN1_CONTEXT_S_0;
	}
	else
	{
		asn1_type = asn1_unwrap(&priv, &priv);
	}

	/* three supported ML-DSA private key formats */
	switch(asn1_type)
	{
		/* private key in seed-only format */
		case ASN1_CONTEXT_S_0:
			seed = priv;
			if (seed.len != ML_DSA_SEED_LEN ||
			   !generate_keypair(this, chunk_clone(seed)))
			{
				DBG1(DBG_LIB, "failed to load ML-DSA private key seed");
				destroy(this);
				return NULL;
			}
			break;

		/* private key in epanded format */
		case ASN1_OCTET_STRING:
			if (priv.len != this->params->privkey_len)
			{
				DBG1(DBG_LIB, "failed to load ML-DSA expanded private key");
				destroy(this);
				return NULL;
			}
			memcpy(this->privkey.ptr, priv.ptr, priv.len);
			break;

		/* private key in both seed and expanded format */
		case ASN1_SEQUENCE:
			if (priv.len < 2 || priv.ptr[0] != ASN1_OCTET_STRING ||
				asn1_length(&priv) != ML_DSA_SEED_LEN)
			{
				DBG1(DBG_LIB, "failed to identify ML-DSA private key seed");
				destroy(this);
				return NULL;
			}
			seed = chunk_create(priv.ptr, ML_DSA_SEED_LEN);
			if (!generate_keypair(this, chunk_clone(seed)))
			{
				DBG1(DBG_LIB, "failed to load ML-DSA private key seed");
				destroy(this);
				return NULL;
			}
			priv.ptr += ML_DSA_SEED_LEN;
			priv.len -= ML_DSA_SEED_LEN;
			if (priv.len < 2 || priv.ptr[0] != ASN1_OCTET_STRING ||
				asn1_length(&priv) != this->params->privkey_len)
			{
				DBG1(DBG_LIB, "failed to identify ML-DSA expanded private key");
				destroy(this);
				return NULL;
			}
			if (!chunk_equals(priv, this->privkey))
			{
				DBG1(DBG_LIB, "loaded expanded private key is not derived "
							  "from loaded seed");
				destroy(this);
				return NULL;
			}
			break;

		/* invalid private key format */
		case ASN1_INVALID:
		default:
			DBG1(DBG_LIB, "unknown ML-DSA private key format");
			destroy(this);
			return NULL;
	}

	return &this->public;
}
