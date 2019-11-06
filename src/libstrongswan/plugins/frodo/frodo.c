/*
 * MIT License
 *
 * Copyright (C) Microsoft Corporation
 *
 * Copyright (C) 2019 Andreas Steffen
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

#include "frodo.h"
#include "frodo_params.h"
#include "frodo_utils.h"

#include <utils/debug.h>

typedef struct private_frodo_t private_frodo_t;

/**
 * Private data of an frodo_t object.
 */
struct private_frodo_t {

	/**
	 * Public frodo_t interface.
	 */
	frodo_t public;

	/**
	 * key exchange method
	 */
	key_exchange_method_t method;

	/**
	 * If TRUE use AES128 for generating matrix A, otherwise use SHAKE128
	 */
	bool use_aes;

	/**
	 * Frodo parameters
	 */
	const frodo_params_t *params;

	/**
	 * Public Key
	 */
	uint8_t *public_key;

	/**
	 * Secret Key
	 */
	uint8_t *secret_key;

	/**
	 * Ciphertext
	 */
	uint8_t *ciphertext;

	/**
	 * Shared secret
	 */
	uint8_t *shared_secret;

	/**
	 * NIST CTR DRBG
	 */
	drbg_t *drbg;

	/**
	 * SHAKE-128 or SHAKE-256 eXtended Output Function
	 */
	xof_t *xof;

};

/**
 *
 */
static bool need_drbg(private_frodo_t *this)
{
	uint32_t strength = 256;
	rng_t *entropy;

	if (this->drbg)
	{
		return TRUE;
	}

	/* entropy will be owned by drbg */
	entropy = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
	if (!entropy)
	{
		DBG1(DBG_LIB, "could not attach entropy source for DRBG");
		return FALSE;
	}

	this->drbg = lib->crypto->create_drbg(lib->crypto, DRBG_CTR_AES256,
										  strength, entropy, chunk_empty);
	if (!this->drbg)
	{
		DBG1(DBG_LIB, "could not instantiate DRBG at %u bit security", strength);
		entropy->destroy(entropy);
		return FALSE;
	}

	return TRUE;
}

/**
 * Generator function shared between encaps and decaps shared secret
 */
static bool generate(private_frodo_t *this, chunk_t G2in, uint8_t *k,
					 uint16_t *Bp, uint16_t *C)
{
	const uint32_t n_x_nb     = this->params->n  * this->params->nb;
	const uint32_t nb_x_nb    = this->params->nb * this->params->nb;
	const uint32_t log_q      = this->params->log_q;
	const uint32_t seed_A_len = this->params->seed_A_len;
	const uint32_t ss_len     = this->params->ss_len;
	const uint32_t pk_len     = this->params->pk_len;

	uint8_t *mu       = G2in.ptr + ss_len;
	uint8_t *pk_seedA = this->public_key;
	uint8_t *pk_b     = this->public_key + seed_A_len;
	uint16_t B[n_x_nb], Sp[n_x_nb], Ep[n_x_nb], Epp[nb_x_nb], V[nb_x_nb];

	chunk_t seedSE = chunk_alloc(1 + ss_len);

	if (!this->xof->set_seed(this->xof, G2in) ||
		!this->xof->get_bytes(this->xof, ss_len, seedSE.ptr + 1) ||
		!this->xof->get_bytes(this->xof, ss_len, k))
	{
		return FALSE;
	}
	*seedSE.ptr = 0x96;

	/* Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly */
	if (!this->xof->set_seed(this->xof, seedSE) ||
		!this->xof->get_bytes(this->xof,
							  n_x_nb * sizeof(uint16_t), (uint8_t*)Sp) ||
		!this->xof->get_bytes(this->xof,
							  n_x_nb * sizeof(uint16_t), (uint8_t*)Ep) ||
		!this->xof->get_bytes(this->xof,
							 nb_x_nb * sizeof(uint16_t), (uint8_t*)Epp))
	{
		return FALSE;
	}

	frodo_sample_n(this->params, Sp, n_x_nb);
	frodo_sample_n(this->params, Ep, n_x_nb);
	frodo_mul_add_sa_plus_e(this->params, Bp, Sp, Ep, pk_seedA, this->use_aes);

	/* Generate Epp, and compute V = Sp*B + Epp */
	frodo_sample_n(this->params, Epp, nb_x_nb);
	frodo_unpack(B, n_x_nb, pk_b, pk_len - seed_A_len, log_q);
	frodo_mul_add_sb_plus_e(this->params, V, B, Sp, Epp);

	/* Encode mu, and compute C = V + enc(mu) (mod q) */
	frodo_key_encode(this->params, C, (uint16_t*)mu);
	frodo_add(this->params, C, V, C);

	/* Cleanup */
	memwipe((uint8_t *)Sp,   n_x_nb * sizeof(uint16_t));
	memwipe((uint8_t *)Ep,   n_x_nb * sizeof(uint16_t));
	memwipe((uint8_t *)Epp, nb_x_nb * sizeof(uint16_t));
	memwipe((uint8_t *)V,   nb_x_nb * sizeof(uint16_t));
	chunk_clear(&seedSE);

	return TRUE;
}

/**
 * Generate the shared secret and encrypt it with the configured public key
 */
static bool encaps_shared_secret(private_frodo_t *this)
{
	const uint32_t n_x_nb     = this->params->n  * this->params->nb;
	const uint32_t nb_x_nb    = this->params->nb * this->params->nb;
	const uint32_t log_q      = this->params->log_q;
	const uint32_t extr_bits  = this->params->extr_bits;
	const uint32_t ct_c1_len  = (n_x_nb  * log_q)/8;
	const uint32_t ct_c2_len  = (nb_x_nb * log_q)/8;
	const uint32_t mu_len     = (nb_x_nb * extr_bits)/8;
	const uint32_t ss_len     = this->params->ss_len;
	const uint32_t ct_len     = this->params->ct_len;
	const uint32_t pk_len     = this->params->pk_len;

	chunk_t pk = chunk_create(this->public_key, pk_len);
	chunk_t G2in = chunk_alloca(ss_len + mu_len);
	uint8_t *pkh = G2in.ptr;
	uint8_t *mu  = G2in.ptr + ss_len;
	uint8_t *ct_c1, *ct_c2;
	uint8_t Fin[ct_len + ss_len];
	uint8_t *Fin_ct = &Fin[0];
	uint8_t *Fin_k  = &Fin[ct_len];
	uint8_t k[ss_len];
	uint16_t Bp[n_x_nb], C[nb_x_nb];

	if (!this->ciphertext)
	{
		this->ciphertext = malloc(ct_len);
	}
	ct_c1 = this->ciphertext;
	ct_c2 = this->ciphertext + ct_c1_len;

	/* pkh <- G_1(pk) */
	if (!this->xof->set_seed(this->xof, pk) ||
		!this->xof->get_bytes(this->xof, ss_len, pkh))
	{
		return FALSE;
	}

	/* Generate random mu */
	if (!this->drbg->generate(this->drbg, mu_len, mu))
	{
		DBG1(DBG_LIB, "could not generate mu");
		return FALSE;
	}

	if (!generate(this, G2in, k, Bp, C))
	{
		return FALSE;
	}
	frodo_pack(ct_c1, ct_c1_len, Bp, n_x_nb, log_q);
	frodo_pack(ct_c2, ct_c2_len, C, nb_x_nb, log_q);

	/* Compute ss = F(ct||KK) */
	memcpy(Fin_ct, this->ciphertext, ct_len);
	memcpy(Fin_k, k, ss_len);

	if (!this->xof->set_seed(this->xof, chunk_create(Fin, ct_len + ss_len)) ||
		!this->xof->get_bytes(this->xof, ss_len, this->shared_secret))
	{
		return FALSE;
	}

	/* Cleanup */
	memwipe(mu, mu_len);
	memwipe(k, ss_len);
 	memwipe(Fin_k, ss_len);

	return TRUE;
}

/**
 * Decapsulate the shared secret using the secret key
 */
static bool decaps_shared_secret(private_frodo_t *this)
{
	const uint32_t n_x_nb     = this->params->n  * this->params->nb;
	const uint32_t nb_x_nb    = this->params->nb * this->params->nb;
	const uint32_t log_q      = this->params->log_q;
	const uint32_t extr_bits  = this->params->extr_bits;
	const uint32_t ct_c1_len  = (n_x_nb  * log_q)/8;
	const uint32_t ct_c2_len  = (nb_x_nb * log_q)/8;
	const uint32_t mu_len     = (nb_x_nb * extr_bits)/8;
	const uint32_t ss_len     = this->params->ss_len;
	const uint32_t ct_len     = this->params->ct_len;
	const uint32_t pk_len     = this->params->pk_len;

	chunk_t G2in = chunk_alloca(ss_len + mu_len);
	uint8_t *pkh = G2in.ptr;
	uint8_t *muprime = G2in.ptr + ss_len;
	uint8_t *ct_c1 = this->ciphertext;
	uint8_t *ct_c2 = this->ciphertext + ct_c1_len;
	uint8_t *sk_s = this->secret_key;
	uint16_t *sk_S = (uint16_t *)(this->secret_key + ss_len + pk_len);
	uint8_t *sk_pkh = this->secret_key + ss_len + pk_len + 2*n_x_nb;
	uint8_t Fin[ct_len + ss_len];
	uint8_t *Fin_ct = &Fin[0];
	uint8_t *Fin_k = &Fin[ct_len];
	uint8_t kprime[ss_len];
	uint16_t Bp[n_x_nb], BBp[n_x_nb];
	uint16_t W[nb_x_nb], C[nb_x_nb], CC[nb_x_nb];

	/* Compute W = C - Bp*S (mod q), and decode the randomness mu */
	frodo_unpack(Bp, n_x_nb, ct_c1, ct_c1_len, log_q);
	frodo_unpack(C, nb_x_nb, ct_c2, ct_c2_len, log_q);
	frodo_mul_bs(this->params, W, Bp, sk_S);
	frodo_sub(this->params, W, C, W);
	frodo_key_decode(this->params, (uint16_t*)muprime, W);
	memcpy(pkh, sk_pkh, ss_len);

	if (!generate(this, G2in, kprime, BBp, CC))
	{
		return FALSE;
	}

	/* Prepare input to F */
	memcpy(Fin_ct, this->ciphertext, ct_len);

	/* Reducing BBp modulo q */
	for (int i = 0; i < n_x_nb; i++)
	{
		BBp[i] = BBp[i] & ((1 << log_q) - 1);
	}

	/* Is (Bp == BBp & C == CC) = true */
	if (memcmp(Bp, BBp, n_x_nb * sizeof(uint16_t)) == 0 &&
		memcmp(C,  CC, nb_x_nb * sizeof(uint16_t)) == 0)
	{
		/* Load k' to do ss = F(ct || k') */
		memcpy(Fin_k, kprime, ss_len);
	}
	else
	{
		/* Load s to do ss = F(ct || s) */
		memcpy(Fin_k, sk_s, ss_len);
	}

	if (!this->xof->set_seed(this->xof, chunk_create(Fin, ct_len + ss_len)) ||
		!this->xof->get_bytes(this->xof, ss_len, this->shared_secret))
	{
		return FALSE;
	}

	/* Cleanup: */
	memwipe((uint8_t *)W, nb_x_nb * sizeof(uint16_t));
	memwipe(muprime, mu_len);
	memwipe(kprime, ss_len);
	memwipe(Fin_k, ss_len);

	return TRUE;
}

/**
 *
 */
static bool set_ciphertext(private_frodo_t *this, chunk_t value)
{
	if (value.len != this->params->ct_len)
	{
		DBG1(DBG_LIB, "wrong %N ciphertext size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->params->ct_len);
		return FALSE;
	}
	this->ciphertext = malloc(value.len);
	memcpy(this->ciphertext, value.ptr, value.len);

	return decaps_shared_secret(this);
}

METHOD(key_exchange_t, get_public_key, bool,
	private_frodo_t *this, chunk_t *value)
{
	/* responder action */
	if (this->ciphertext)
	{
		*value = chunk_clone(
					chunk_create(this->ciphertext, this->params->ct_len));
		return TRUE;
	}

	/* initiator action */
	if (!this->secret_key)
	{
		const uint32_t n_x_nb     = this->params->n * this->params->nb;
		const uint32_t log_q      = this->params->log_q;
		const uint32_t seed_A_len = this->params->seed_A_len;
		const uint32_t ss_len     = this->params->ss_len;
		const uint32_t pk_len     = this->params->pk_len;

		uint8_t *pk_seedA, *pk_b, *sk_pos;
		uint16_t B[n_x_nb], S[n_x_nb], E[n_x_nb];
		uint8_t randomness[ss_len + ss_len + seed_A_len];
		uint8_t *randomness_s =      &randomness[0];
		uint8_t *randomness_seedSE = &randomness[ss_len];
		uint8_t *randomness_z =      &randomness[ss_len + ss_len];
		uint8_t seedSE[1 + ss_len];

		this->secret_key = malloc(this->params->sk_len);
		pk_seedA = this->public_key;
		pk_b     = this->public_key + seed_A_len;

		/* Do we need an entropy source? */
		/* TODO */
 		/* Generate the secret value s and the seeds for S, E and seed_A */
		if (!need_drbg(this) ||
			!this->drbg->generate(this->drbg, 2*ss_len + seed_A_len, randomness))
		{
			DBG1(DBG_LIB, "could not generate randomness");
			return FALSE;
		}

 		/* Generate seed_A as part of the public key */
		if (!this->xof->set_seed(this->xof,
								 chunk_create(randomness_z, seed_A_len)) ||
			!this->xof->get_bytes(this->xof, seed_A_len, pk_seedA))
		{
			return FALSE;
		}

		/* Generate S and E, and compute B = A*S + E. Generate A on-the-fly */
		seedSE[0] = 0x5F;
		memcpy(&seedSE[1], randomness_seedSE, ss_len);

		if (!this->xof->set_seed(this->xof, chunk_create(seedSE, 1 + ss_len)) ||
			!this->xof->get_bytes(this->xof,
								  n_x_nb * sizeof(uint16_t), (uint8_t*)S) ||
			!this->xof->get_bytes(this->xof,
								  n_x_nb * sizeof(uint16_t), (uint8_t*)E))
		{
			return FALSE;
		}

		frodo_sample_n(this->params, S, n_x_nb);
		frodo_sample_n(this->params, E, n_x_nb);

		if (!frodo_mul_add_as_plus_e(this->params, B, S, E, this->public_key,
									 this->use_aes))
		{
			return FALSE;
		}

 		/* Encode the second part of the public key */
		frodo_pack(pk_b, pk_len - seed_A_len, B, n_x_nb, log_q);

		/* Add s, pk and S to the secret key */
		sk_pos = this->secret_key;
		memcpy(sk_pos, randomness_s, ss_len);
		sk_pos += ss_len;
		memcpy(sk_pos, this->public_key, pk_len);
		sk_pos += pk_len;
		memcpy(sk_pos, S, n_x_nb * sizeof(uint16_t));
		sk_pos += n_x_nb * sizeof(uint16_t);

		/* Add H(pk) to the secret key */
		if (!this->xof->set_seed(this->xof,
								 chunk_create(this->public_key, pk_len)) ||
			!this->xof->get_bytes(this->xof, ss_len, sk_pos))
		{
			return FALSE;
		}

		/* Cleanup */
		memwipe((uint8_t *)S, n_x_nb * sizeof(uint16_t));
		memwipe((uint8_t *)E, n_x_nb * sizeof(uint16_t));
		memwipe(randomness, ss_len + ss_len + seed_A_len);
		memwipe(seedSE, 1 + ss_len);
	}
	*value = chunk_clone(chunk_create(this->public_key, this->params->pk_len));

	return TRUE;
}


METHOD(key_exchange_t, get_shared_secret, bool,
	private_frodo_t *this, chunk_t *secret)
{
	*secret = chunk_clone(
				chunk_create(this->shared_secret, this->params->ss_len));
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_frodo_t *this, chunk_t value)
{
	/* initiator action */
	if (this->secret_key)
	{
		return set_ciphertext(this, value);
	}

	/* responder action */
	if (value.len != this->params->pk_len)
	{
		DBG1(DBG_LIB, "wrong %N public key size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->params->pk_len);
		return FALSE;
	}
	memcpy(this->public_key, value.ptr, value.len);

	return need_drbg(this) && encaps_shared_secret(this);
}


METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_frodo_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, set_seed, bool,
	private_frodo_t *this, chunk_t value, drbg_t *drbg)
{
	DESTROY_IF(this->drbg);
	this->drbg = drbg->get_ref(drbg);

	return TRUE;
}

METHOD(key_exchange_t, destroy, void,
	private_frodo_t *this)
{
	DESTROY_IF(this->drbg);
	this->xof->destroy(this->xof);

	memwipe(this->secret_key, this->params->sk_len);
	free(this->secret_key);
	memwipe(this->shared_secret, this->params->ss_len);
	free(this->shared_secret);
	free(this->public_key);
	free(this->ciphertext);
	free(this);
}

/*
 * Described in header.
 */
frodo_t *frodo_create(key_exchange_method_t method)
{
	private_frodo_t *this;
	const frodo_params_t *params;
	frodo_kem_type_t id;
	bool use_aes;
	xof_t *xof;

	switch (method)
	{
		case KE_FRODO_SHAKE_L1:
			id = FRODO_KEM_L1;
			use_aes = FALSE;
			break;
		case KE_FRODO_SHAKE_L3:
			id = FRODO_KEM_L3;
			use_aes = FALSE;
			break;
		case KE_FRODO_SHAKE_L5:
			id = FRODO_KEM_L5;
			use_aes = FALSE;
			break;
		case KE_FRODO_AES_L1:
			id = FRODO_KEM_L1;
			use_aes = TRUE;
			break;
		case KE_FRODO_AES_L3:
			id = FRODO_KEM_L3;
			use_aes = TRUE;
			break;
		case KE_FRODO_AES_L5:
			id = FRODO_KEM_L5;
			use_aes = TRUE;
			break;
		default:
			return NULL;
	}
	params = frodo_params_get_by_id(id);

	xof = lib->crypto->create_xof(lib->crypto, params->xof_type);
	if (!xof)
	{
		DBG1(DBG_LIB, "could not instantiate %N", ext_out_function_names,
					   params->xof_type);
		return NULL;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_method = _get_method,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_shared_secret = _get_shared_secret,
				.set_seed = _set_seed,
				.destroy = _destroy,
			},
		},
		.method = method,
		.use_aes = use_aes,
		.params = params,
		.xof = xof,
		.public_key = malloc(params->pk_len),
		.shared_secret = malloc(params->ss_len),
	);

	return &this->public;
}
