/*
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <gmp.h>

#include "gmp_diffie_hellman.h"

#include <debug.h>

#ifdef HAVE_MPZ_POWM_SEC
# undef mpz_powm
# define mpz_powm mpz_powm_sec
#endif

typedef struct private_gmp_diffie_hellman_t private_gmp_diffie_hellman_t;

/**
 * Private data of an gmp_diffie_hellman_t object.
 */
struct private_gmp_diffie_hellman_t {
	/**
	 * Public gmp_diffie_hellman_t interface.
	 */
	gmp_diffie_hellman_t public;

	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t group;

	/*
	 * Generator value.
	 */
	mpz_t g;

	/**
	 * My private value.
	 */
	mpz_t xa;

	/**
	 * My public value.
	 */
	mpz_t ya;

	/**
	 * Other public value.
	 */
	mpz_t yb;

	/**
	 * Shared secret.
	 */
	mpz_t zz;

	/**
	 * Modulus.
	 */
	mpz_t p;

	/**
	 * Modulus length.
	 */
	size_t p_len;

	/**
	 * True if shared secret is computed and stored in my_public_value.
	 */
	bool computed;
};

/**
 * Implementation of gmp_diffie_hellman_t.set_other_public_value.
 */
static void set_other_public_value(private_gmp_diffie_hellman_t *this, chunk_t value)
{
	mpz_t p_min_1;

	mpz_init(p_min_1);
	mpz_sub_ui(p_min_1, this->p, 1);

	mpz_import(this->yb, value.len, 1, 1, 1, 0, value.ptr);

	/* check public value:
	 * 1. 0 or 1 is invalid as 0^a = 0 and 1^a = 1
	 * 2. a public value larger or equal the modulus is invalid */
	if (mpz_cmp_ui(this->yb, 1) > 0 &&
		mpz_cmp(this->yb, p_min_1) < 0)
	{
#ifdef EXTENDED_DH_TEST
		/* 3. test if y ^ q mod p = 1, where q = (p - 1)/2. */
		mpz_t q, one;

		mpz_init(q);
		mpz_init(one);
		mpz_fdiv_q_2exp(q, p_min_1, 1);
		mpz_powm(one, this->yb, q, this->p);
		mpz_clear(q);
		if (mpz_cmp_ui(one, 1) == 0)
		{
			mpz_powm(this->zz, this->yb, this->xa, this->p);
			this->computed = TRUE;
		}
		else
		{
			DBG1("public DH value verification failed: y ^ q mod p != 1");
		}
		mpz_clear(one);
#else
		mpz_powm(this->zz, this->yb, this->xa, this->p);
		this->computed = TRUE;
#endif
	}
	else
	{
		DBG1("public DH value verification failed: y < 2 || y > p - 1 ");
	}
	mpz_clear(p_min_1);
}

/**
 * Implementation of gmp_diffie_hellman_t.get_my_public_value.
 */
static void get_my_public_value(private_gmp_diffie_hellman_t *this,chunk_t *value)
{
	value->len = this->p_len;
	value->ptr = mpz_export(NULL, NULL, 1, value->len, 1, 0, this->ya);
	if (value->ptr == NULL)
	{
		value->len = 0;
	}
}

/**
 * Implementation of gmp_diffie_hellman_t.get_shared_secret.
 */
static status_t get_shared_secret(private_gmp_diffie_hellman_t *this, chunk_t *secret)
{
	if (!this->computed)
	{
		return FAILED;
	}
	secret->len = this->p_len;
	secret->ptr = mpz_export(NULL, NULL, 1, secret->len, 1, 0, this->zz);
	if (secret->ptr == NULL)
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of gmp_diffie_hellman_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_gmp_diffie_hellman_t *this)
{
	return this->group;
}

/**
 * Implementation of gmp_diffie_hellman_t.destroy.
 */
static void destroy(private_gmp_diffie_hellman_t *this)
{
	mpz_clear(this->p);
	mpz_clear(this->xa);
	mpz_clear(this->ya);
	mpz_clear(this->yb);
	mpz_clear(this->zz);
	mpz_clear(this->g);
	free(this);
}

/*
 * Described in header.
 */
gmp_diffie_hellman_t *gmp_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_gmp_diffie_hellman_t *this = malloc_thing(private_gmp_diffie_hellman_t);
	diffie_hellman_params_t *params;
	rng_t *rng;
	chunk_t random;

	/* public functions */
	this->public.dh.get_shared_secret = (status_t (*)(diffie_hellman_t *, chunk_t *)) get_shared_secret;
	this->public.dh.set_other_public_value = (void (*)(diffie_hellman_t *, chunk_t )) set_other_public_value;
	this->public.dh.get_my_public_value = (void (*)(diffie_hellman_t *, chunk_t *)) get_my_public_value;
	this->public.dh.get_dh_group = (diffie_hellman_group_t (*)(diffie_hellman_t *)) get_dh_group;
	this->public.dh.destroy = (void (*)(diffie_hellman_t *)) destroy;

	/* private variables */
	this->group = group;
	mpz_init(this->p);
	mpz_init(this->yb);
	mpz_init(this->ya);
	mpz_init(this->xa);
	mpz_init(this->zz);
	mpz_init(this->g);

	this->computed = FALSE;

	params = diffie_hellman_get_params(this->group);
	if (!params)
	{
		destroy(this);
		return NULL;
	}
	mpz_import(this->p, params->prime_len, 1, 1, 1, 0, params->prime);
	this->p_len = params->prime_len;
	mpz_set_ui(this->g, params->generator);

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1("no RNG found for quality %N", rng_quality_names, RNG_STRONG);
		destroy(this);
		return NULL;
	}

	rng->allocate_bytes(rng, params->exp_len, &random);
	rng->destroy(rng);

	if (params->exp_len == this->p_len)
	{
		/* achieve bitsof(p)-1 by setting MSB to 0 */
		*random.ptr &= 0x7F;
	}
	mpz_import(this->xa, random.len, 1, 1, 1, 0, random.ptr);
	chunk_free(&random);
	DBG2("size of DH secret exponent: %u bits", mpz_sizeinbase(this->xa, 2));

	mpz_powm(this->ya, this->g, this->xa, this->p);

	return &this->public;
}

