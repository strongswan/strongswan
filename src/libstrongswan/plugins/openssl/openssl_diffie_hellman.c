/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include <openssl/dh.h>

#include "openssl_diffie_hellman.h"

#include <debug.h>

typedef struct modulus_entry_t modulus_entry_t;

/**
 * Entry of the modulus list.
 */
struct modulus_entry_t {
	/**
	 * Group number as it is defined in file transform_substructure.h.
	 */
	diffie_hellman_group_t group;

	/**
	 * Pointer to the function to get the modulus.
	 */
	BIGNUM *(*get_prime)(BIGNUM *bn);

	/*
	 * Optimum length of exponent in bits.
	 */
	long opt_exponent_len;

	/*
	 * Generator value.
	 */
	u_int16_t generator;
};

/**
 * All supported modulus values - optimum exponent size according to RFC 3526.
 */
static modulus_entry_t modulus_entries[] = {
	{MODP_768_BIT,  get_rfc2409_prime_768,  256, 2},
	{MODP_1024_BIT, get_rfc2409_prime_1024, 256, 2},
	{MODP_1536_BIT, get_rfc3526_prime_1536, 256, 2},
	{MODP_2048_BIT, get_rfc3526_prime_2048, 384, 2},
	{MODP_3072_BIT, get_rfc3526_prime_3072, 384, 2},
	{MODP_4096_BIT, get_rfc3526_prime_4096, 512, 2},
	{MODP_6144_BIT, get_rfc3526_prime_6144, 512, 2},
	{MODP_8192_BIT, get_rfc3526_prime_8192, 512, 2},
};

typedef struct private_openssl_diffie_hellman_t private_openssl_diffie_hellman_t;

/**
 * Private data of an openssl_diffie_hellman_t object.
 */
struct private_openssl_diffie_hellman_t {
	/**
	 * Public openssl_diffie_hellman_t interface.
	 */
	openssl_diffie_hellman_t public;

	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t group;

	/**
	 * Diffie Hellman object
	 */
	DH *dh;

	/**
	 * Other public value
	 */
	BIGNUM *pub_key;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * True if shared secret is computed
	 */
	bool computed;
};

/**
 * Implementation of openssl_diffie_hellman_t.get_my_public_value.
 */
static void get_my_public_value(private_openssl_diffie_hellman_t *this,
								chunk_t *value)
{
	*value = chunk_alloc(DH_size(this->dh));
	memset(value->ptr, 0, value->len);
	BN_bn2bin(this->dh->pub_key,
			  value->ptr + value->len - BN_num_bytes(this->dh->pub_key));
}

/**
 * Implementation of openssl_diffie_hellman_t.get_shared_secret.
 */
static status_t get_shared_secret(private_openssl_diffie_hellman_t *this,
								  chunk_t *secret)
{
	if (!this->computed)
	{
		return FAILED;
	}
	/* shared secret should requires a len according the DH group */
	*secret = chunk_alloc(DH_size(this->dh));
	memset(secret->ptr, 0, secret->len);
	memcpy(secret->ptr + secret->len - this->shared_secret.len,
		   this->shared_secret.ptr, this->shared_secret.len);

	return SUCCESS;
}


/**
 * Implementation of openssl_diffie_hellman_t.set_other_public_value.
 */
static void set_other_public_value(private_openssl_diffie_hellman_t *this,
								   chunk_t value)
{
	int len;

	BN_bin2bn(value.ptr, value.len, this->pub_key);
	chunk_clear(&this->shared_secret);
	this->shared_secret.ptr = malloc(DH_size(this->dh));
	memset(this->shared_secret.ptr, 0xFF, this->shared_secret.len);
	len = DH_compute_key(this->shared_secret.ptr, this->pub_key, this->dh);
	if (len < 0)
	{
		DBG1("DH shared secret computation failed");
		return;
	}
	this->shared_secret.len = len;
	this->computed = TRUE;
}

/**
 * Implementation of openssl_diffie_hellman_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_openssl_diffie_hellman_t *this)
{
	return this->group;
}

/**
 * Lookup the modulus in modulo table
 */
static status_t set_modulus(private_openssl_diffie_hellman_t *this)
{
	int i;
	bool ansi_x9_42;

	ansi_x9_42 = lib->settings->get_bool(lib->settings,
										 "libstrongswan.dh_exponent_ansi_x9_42", TRUE);

	for (i = 0; i < (sizeof(modulus_entries) / sizeof(modulus_entry_t)); i++)
	{
		if (modulus_entries[i].group == this->group)
		{
			this->dh->p = modulus_entries[i].get_prime(NULL);
			this->dh->g = BN_new();
			BN_set_word(this->dh->g, modulus_entries[i].generator);
			if (!ansi_x9_42)
			{
				this->dh->length = modulus_entries[i].opt_exponent_len;
			}
			return SUCCESS;
		}
	}
	return NOT_FOUND;
}

/**
 * Implementation of openssl_diffie_hellman_t.destroy.
 */
static void destroy(private_openssl_diffie_hellman_t *this)
{
	BN_clear_free(this->pub_key);
	DH_free(this->dh);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header.
 */
openssl_diffie_hellman_t *openssl_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_openssl_diffie_hellman_t *this = malloc_thing(private_openssl_diffie_hellman_t);

	this->public.dh.get_shared_secret = (status_t (*)(diffie_hellman_t *, chunk_t *)) get_shared_secret;
	this->public.dh.set_other_public_value = (void (*)(diffie_hellman_t *, chunk_t )) set_other_public_value;
	this->public.dh.get_my_public_value = (void (*)(diffie_hellman_t *, chunk_t *)) get_my_public_value;
	this->public.dh.get_dh_group = (diffie_hellman_group_t (*)(diffie_hellman_t *)) get_dh_group;
	this->public.dh.destroy = (void (*)(diffie_hellman_t *)) destroy;

	this->dh = DH_new();
	if (!this->dh)
	{
		free(this);
		return NULL;
	}

	this->group = group;
	this->computed = FALSE;
	this->pub_key = BN_new();
	this->shared_secret = chunk_empty;

	/* find a modulus according to group */
	if (set_modulus(this) != SUCCESS)
	{
		destroy(this);
		return NULL;
	}

	/* generate my public and private values */
	if (!DH_generate_key(this->dh))
	{
		destroy(this);
		return NULL;
	}
	DBG2("size of DH secret exponent: %d bits", BN_num_bits(this->dh->priv_key));

	return &this->public;
}
