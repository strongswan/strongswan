/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "ntru_ke.h"
#include "ntru_drbg.h"

#include "ntru_crypto/ntru_crypto.h"

#include <crypto/diffie_hellman.h>
#include <utils/debug.h>

typedef struct private_ntru_ke_t private_ntru_ke_t;
typedef struct param_set_t param_set_t;

/**
 * Defines an NTRU parameter set by ID or OID
 */
struct param_set_t {
	NTRU_ENCRYPT_PARAM_SET_ID id;
	char oid[3];
	char *name;
};

/* Best bandwidth and speed, no X9.98 compatibility */
static param_set_t param_sets_optimum[] = {
	{ NTRU_EES401EP2,  {0x00, 0x02, 0x10}, "ees401ep2"  },
	{ NTRU_EES439EP1,  {0x00, 0x03, 0x10}, "ees439ep1"  },
	{ NTRU_EES593EP1,  {0x00, 0x05, 0x10}, "ees593ep1"  },
	{ NTRU_EES743EP1,  {0x00, 0x06, 0x10}, "ees743ep1"  }
};

/* X9.98/IEEE 1363.1 parameter sets for best speed */
static param_set_t param_sets_x9_98_speed[] = {
	{ NTRU_EES659EP1,  {0x00, 0x02, 0x06}, "ees659ep1"  },
	{ NTRU_EES761EP1,  {0x00, 0x03, 0x05}, "ees761ep1"  },
	{ NTRU_EES1087EP1, {0x00, 0x05, 0x05}, "ees1087ep1" },
	{ NTRU_EES1499EP1, {0x00, 0x06, 0x05}, "ees1499ep1" }
};

/* X9.98/IEEE 1363.1 parameter sets for best bandwidth (smallest size) */
static param_set_t param_sets_x9_98_bandwidth[] = {
	{ NTRU_EES401EP1,  {0x00, 0x02, 0x04}, "ees401ep1"  },
	{ NTRU_EES449EP1,  {0x00, 0x03, 0x03}, "ees449ep1"  },
	{ NTRU_EES677EP1,  {0x00, 0x05, 0x03}, "ees677ep1"  },
	{ NTRU_EES1087EP2, {0x00, 0x06, 0x03}, "ees1087ep2" }
};

/* X9.98/IEEE 1363.1 parameter sets balancing speed and bandwidth */
static param_set_t param_sets_x9_98_balance[] = {
	{ NTRU_EES541EP1,  {0x00, 0x02, 0x05}, "ees541ep1"  },
	{ NTRU_EES613EP1,  {0x00, 0x03, 0x04}, "ees613ep1"  },
	{ NTRU_EES887EP1,  {0x00, 0x05, 0x04}, "ees887ep1"  },
	{ NTRU_EES1171EP1, {0x00, 0x06, 0x04}, "ees1171ep1" }
};

/**
 * Private data of an ntru_ke_t object.
 */
struct private_ntru_ke_t {
	/**
	 * Public ntru_ke_t interface.
	 */
	ntru_ke_t public;

	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t group;

	/**
	 * NTRU Parameter Set
	 */
	param_set_t *param_set;

	/**
	 * Cryptographical strength in bits of the NTRU Parameter Set
	 */
	u_int32_t strength;

	/**
	 * NTRU Public Key
	 */
	chunk_t pub_key;

	/**
	 * NTRU Private Key
	 */
	chunk_t priv_key;

	/**
	 * NTRU encrypted shared secret
	 */
	chunk_t ciphertext;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * True if peer is responder
	 */
	bool responder;

	/**
	 * True if shared secret is computed
	 */
	bool computed;

	/**
	 * True Random Generator
	 */
	rng_t *entropy;

	/**
	 * Deterministic Random Bit Generator
	 */
    ntru_drbg_t *drbg;
};

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_ntru_ke_t *this, chunk_t *value)
{
    uint16_t pub_key_len, priv_key_len;

	*value = chunk_empty;

	if (this->responder)
	{
		if (this->ciphertext.len)
		{
			*value = chunk_clone(this->ciphertext);
		}
	}
	else
	{
		if (this->pub_key.len == 0)
		{
			/* determine the NTRU public and private key sizes */
			if (ntru_crypto_ntru_encrypt_keygen(this->drbg, this->param_set->id,
								&pub_key_len, NULL,
				 				&priv_key_len, NULL) != NTRU_OK)
			{
				DBG1(DBG_LIB, "error determining NTRU public and private key "
							  "sizes");
				return;
			}
			this->pub_key  = chunk_alloc(pub_key_len);
			this->priv_key = chunk_alloc(priv_key_len);

			/* generate a random NTRU public/private key pair */
		    if (ntru_crypto_ntru_encrypt_keygen(this->drbg, this->param_set->id,
								&pub_key_len, this->pub_key.ptr,
				 				&priv_key_len, this->priv_key.ptr) != NTRU_OK)
			{
				DBG1(DBG_LIB, "NTRU keypair generation failed");
				chunk_free(&this->priv_key);
				chunk_free(&this->pub_key);
				return;
			}
			DBG3(DBG_LIB, "NTRU public key: %B", &this->pub_key);
			DBG4(DBG_LIB, "NTRU private key: %B", &this->priv_key);
		}
		*value = chunk_clone(this->pub_key);
	}
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_ntru_ke_t *this, chunk_t *secret)
{
	if (!this->computed || !this->shared_secret.len)
	{
		*secret = chunk_empty;
		return FAILED;
	}
	*secret = chunk_clone(this->shared_secret);

	return SUCCESS;
}


METHOD(diffie_hellman_t, set_other_public_value, void,
	private_ntru_ke_t *this, chunk_t value)
{
	u_int16_t plaintext_len, ciphertext_len;

	if (this->priv_key.len)
	{
		/* initiator decrypting shared secret */
		if (value.len == 0)
		{
			DBG1(DBG_LIB, "empty NTRU ciphertext");
			return;
		}
		this->ciphertext = chunk_clone(value);
		DBG3(DBG_LIB, "NTRU ciphertext: %B", &this->ciphertext);

		/* determine the size of the maximum plaintext */
    	if (ntru_crypto_ntru_decrypt(this->priv_key.len, this->priv_key.ptr,
								this->ciphertext.len, this->ciphertext.ptr,
								&plaintext_len, NULL) != NTRU_OK)
		{
			DBG1(DBG_LIB, "error determining maximum plaintext size");
			return;
		}
		this->shared_secret = chunk_alloc(plaintext_len);

		/* decrypt the shared secret */
    	if (ntru_crypto_ntru_decrypt(this->priv_key.len, this->priv_key.ptr,
						this->ciphertext.len, this->ciphertext.ptr,
						&plaintext_len, this->shared_secret.ptr) != NTRU_OK)
		{
			DBG1(DBG_LIB, "NTRU decryption of shared secret failed");
			chunk_free(&this->shared_secret);
			return;
		}
		this->shared_secret.len = plaintext_len;
		this->computed = TRUE;
	}
	else
	{
		/* responder generating and encrypting the shared secret */
		this->responder = TRUE;

		/* check the NTRU public key format */
		if (value.len < 5 || value.ptr[0] != 1 || value.ptr[1] != 3)
		{
			DBG1(DBG_LIB, "received NTRU public key with invalid header");
			return;
		}
		if (!memeq(value.ptr + 2, this->param_set->oid, 3))
		{
			DBG1(DBG_LIB, "received NTRU public key with wrong OID");
			return;
		}
		this->pub_key = chunk_clone(value);

		/* shared secret size is chosen as twice the cryptographical strength */
		this->shared_secret = chunk_alloc(2 * this->strength / BITS_PER_BYTE);

		/* generate the random shared secret */
		if (!this->drbg->generate(this->drbg, this->strength,
				this->shared_secret.len, this->shared_secret.ptr))
		{
			DBG1(DBG_LIB, "generation of shared secret failed");
			chunk_free(&this->shared_secret);
			return;
		}
		this->computed = TRUE;

		/* determine the size of the ciphertext */
		if (ntru_crypto_ntru_encrypt(this->drbg,
							this->pub_key.len,	this->pub_key.ptr,
							this->shared_secret.len, this->shared_secret.ptr,
                            &ciphertext_len, NULL) != NTRU_OK)
		{
			DBG1(DBG_LIB, "error determining ciphertext size");
			return;
		}
		this->ciphertext = chunk_alloc(ciphertext_len);

		/* encrypt the shared secret */
		if (ntru_crypto_ntru_encrypt(this->drbg,
							this->pub_key.len,	this->pub_key.ptr,
							this->shared_secret.len, this->shared_secret.ptr,
                            &ciphertext_len, this->ciphertext.ptr) != NTRU_OK)
		{
			DBG1(DBG_LIB, "NTRU encryption of shared secret failed");
			chunk_free(&this->ciphertext);
			return;
		}
		DBG3(DBG_LIB, "NTRU ciphertext: %B", &this->ciphertext);
	}
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_ntru_ke_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_ntru_ke_t *this)
{
	this->drbg->destroy(this->drbg);
	this->entropy->destroy(this->entropy);
	chunk_free(&this->pub_key);
	chunk_free(&this->ciphertext);
	chunk_clear(&this->priv_key);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header.
 */
ntru_ke_t *ntru_ke_create(diffie_hellman_group_t group, chunk_t g, chunk_t p)
{
	private_ntru_ke_t *this;
	param_set_t *param_sets, *param_set;
	rng_t *entropy;
	ntru_drbg_t *drbg;
	char *parameter_set;
	u_int32_t strength;

	parameter_set = lib->settings->get_str(lib->settings,
						"%s.plugins.ntru.parameter_set", "optimum", lib->ns);

	if (streq(parameter_set, "x9_98_speed"))
	{
		param_sets = param_sets_x9_98_speed;
	}
	else if (streq(parameter_set, "x9_98_bandwidth"))
	{
		param_sets = param_sets_x9_98_bandwidth;
	}
	else if (streq(parameter_set, "x9_98_balance"))
	{
		param_sets = param_sets_x9_98_balance;
	}
	else
	{
		param_sets = param_sets_optimum;
	}

	switch (group)
	{
		case NTRU_112_BIT:
			strength = 112;
			param_set = &param_sets[0];
			break;
		case NTRU_128_BIT:
			strength = 128;
			param_set = &param_sets[1];
			break;
		case NTRU_192_BIT:
			strength = 192;
			param_set = &param_sets[2];
			break;
		case NTRU_256_BIT:
			strength = 256;
			param_set = &param_sets[3];
			break;
		default:
			return NULL;
	}
	DBG1(DBG_LIB, "%u bit %s NTRU parameter set %s selected", strength,
				   parameter_set, param_set->name);

	entropy = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
	if (!entropy)
	{
		DBG1(DBG_LIB, "could not attach entropy source for DRBG");
		return NULL;
	}

	drbg = ntru_drbg_create(strength, chunk_from_str("IKE NTRU-KE"), entropy);
	if (!drbg)
 	{
		DBG1(DBG_LIB, "could not instantiate DRBG at %u bit security", strength);
		entropy->destroy(entropy);
        return NULL;
	}

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
		.group = group,
		.param_set = param_set,
		.strength = strength,
		.entropy = entropy,
		.drbg = drbg,
	);

	return &this->public;
}

