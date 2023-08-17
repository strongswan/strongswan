/*
 * Copyright (C) 2018-2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
 *
 * Based on public domain code by Erdem Alkim, Léo Ducas, Thomas Pöppelmann,
 * and Peter Schwabe.
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

#include "oqs_kem.h"
#include "oqs_drbg.h"

#include <utils/debug.h>

#include <oqs/oqs.h>

typedef struct private_oqs_kem_t private_oqs_kem_t;

/**
 * Private data of an oqs_kem_t object.
 */
struct private_oqs_kem_t {

	/**
	 * Public oqs_kem_t interface.
	 */
	oqs_kem_t public;

	/**
	 * Key exchange method
	 */
	key_exchange_method_t method;

	/**
	 * Internal OQS_KEM object
	 */
	OQS_KEM *kem;

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
	 * Deterministic Random Bit Generator (DRBG)
	 */
	drbg_t *drbg;

};

/**
 * Generate the shared secret and encrypt it with the configured public key
 */
static bool encaps_shared_secret(private_oqs_kem_t *this)
{
	OQS_STATUS rc;

	if (!this->ciphertext)
	{
		this->ciphertext = malloc(this->kem->length_ciphertext);
	}

	rc = OQS_KEM_encaps(this->kem, this->ciphertext, this->shared_secret,
						this->public_key);
	if (rc != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "%N encapsulation failed",
			 key_exchange_method_names, this->method);
		return FALSE;
	}
	return TRUE;
}

/**
 * Set the ciphertext and decrypt the shared secret using the secret key
 */
static bool set_ciphertext(private_oqs_kem_t *this, chunk_t value)
{
	OQS_STATUS rc;

	if (value.len != this->kem->length_ciphertext)
	{
		DBG1(DBG_LIB, "wrong %N ciphertext size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->kem->length_ciphertext);
		return FALSE;
	}

	rc = OQS_KEM_decaps(this->kem, this->shared_secret, value.ptr,
						this->secret_key);
	if (rc != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "%N decapsulation failed",
			 key_exchange_method_names, this->method);
		return FALSE;
	}

	return TRUE;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_oqs_kem_t *this, chunk_t *value)
{
	OQS_STATUS rc;

	oqs_drbg_set(this->drbg);

	/* responder action */
	if (this->ciphertext)
	{
		*value = chunk_clone(chunk_create(this->ciphertext,
										  this->kem->length_ciphertext));
		return TRUE;
	}

	/* initiator action */
	if (!this->secret_key)
	{
		this->secret_key = malloc(this->kem->length_secret_key);
		rc = OQS_KEM_keypair(this->kem, this->public_key, this->secret_key);
		if (rc != OQS_SUCCESS)
		{
			DBG1(DBG_LIB, "%N keypair generation failed",
				 key_exchange_method_names, this->method);
			return FALSE;
		}
	}
	*value = chunk_clone(chunk_create(this->public_key,
									  this->kem->length_public_key));
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_oqs_kem_t *this, chunk_t value)
{
	oqs_drbg_set(this->drbg);

	/* initiator action */
	if (this->secret_key)
	{
		return set_ciphertext(this, value);
	}

	/* responder action */
	if (value.len != this->kem->length_public_key)
	{
		DBG1(DBG_LIB, "wrong %N public key size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->kem->length_public_key);
		return FALSE;
	}
	memcpy(this->public_key, value.ptr, value.len);

	return encaps_shared_secret(this);
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_oqs_kem_t *this, chunk_t *secret)
{
	*secret = chunk_clone(chunk_create(this->shared_secret,
									   this->kem->length_shared_secret));
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_oqs_kem_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, set_seed, bool,
	private_oqs_kem_t *this, chunk_t value, drbg_t *drbg)
{
	if (!drbg)
	{
		return FALSE;
	}
	DESTROY_IF(this->drbg);
	this->drbg = drbg->get_ref(drbg);
	OQS_randombytes_custom_algorithm(oqs_drbg_rand);

	return TRUE;
}

METHOD(key_exchange_t, destroy, void,
	private_oqs_kem_t *this)
{
	DESTROY_IF(this->drbg);
	memwipe(this->secret_key, this->kem->length_secret_key);
	free(this->secret_key);
	memwipe(this->shared_secret, this->kem->length_shared_secret);
	free(this->shared_secret);
	OQS_KEM_free(this->kem);
	free(this->public_key);
	free(this->ciphertext);
	free(this);
}

/*
 * Described in header.
 */
oqs_kem_t *oqs_kem_create(key_exchange_method_t method)
{
	private_oqs_kem_t *this;
	char *kem_alg = NULL;
	OQS_KEM *kem;

	switch (method)
	{
		case KE_KYBER_L1:
			kem_alg = OQS_KEM_alg_kyber_512;
			break;
		case KE_KYBER_L3:
			kem_alg = OQS_KEM_alg_kyber_768;
			break;
		case KE_KYBER_L5:
			kem_alg = OQS_KEM_alg_kyber_1024;
			break;
		case KE_BIKE_L1:
			kem_alg = OQS_KEM_alg_bike_l1;
			break;
		case KE_BIKE_L3:
			kem_alg = OQS_KEM_alg_bike_l3;
			break;
		case KE_BIKE_L5:
			kem_alg = OQS_KEM_alg_bike_l5;
			break;
		case KE_FRODO_AES_L1:
			kem_alg = OQS_KEM_alg_frodokem_640_aes;
			break;
		case KE_FRODO_AES_L3:
			kem_alg = OQS_KEM_alg_frodokem_976_aes;
			break;
		case KE_FRODO_AES_L5:
			kem_alg = OQS_KEM_alg_frodokem_1344_aes;
			break;
		case KE_FRODO_SHAKE_L1:
			kem_alg = OQS_KEM_alg_frodokem_640_shake;
			break;
		case KE_FRODO_SHAKE_L3:
			kem_alg = OQS_KEM_alg_frodokem_976_shake;
			break;
		case KE_FRODO_SHAKE_L5:
			kem_alg = OQS_KEM_alg_frodokem_1344_shake;
			break;
		case KE_HQC_L1:
			kem_alg = OQS_KEM_alg_hqc_128;
			break;
		case KE_HQC_L3:
			kem_alg = OQS_KEM_alg_hqc_192;
			break;
		case KE_HQC_L5:
			kem_alg = OQS_KEM_alg_hqc_256;
			break;
		default:
			return NULL;
	}

	if (OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl) != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "OQS RNG could not be switched to openssl");
		return NULL;
	}

	kem = OQS_KEM_new(kem_alg);
	if (!kem)
	{
		DBG1(DBG_LIB, "OQS KEM '%s' not available", kem_alg);
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
		.kem = kem,
		.public_key = malloc(kem->length_public_key),
		.shared_secret = malloc(kem->length_shared_secret),
	);
	memset(this->shared_secret, 0x00, kem->length_shared_secret);

	return &this->public;
}
