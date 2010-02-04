/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "tls_crypto.h"

#include <daemon.h>

typedef struct private_tls_crypto_t private_tls_crypto_t;

/**
 * Private data of an tls_crypto_t object.
 */
struct private_tls_crypto_t {

	/**
	 * Public tls_crypto_t interface.
	 */
	tls_crypto_t public;

	/**
	 * List of supported/acceptable cipher suites
	 */
	tls_cipher_suite_t *suites;

	/**
	 * Number of supported suites
	 */
	int suite_count;

	/**
	 * Selected cipher suite
	 */
	tls_cipher_suite_t suite;

	/**
	 * TLS context
	 */
	tls_t *tls;

	/**
	 * Connection state TLS PRF
	 */
	tls_prf_t *prf;
};

/**
 * Initialize the cipher suite list
 */
static void build_cipher_suite_list(private_tls_crypto_t *this)
{
	encryption_algorithm_t encr;
	integrity_algorithm_t mac;
	enumerator_t *encrs, *macs;
	tls_cipher_suite_t supported[64], unique[64];
	int count = 0, i, j;

	/* we assume that we support RSA, but no DHE yet */
	macs = lib->crypto->create_signer_enumerator(lib->crypto);
	while (macs->enumerate(macs, &mac))
	{
		switch (mac)
		{
			case AUTH_HMAC_SHA1_160:
				supported[count++] = TLS_RSA_WITH_NULL_SHA;
				break;
			case AUTH_HMAC_SHA2_256_256:
				supported[count++] = TLS_RSA_WITH_NULL_SHA256;
				break;
			case AUTH_HMAC_MD5_128:
				supported[count++] = TLS_RSA_WITH_NULL_MD5;
				break;
			default:
				break;
		}
		encrs = lib->crypto->create_crypter_enumerator(lib->crypto);
		while (encrs->enumerate(encrs, &encr))
		{
			switch (encr)
			{
				case ENCR_AES_CBC:
					switch (mac)
					{
						case AUTH_HMAC_SHA1_160:
							supported[count++] = TLS_RSA_WITH_AES_128_CBC_SHA;
							supported[count++] = TLS_RSA_WITH_AES_256_CBC_SHA;
							break;
						case AUTH_HMAC_SHA2_256_256:
							supported[count++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
							supported[count++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
							break;
						default:
							break;
					}
					break;
				case ENCR_3DES:
					switch (mac)
					{
						case AUTH_HMAC_SHA1_160:
							supported[count++] = TLS_RSA_WITH_3DES_EDE_CBC_SHA;
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
		}
		encrs->destroy(encrs);
	}
	macs->destroy(macs);

	/* remove duplicates */
	this->suite_count = 0;
	for (i = 0; i < count; i++)
	{
		bool match = FALSE;

		for (j = 0; j < this->suite_count; j++)
		{
			if (supported[i] == unique[j])
			{
				match = TRUE;
				break;
			}
		}
		if (!match)
		{
			unique[this->suite_count++] = supported[i];
		}
	}
	free(this->suites);
	this->suites = malloc(sizeof(tls_cipher_suite_t) * this->suite_count);
	memcpy(this->suites, unique, sizeof(tls_cipher_suite_t) * this->suite_count);
}

METHOD(tls_crypto_t, get_cipher_suites, int,
	private_tls_crypto_t *this, tls_cipher_suite_t **suites)
{
	*suites = this->suites;
	return this->suite_count;
}

METHOD(tls_crypto_t, select_cipher_suite, tls_cipher_suite_t,
	private_tls_crypto_t *this, tls_cipher_suite_t *suites, int count)
{
	int i, j;

	for (i = 0; i < this->suite_count; i++)
	{
		for (j = 0; j < count; j++)
		{
			if (this->suites[i] == suites[j])
			{
				this->suite = this->suites[i];
				return this->suite;
			}
		}
	}
	return 0;
}

METHOD(tls_crypto_t, derive_master_secret, void,
	private_tls_crypto_t *this, chunk_t premaster,
	chunk_t client_random, chunk_t server_random)
{
	if (!this->prf)
	{
		if (this->tls->get_version(this->tls) < TLS_1_2)
		{
			this->prf = tls_prf_create_10();
		}
		else
		{
			switch (this->suite)
			{
				case TLS_RSA_WITH_NULL_MD5:
					this->prf = tls_prf_create_12(PRF_HMAC_MD5);
					break;
				case TLS_RSA_WITH_AES_128_CBC_SHA:
				case TLS_RSA_WITH_AES_256_CBC_SHA:
				case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
				case TLS_RSA_WITH_NULL_SHA:
					this->prf = tls_prf_create_12(PRF_HMAC_SHA1);
					break;
				case TLS_RSA_WITH_AES_128_CBC_SHA256:
				case TLS_RSA_WITH_NULL_SHA256:
					this->prf = tls_prf_create_12(PRF_HMAC_SHA2_256);
					break;
				default:
					DBG1(DBG_IKE, "PRF for cipher suite unknown");
					break;
			}
		}
	}
	if (this->prf)
	{
		char master[48];
		chunk_t seed;

		seed = chunk_cata("cc", client_random, server_random);
		this->prf->set_key(this->prf, premaster);
		this->prf->get_bytes(this->prf, "master secret", seed,
							 sizeof(master), master);

		this->prf->set_key(this->prf, chunk_from_thing(master));
		memset(master, 0, sizeof(master));
	}
}

METHOD(tls_crypto_t, get_prf, tls_prf_t*,
	private_tls_crypto_t *this)
{

	return this->prf;
}

METHOD(tls_crypto_t, destroy, void,
	private_tls_crypto_t *this)
{
	free(this->suites);
	DESTROY_IF(this->prf);
	free(this);
}

/**
 * See header
 */
tls_crypto_t *tls_crypto_create(tls_t *tls)
{
	private_tls_crypto_t *this;

	INIT(this,
		.public = {
			.get_cipher_suites = _get_cipher_suites,
			.select_cipher_suite = _select_cipher_suite,
			.derive_master_secret = _derive_master_secret,
			.get_prf = _get_prf,
			.destroy = _destroy,
		},
		.tls = tls,
	);

	build_cipher_suite_list(this);

	return &this->public;
}
