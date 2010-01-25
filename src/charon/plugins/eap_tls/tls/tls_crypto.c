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

typedef struct private_tls_crypto_t private_tls_crypto_t;

/**
 * Private data of an tls_crypto_t object.
 */
struct private_tls_crypto_t {

	/**
	 * Public tls_crypto_t interface.
	 */
	tls_crypto_t public;
};

METHOD(tls_crypto_t, get_cipher_suites, int,
	private_tls_crypto_t *this, tls_cipher_suite_t **suites)
{
	encryption_algorithm_t encr;
	integrity_algorithm_t mac;
	enumerator_t *encrs, *macs;
	tls_cipher_suite_t buf[64];
	int count = 0, i, j, res = 0;

	/* we assume that we support RSA, but no DHE yet */
	macs = lib->crypto->create_signer_enumerator(lib->crypto);
	while (macs->enumerate(macs, &mac))
	{
		switch (mac)
		{
			case AUTH_HMAC_SHA1_160:
				buf[count++] = TLS_RSA_WITH_NULL_SHA;
				break;
			case AUTH_HMAC_SHA2_256_256:
				buf[count++] = TLS_RSA_WITH_NULL_SHA256;
				break;
			case AUTH_HMAC_MD5_128:
				buf[count++] = TLS_RSA_WITH_NULL_MD5;
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
							buf[count++] = TLS_RSA_WITH_AES_128_CBC_SHA;
							buf[count++] = TLS_RSA_WITH_AES_256_CBC_SHA;
							break;
						case AUTH_HMAC_SHA2_256_256:
							buf[count++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
							buf[count++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
							break;
						default:
							break;
					}
					break;
				case ENCR_3DES:
					switch (mac)
					{
						case AUTH_HMAC_SHA1_160:
							buf[count++] = TLS_RSA_WITH_3DES_EDE_CBC_SHA;
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
	*suites = malloc(sizeof(tls_cipher_suite_t) * count);
	for (i = 0; i < count; i++)
	{
		bool match = FALSE;

		for (j = 0; j < res; j++)
		{
			if (buf[i] == (*suites)[j])
			{
				match = TRUE;
				break;
			}
		}
		if (!match)
		{
			(*suites)[res++] = buf[i];
		}
	}
	return res;
}


METHOD(tls_crypto_t, destroy, void,
	private_tls_crypto_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_crypto_t *tls_crypto_create()
{
	private_tls_crypto_t *this;

	INIT(this,
		.public = {
			.get_cipher_suites = _get_cipher_suites,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
