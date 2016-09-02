/*
 * Copyright (C) 2016 Codrut Cristian Grosu (codrut.cristian.grosu@gmail.com)
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


#include "save_keys_listener.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct private_save_keys_listener_t private_save_keys_listener_t;

typedef struct map_algorithm_name_t map_algorithm_name_t;

/**
 * Default path for the directory where the decryption tables will be stored.
 */
static char *default_path = NULL;

/**
 * Private data of an save_keys_listener_t object.
 */
struct private_save_keys_listener_t {

	/**
	 * Public save_keys_listener_t interface.
	 */
	save_keys_listener_t public;

	/**
	 * SPI_i for IKEv2.
	 */
	chunk_t spi_i;

	/**
	 * SPI_r for IKEv2.
	 */
	chunk_t spi_r;

	/**
	 * Path to the directory where the decryption tables will be stored.
	 */
	char *directory_path;
};

/**
 * Mapping strongSwan names with wireshark names.
 */
struct map_algorithm_name_t {
	/**
	 * Identifier specified in strongSwan
	 */
	int strongswan;

	/**
	 * Key size identifier
	 */
	int size;

	/**
	 * Name of the algorithm in wireshark
	 */
	char *name;
};

/**
 * IKE Algorithms for encryption
 */
static map_algorithm_name_t ike_encryption_algs[] = {
	{ENCR_3DES,		-1,	"3DES [RFC2451]"},
	{ENCR_AES_CBC,		128,	"AES-CBC-128 [RFC3602]"},
	{ENCR_AES_CBC,		192,	"AES-CBC-192 [RFC3602]"},
	{ENCR_AES_CBC,		256,	"AES-CBC-256 [RFC3602]"},
	{ENCR_NULL,		-1,	"NULL [RFC2410]"},
};

/**
 * Expands the name of encryption algorithms for IKE decryption table.
 */
static inline char *expand_enc_name(uint16_t enc_alg, uint16_t size)
{
	unsigned int i;
	for (i = 0; i < countof(ike_encryption_algs); i ++)
	{
		if (ike_encryption_algs[i].size == -1 ||
			ike_encryption_algs[i].size == size)
		{
			if (ike_encryption_algs[i].strongswan == enc_alg)
			{
				return ike_encryption_algs[i].name;
			}
		}
	}
	return NULL;
}

/**
 * See header.
 */
save_keys_listener_t *save_keys_listener_create()
{
	private_save_keys_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
			},
		}
	);

	this->directory_path = lib->settings->get_str(lib->settings,
							"%s.plugins.save-keys.directory_path",
								default_path, lib->ns);
	return &this->public;
}
