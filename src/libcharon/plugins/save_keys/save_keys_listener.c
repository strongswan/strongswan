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
 * Name for ikev2 decryption table file
 */
static char *ikev2_name = "ikev2_decryption_table";

/**
 * Name for ikev1 decryption table file
 */
static char *ikev1_name = "ikev1_decryption_table";

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
 * IKE Algorithms for integrity
 */
static map_algorithm_name_t ike_integrity_algs[] = {
	{AUTH_HMAC_MD5_96,		-1,	"HMAC_MD5_96 [RFC2403]"},
	{AUTH_HMAC_SHA1_96,		-1,	"HMAC_SHA1_96 [RFC2404]"},
	{AUTH_HMAC_SHA2_256_96,		-1,	"HMAC_SHA2_256_96 [draft-ietf-ipsec-ciph-sha-256-00]"},
	{AUTH_HMAC_SHA2_512_256,	-1,	"HMAC_SHA2_512_256 [RFC4868]"},
	{AUTH_HMAC_SHA2_384_192,	-1,	"HMAC_SHA2_384_192 [RFC4868]"},
	{AUTH_HMAC_SHA2_256_128,	-1,	"HMAC_SHA2_256_128 [RFC4868]"},
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
 * Expands the name of integrity algorithms for IKE decryption table.
 */
static inline char *expand_int_name(uint16_t int_alg)
{
	unsigned int i;
	for (i = 0; i < countof(ike_integrity_algs); i ++)
	{
		if (ike_integrity_algs[i].strongswan == int_alg)
		{
			return ike_integrity_algs[i].name;
		}
	}
	return NULL;
}

METHOD(listener_t, send_spis, bool,
	private_save_keys_listener_t *this, chunk_t spi_i, chunk_t spi_r)
{
	if (this->spi_i.ptr)
	{
		chunk_free(&this->spi_i);
	}
	if (this->spi_r.ptr)
	{
		chunk_free(&this->spi_r);
	}
	this->spi_i = chunk_clone(spi_i);
	this->spi_r = chunk_clone(spi_r);
	return TRUE;
}

METHOD(listener_t, save_ike_keys, bool,
	private_save_keys_listener_t *this, ike_version_t ike_version,
	chunk_t sk_ei, chunk_t sk_er, chunk_t sk_ai, chunk_t sk_ar, uint16_t enc_alg,
	uint16_t key_size, uint16_t int_alg)
{
	char *buffer_enc_alg = NULL, *buffer_int_alg = NULL;
	FILE *ikev2_file, *ikev1_file;
	char *path_ikev2 = NULL, *path_ikev1 = NULL;

	if (this->directory_path)
	{
		path_ikev2 = malloc (strlen(this->directory_path) + strlen(ikev2_name) + 1);
		path_ikev1 = malloc (strlen(this->directory_path) + strlen(ikev1_name) + 1);
		strcpy(path_ikev2, this->directory_path);
		strcat(path_ikev2, ikev2_name);
		strcpy(path_ikev1, this->directory_path);
		strcat(path_ikev1, ikev1_name);

		if (ike_version == IKEV2)
		{
			buffer_enc_alg = expand_enc_name(enc_alg, key_size);
			buffer_int_alg = expand_int_name(int_alg);
			if (buffer_enc_alg && buffer_enc_alg)
			{
				ikev2_file = fopen(path_ikev2, "a");
				if (ikev2_file)
				{
					fprintf(ikev2_file, "%+B,%+B,%+B,%+B,\"%s\",%+B,%+B,\"%s\"\n",
						&this->spi_i, &this->spi_r,&sk_ei, &sk_er,
						buffer_enc_alg, &sk_ai, &sk_ar,	buffer_int_alg);
					fclose(ikev2_file);
				}
			}
		}
		else
		{
			ikev1_file = fopen(path_ikev1, "a");
			if (ikev1_file)
			{
				fprintf(ikev1_file, "%+B,%+B\n", &this->spi_i, &sk_ei);
				fclose(ikev1_file);
			}
		}

		free(buffer_int_alg);
		free(buffer_enc_alg);
		chunk_clear(&this->spi_i);
		chunk_clear(&this->spi_r);
		free(path_ikev2);
		free(path_ikev1);
	}

        return TRUE;
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
				.save_ike_keys = _save_ike_keys,
				.send_spis = _send_spis,
			},
		}
	);

	this->directory_path = lib->settings->get_str(lib->settings,
							"%s.plugins.save-keys.directory_path",
								default_path, lib->ns);
	return &this->public;
}
