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
 * Name for esp decryption table file
 */
static char *esp_name = "esp_sa";

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
 * ESP Algorithms for encryption
 */
static map_algorithm_name_t esp_encryption_algs[] = {
	{ENCR_NULL,		-1,	"NULL"},
	{ENCR_3DES,		-1,	"TripleDes-CBC [RFC2451]"},
	{ENCR_AES_CBC,		-1,	"AES-CBC [RFC3602]"},
	{ENCR_AES_CTR,		-1,	"AES-CTR [RFC3686]"},
	{ENCR_DES,		-1,	"DES-CBC [RFC2405]"},
	{ENCR_CAST,		-1,	"CAST5-CBC [RFC2144]"},
	{ENCR_BLOWFISH,		-1,	"BLOWFISH-CBC [RFC2451]"},
	{ENCR_TWOFISH_CBC,	-1,	"TWOFISH-CBC"},
	{ENCR_AES_GCM_ICV8,	128,	"AES-GCM [RFC4106]"},
	{ENCR_AES_GCM_ICV12,	192,	"AES-GCM [RFC4106]"},
	{ENCR_AES_GCM_ICV16,	256,	"AES-GCM [RFC4106]"},
};

/**
 * ESP Algorithms for integrity
 */
static map_algorithm_name_t esp_integrity_algs[] = {
	{AUTH_HMAC_SHA1_96,		-1,	"HMAC-SHA-1-96 [RFC2404]"},
	{AUTH_HMAC_SHA2_256_96,		-1,	"HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]"},
	{AUTH_HMAC_MD5_96,		-1,	"HMAC-MD5-96 [RFC2403]"},
	{AUTH_HMAC_SHA2_256_128,	-1,	"HMAC-SHA-256-128 [RFC4868]"},
	{AUTH_HMAC_SHA2_384_192,	-1,	"HMAC-SHA-384-192 [RFC4868]"},
	{AUTH_HMAC_SHA2_512_256,	-1,	"HMAC-SHA-512-256 [RFC4868]"},
	{-1,				128,	"ANY 128 bit authentication [no checking]"},
	{-1,				192,	"ANY 192 bit authentication [no checking]"},
	{-1,				256,	"ANY 256 bit authentication [no checking]"},
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

/**
 * Expands the name of encryption algorithms for ESP decryption table.
 */
static inline char *esp_expand_enc_name(uint16_t enc_alg, int *ICV_length)
{
	unsigned int i;
	for (i = 0; i < countof(esp_encryption_algs); i ++)
	{
		if (esp_encryption_algs[i].strongswan == enc_alg)
		{
			(*ICV_length) = esp_encryption_algs[i].size;
			return esp_encryption_algs[i].name;
		}
	}
	return NULL;
}

/**
 * Expands the name of integrity algorithms for ESP decryption table.
 */
static inline char *esp_expand_int_name(uint16_t int_alg, int icv_length)
{
	unsigned int i;
	for (i = 0; i < countof(esp_integrity_algs); i ++)
	{
		if (icv_length != -1 && esp_integrity_algs[i].size == icv_length)
		{
			return esp_integrity_algs[i].name;
		}
		else if (esp_integrity_algs[i].strongswan == int_alg)
		{
			return esp_integrity_algs[i].name;
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

METHOD(listener_t, save_child_keys, bool,
	private_save_keys_listener_t *this, uint16_t enc_alg,
	uint16_t int_alg, host_t *init_ip, host_t *resp_ip,
	uint32_t spi_out, chunk_t encr_key_out,
	chunk_t int_key_out, uint32_t spi_in, chunk_t encr_key_in,
	chunk_t int_key_in)
{
	int icv_length = -1;
	char *name_enc_alg = NULL, *name_int_alg = NULL;
	FILE *esp_file;

	if (this->directory_path)
	{
		char *path_esp = malloc (strlen(this->directory_path) + strlen(esp_name) + 1);
		strcpy(path_esp, this->directory_path);
		strcat(path_esp, esp_name);

		esp_file = fopen(path_esp, "a");
		if (esp_file)
		{
			name_enc_alg = esp_expand_enc_name(enc_alg, &icv_length);
			name_int_alg = esp_expand_int_name(int_alg, icv_length);

			if (name_enc_alg && name_int_alg)
			{
				if (init_ip->get_family(init_ip) == AF_INET)
				{
					fprintf(esp_file, "\"IPv4\",\"%H\",\"%H\",\"0x%.8x\",\"%s\",\"0x%+B\",\"%s\",\"0x%+B\"\n",
						init_ip, resp_ip, ntohl(spi_out), name_enc_alg, &encr_key_out,
						name_int_alg, &int_key_out);
					fprintf(esp_file, "\"IPv4\",\"%H\",\"%H\",\"0x%.8x\",\"%s\",\"0x%+B\",\"%s\",\"0x%+B\"\n",
						resp_ip, init_ip, ntohl(spi_in), name_enc_alg, &encr_key_in,
						name_int_alg, &int_key_in);
				}
				else if (init_ip->get_family(init_ip) == AF_INET6)
				{
					fprintf(esp_file, "\"IPv6\",\"%H\",\"%H\",\"0x%.8x\",\"%s\",\"0x%+B\",\"%s\",\"0x%+B\"\n",
						init_ip, resp_ip, ntohl(spi_out), name_enc_alg, &encr_key_out,
						name_int_alg, &int_key_out);
					fprintf(esp_file, "\"IPv6\",\"%H\",\"%H\",\"0x%.8x\",\"%s\",\"0x%+B\",\"%s\",\"0x%+B\"\n",
						resp_ip, init_ip, ntohl(spi_in), name_enc_alg, &encr_key_in,
						name_int_alg, &int_key_in);
				}
			}

			free(name_int_alg);
			free(name_enc_alg);
			fclose(esp_file);
			free(path_esp);
		}
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
				.save_child_keys = _save_child_keys,
			},
		}
	);

	this->directory_path = lib->settings->get_str(lib->settings,
							"%s.plugins.save-keys.directory_path",
								default_path, lib->ns);
	return &this->public;
}
