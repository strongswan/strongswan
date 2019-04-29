/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "test_suite.h"

#include <plugins/plugin_feature.h>

/**
 * Signature schemes to test
 */
static struct {
	/* key size for scheme, 0 for any */
	int key_size;
	signature_scheme_t scheme;
} schemes[] = {
	{ 0, SIGN_ECDSA_WITH_SHA1_DER },
	{ 0, SIGN_ECDSA_WITH_SHA256_DER },
	{ 0, SIGN_ECDSA_WITH_SHA384_DER },
	{ 0, SIGN_ECDSA_WITH_SHA512_DER },
	{ 0, SIGN_ECDSA_WITH_NULL },
	{ 256, SIGN_ECDSA_256 },
	{ 384, SIGN_ECDSA_384 },
	{ 521, SIGN_ECDSA_521 },
};

/**
 * Perform a signature verification "good" test having a keypair
 */
static void test_good_sig(private_key_t *privkey, public_key_t *pubkey)
{
	chunk_t sig, data = chunk_from_chars(0x01,0x02,0x03,0xFD,0xFE,0xFF);
	int i;

	for (i = 0; i < countof(schemes); i++)
	{
		if (!lib->plugins->has_feature(lib->plugins,
						PLUGIN_PROVIDE(PUBKEY_VERIFY, schemes[i].scheme)) ||
			!lib->plugins->has_feature(lib->plugins,
						PLUGIN_PROVIDE(PRIVKEY_SIGN, schemes[i].scheme)))
		{
			continue;
		}
		if (schemes[i].key_size != 0 &&
			 schemes[i].key_size != privkey->get_keysize(privkey))
		{
			continue;
		}
		fail_unless(privkey->sign(privkey, schemes[i].scheme, NULL, data, &sig),
					"sign %N", signature_scheme_names, schemes[i].scheme);
		fail_unless(pubkey->verify(pubkey, schemes[i].scheme, NULL, data, sig),
					"verify %N", signature_scheme_names, schemes[i].scheme);
		free(sig.ptr);
	}
}

/**
 * Some special signatures that should never validate successfully
 */
static chunk_t invalid_sigs[] = {
	chunk_from_chars(),
	chunk_from_chars(0x00),
	chunk_from_chars(0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
	chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
};

/**
 * Check public key that it properly fails against some crafted sigs
 */
static void test_bad_sigs(public_key_t *pubkey)
{
	chunk_t data = chunk_from_chars(0x01,0x02,0x03,0xFD,0xFE,0xFF);
	int s, i;

	for (s = 0; s < countof(schemes); s++)
	{
		if (schemes[s].key_size != 0 &&
			 schemes[s].key_size != pubkey->get_keysize(pubkey))
		{
			continue;
		}
		if (!lib->plugins->has_feature(lib->plugins,
						PLUGIN_PROVIDE(PUBKEY_VERIFY, schemes[s].scheme)))
		{
			continue;
		}
		for (i = 0; i < countof(invalid_sigs); i++)
		{
			fail_if(
				pubkey->verify(pubkey, schemes[s].scheme, NULL, data,
							   invalid_sigs[i]),
				"bad %N sig accepted %B",
				signature_scheme_names, schemes[s].scheme,
				&invalid_sigs[i]);
		}
	}
}

/**
 * ECDSA key sizes to test
 */
static int key_sizes[] = {
	256, 384, 521,
};

START_TEST(test_gen)
{
	private_key_t *privkey;
	public_key_t *pubkey;

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA,
								 BUILD_KEY_SIZE, key_sizes[_i], BUILD_END);
	ck_assert(privkey != NULL);
	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey != NULL);

	test_good_sig(privkey, pubkey);

	test_bad_sigs(pubkey);

	pubkey->destroy(pubkey);
	privkey->destroy(privkey);
}
END_TEST

/**
 * Private keys to load
 */
static struct {
	chunk_t key;
	chunk_t pkcs8;
	chunk_t pub;
	chunk_t fp_pk;
	chunk_t fp_spki;
} keys[] = {
	{ chunk_from_chars( /* ECDSA-256 */
		0x30,0x77,0x02,0x01,0x01,0x04,0x20,0x42,0xc6,0x8c,0xff,0x2b,0x8b,0x87,0xa1,0xfb,
		0x50,0xf6,0xfe,0xd6,0x88,0xb3,0x0a,0x48,0xb2,0xc5,0x8f,0x50,0xe0,0xcf,0x40,0xfa,
		0x57,0xd1,0xc6,0x6c,0x20,0x64,0xc5,0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,
		0x03,0x01,0x07,0xa1,0x44,0x03,0x42,0x00,0x04,0x9c,0xb2,0x52,0xcb,0xc0,0x5c,0xcf,
		0x97,0xdd,0xd6,0xe7,0x49,0x32,0x47,0x0c,0x8e,0xdb,0x6d,0xbf,0xc8,0x1a,0x0a,0x01,
		0xe8,0x5e,0x3f,0x8e,0x64,0x33,0xb4,0x15,0xbb,0x1b,0xa5,0xed,0xf9,0x4b,0xa7,0xe8,
		0x5e,0x6f,0x49,0x24,0xf7,0x32,0xf4,0x9b,0x4c,0x47,0xdc,0xf1,0x28,0x44,0x1c,0x37,
		0xdb,0xee,0xfb,0xd8,0xbd,0x4e,0x5c,0xeb,0x07),
	  chunk_from_chars(
		0x30,0x81,0x87,0x02,0x01,0x00,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,
		0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x04,0x6d,0x30,0x6b,0x02,
		0x01,0x01,0x04,0x20,0x42,0xc6,0x8c,0xff,0x2b,0x8b,0x87,0xa1,0xfb,0x50,0xf6,0xfe,
		0xd6,0x88,0xb3,0x0a,0x48,0xb2,0xc5,0x8f,0x50,0xe0,0xcf,0x40,0xfa,0x57,0xd1,0xc6,
		0x6c,0x20,0x64,0xc5,0xa1,0x44,0x03,0x42,0x00,0x04,0x9c,0xb2,0x52,0xcb,0xc0,0x5c,
		0xcf,0x97,0xdd,0xd6,0xe7,0x49,0x32,0x47,0x0c,0x8e,0xdb,0x6d,0xbf,0xc8,0x1a,0x0a,
		0x01,0xe8,0x5e,0x3f,0x8e,0x64,0x33,0xb4,0x15,0xbb,0x1b,0xa5,0xed,0xf9,0x4b,0xa7,
		0xe8,0x5e,0x6f,0x49,0x24,0xf7,0x32,0xf4,0x9b,0x4c,0x47,0xdc,0xf1,0x28,0x44,0x1c,
		0x37,0xdb,0xee,0xfb,0xd8,0xbd,0x4e,0x5c,0xeb,0x07),
	  chunk_from_chars(
		0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,
		0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x9c,0xb2,0x52,0xcb,0xc0,
		0x5c,0xcf,0x97,0xdd,0xd6,0xe7,0x49,0x32,0x47,0x0c,0x8e,0xdb,0x6d,0xbf,0xc8,0x1a,
		0x0a,0x01,0xe8,0x5e,0x3f,0x8e,0x64,0x33,0xb4,0x15,0xbb,0x1b,0xa5,0xed,0xf9,0x4b,
		0xa7,0xe8,0x5e,0x6f,0x49,0x24,0xf7,0x32,0xf4,0x9b,0x4c,0x47,0xdc,0xf1,0x28,0x44,
		0x1c,0x37,0xdb,0xee,0xfb,0xd8,0xbd,0x4e,0x5c,0xeb,0x07),
	  chunk_from_chars(
		0x07,0x64,0x50,0x1c,0x33,0x37,0x20,0x9b,0xe2,0x0e,0xe9,0x27,0xf0,0x29,0x5b,0x97,
		0x11,0x5f,0x7c,0xd1),
	  chunk_from_chars(
		0x1a,0x97,0x25,0x7a,0x48,0xae,0x8a,0x40,0x1a,0x4b,0xa0,0x0f,0x82,0x3c,0xa3,0x1f,
		0x61,0x91,0xd3,0x91),
	},
	{ chunk_from_chars( /* ECDSA-384 */
		0x30,0x81,0xa4,0x02,0x01,0x01,0x04,0x30,0x4b,0xbf,0x6c,0xf5,0x24,0x78,0x53,0x4b,
		0x1a,0x91,0x23,0xae,0x30,0xc8,0xb3,0xc9,0xc2,0x9b,0x23,0x07,0x10,0x6f,0x1b,0x47,
		0x7c,0xa0,0xd4,0x79,0x3c,0xc4,0x83,0x10,0xd1,0x44,0x07,0xc2,0x1b,0x66,0xff,0xae,
		0x76,0x57,0x72,0x90,0x53,0xc2,0xf5,0x29,0xa0,0x07,0x06,0x05,0x2b,0x81,0x04,0x00,
		0x22,0xa1,0x64,0x03,0x62,0x00,0x04,0x1e,0xcf,0x1c,0x85,0x9d,0x06,0xa0,0x54,0xa2,
		0x24,0x2f,0xd8,0x63,0x56,0x7b,0x70,0x0b,0x7f,0x81,0x96,0xce,0xb9,0x2e,0x35,0x03,
		0x9c,0xf9,0x0a,0x5d,0x3b,0x10,0xf7,0x13,0x7a,0x0d,0xca,0x56,0xda,0x1d,0x44,0x84,
		0x07,0x6f,0x58,0xdc,0x34,0x7b,0x1d,0x4c,0xdd,0x28,0x10,0xc0,0xe2,0xae,0xf4,0xd6,
		0xda,0xea,0xaf,0xfc,0x7a,0xaf,0x59,0x5f,0xbc,0x91,0x65,0xd3,0x21,0x19,0x61,0xbb,
		0xfe,0x3c,0xdb,0x47,0xcb,0x7a,0xe7,0x5d,0xbd,0x28,0xde,0x25,0x64,0x9e,0x3a,0xa9,
		0x18,0xed,0x24,0xe1,0x1f,0x73,0xcc),
	  chunk_from_chars(
		0x30,0x81,0xb6,0x02,0x01,0x00,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,
		0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x22,0x04,0x81,0x9e,0x30,0x81,0x9b,0x02,0x01,
		0x01,0x04,0x30,0x4b,0xbf,0x6c,0xf5,0x24,0x78,0x53,0x4b,0x1a,0x91,0x23,0xae,0x30,
		0xc8,0xb3,0xc9,0xc2,0x9b,0x23,0x07,0x10,0x6f,0x1b,0x47,0x7c,0xa0,0xd4,0x79,0x3c,
		0xc4,0x83,0x10,0xd1,0x44,0x07,0xc2,0x1b,0x66,0xff,0xae,0x76,0x57,0x72,0x90,0x53,
		0xc2,0xf5,0x29,0xa1,0x64,0x03,0x62,0x00,0x04,0x1e,0xcf,0x1c,0x85,0x9d,0x06,0xa0,
		0x54,0xa2,0x24,0x2f,0xd8,0x63,0x56,0x7b,0x70,0x0b,0x7f,0x81,0x96,0xce,0xb9,0x2e,
		0x35,0x03,0x9c,0xf9,0x0a,0x5d,0x3b,0x10,0xf7,0x13,0x7a,0x0d,0xca,0x56,0xda,0x1d,
		0x44,0x84,0x07,0x6f,0x58,0xdc,0x34,0x7b,0x1d,0x4c,0xdd,0x28,0x10,0xc0,0xe2,0xae,
		0xf4,0xd6,0xda,0xea,0xaf,0xfc,0x7a,0xaf,0x59,0x5f,0xbc,0x91,0x65,0xd3,0x21,0x19,
		0x61,0xbb,0xfe,0x3c,0xdb,0x47,0xcb,0x7a,0xe7,0x5d,0xbd,0x28,0xde,0x25,0x64,0x9e,
		0x3a,0xa9,0x18,0xed,0x24,0xe1,0x1f,0x73,0xcc),
	  chunk_from_chars(
		0x30,0x76,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,
		0x81,0x04,0x00,0x22,0x03,0x62,0x00,0x04,0x1e,0xcf,0x1c,0x85,0x9d,0x06,0xa0,0x54,
		0xa2,0x24,0x2f,0xd8,0x63,0x56,0x7b,0x70,0x0b,0x7f,0x81,0x96,0xce,0xb9,0x2e,0x35,
		0x03,0x9c,0xf9,0x0a,0x5d,0x3b,0x10,0xf7,0x13,0x7a,0x0d,0xca,0x56,0xda,0x1d,0x44,
		0x84,0x07,0x6f,0x58,0xdc,0x34,0x7b,0x1d,0x4c,0xdd,0x28,0x10,0xc0,0xe2,0xae,0xf4,
		0xd6,0xda,0xea,0xaf,0xfc,0x7a,0xaf,0x59,0x5f,0xbc,0x91,0x65,0xd3,0x21,0x19,0x61,
		0xbb,0xfe,0x3c,0xdb,0x47,0xcb,0x7a,0xe7,0x5d,0xbd,0x28,0xde,0x25,0x64,0x9e,0x3a,
		0xa9,0x18,0xed,0x24,0xe1,0x1f,0x73,0xcc),
	  chunk_from_chars(
		0x33,0xe5,0x8b,0x39,0xb7,0x88,0xa1,0xbe,0x86,0x2f,0x5f,0xdf,0x8c,0x48,0xe2,0x4a,
		0x51,0x4e,0xe8,0xea),
	  chunk_from_chars(
		0x57,0x5b,0xdb,0x2e,0xa4,0xa9,0xd5,0x53,0x26,0x91,0x76,0x21,0xce,0x68,0x90,0xb2,
		0xa7,0x09,0x74,0xb4),
	},
	{ chunk_from_chars( /* ECDSA-521 */
		0x30,0x81,0xdc,0x02,0x01,0x01,0x04,0x42,0x01,0xcf,0x38,0xaa,0xa7,0x7a,0x79,0x48,
		0xa9,0x60,0x55,0x24,0xa8,0x7e,0xe1,0xbc,0x45,0x35,0x16,0xff,0x18,0xce,0x44,0xa2,
		0x0b,0x72,0x6b,0xca,0x0a,0x40,0xb4,0x97,0x13,0x17,0x90,0x50,0x15,0xb9,0xba,0xfc,
		0x08,0x0e,0xdb,0xf8,0xfc,0x06,0x35,0x37,0xbf,0xfb,0x25,0x74,0xfe,0x0f,0xe1,0x3c,
		0x3a,0xf0,0x0d,0xe0,0x52,0x15,0xa8,0x07,0x6f,0x3e,0xa0,0x07,0x06,0x05,0x2b,0x81,
		0x04,0x00,0x23,0xa1,0x81,0x89,0x03,0x81,0x86,0x00,0x04,0x00,0x56,0x81,0x28,0xd6,
		0xac,0xe9,0xc8,0x82,0x2c,0xac,0x61,0x6d,0xdd,0x88,0x79,0x00,0xe3,0x7a,0x4d,0x25,
		0xc4,0xea,0x05,0x80,0x75,0x48,0xbc,0x75,0x73,0xc4,0xe9,0x76,0x68,0xba,0x51,0xc3,
		0x29,0xce,0x7d,0x1b,0xb0,0x8b,0xac,0xc1,0xcc,0x23,0xa7,0x2d,0xa7,0x2c,0x95,0xf6,
		0x01,0x40,0x26,0x01,0x1c,0x1c,0x9c,0xe7,0xa7,0xb4,0x0f,0x8e,0xba,0x01,0x07,0xb3,
		0xf7,0xbe,0x45,0x20,0xa9,0x9e,0x70,0xf0,0xcf,0x9b,0xa0,0x91,0xe3,0x88,0x8f,0x04,
		0x69,0x3d,0x0f,0x2b,0xf3,0xb4,0x03,0x19,0x89,0xcf,0xfa,0x77,0x04,0x15,0xaf,0xdd,
		0xf7,0x32,0x76,0x25,0x25,0x05,0x8d,0xfd,0x18,0x8a,0xda,0xd6,0xbc,0x71,0xb8,0x9f,
		0x39,0xb0,0xaf,0xcc,0x54,0xb0,0x9c,0x4d,0x54,0xfb,0x46,0x53,0x5f,0xf8,0x45),
	  chunk_from_chars(
		0x30,0x81,0xee,0x02,0x01,0x00,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,
		0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x23,0x04,0x81,0xd6,0x30,0x81,0xd3,0x02,0x01,
		0x01,0x04,0x42,0x01,0xcf,0x38,0xaa,0xa7,0x7a,0x79,0x48,0xa9,0x60,0x55,0x24,0xa8,
		0x7e,0xe1,0xbc,0x45,0x35,0x16,0xff,0x18,0xce,0x44,0xa2,0x0b,0x72,0x6b,0xca,0x0a,
		0x40,0xb4,0x97,0x13,0x17,0x90,0x50,0x15,0xb9,0xba,0xfc,0x08,0x0e,0xdb,0xf8,0xfc,
		0x06,0x35,0x37,0xbf,0xfb,0x25,0x74,0xfe,0x0f,0xe1,0x3c,0x3a,0xf0,0x0d,0xe0,0x52,
		0x15,0xa8,0x07,0x6f,0x3e,0xa1,0x81,0x89,0x03,0x81,0x86,0x00,0x04,0x00,0x56,0x81,
		0x28,0xd6,0xac,0xe9,0xc8,0x82,0x2c,0xac,0x61,0x6d,0xdd,0x88,0x79,0x00,0xe3,0x7a,
		0x4d,0x25,0xc4,0xea,0x05,0x80,0x75,0x48,0xbc,0x75,0x73,0xc4,0xe9,0x76,0x68,0xba,
		0x51,0xc3,0x29,0xce,0x7d,0x1b,0xb0,0x8b,0xac,0xc1,0xcc,0x23,0xa7,0x2d,0xa7,0x2c,
		0x95,0xf6,0x01,0x40,0x26,0x01,0x1c,0x1c,0x9c,0xe7,0xa7,0xb4,0x0f,0x8e,0xba,0x01,
		0x07,0xb3,0xf7,0xbe,0x45,0x20,0xa9,0x9e,0x70,0xf0,0xcf,0x9b,0xa0,0x91,0xe3,0x88,
		0x8f,0x04,0x69,0x3d,0x0f,0x2b,0xf3,0xb4,0x03,0x19,0x89,0xcf,0xfa,0x77,0x04,0x15,
		0xaf,0xdd,0xf7,0x32,0x76,0x25,0x25,0x05,0x8d,0xfd,0x18,0x8a,0xda,0xd6,0xbc,0x71,
		0xb8,0x9f,0x39,0xb0,0xaf,0xcc,0x54,0xb0,0x9c,0x4d,0x54,0xfb,0x46,0x53,0x5f,0xf8,
		0x45),
	  chunk_from_chars(
		0x30,0x81,0x9b,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,
		0x2b,0x81,0x04,0x00,0x23,0x03,0x81,0x86,0x00,0x04,0x00,0x56,0x81,0x28,0xd6,0xac,
		0xe9,0xc8,0x82,0x2c,0xac,0x61,0x6d,0xdd,0x88,0x79,0x00,0xe3,0x7a,0x4d,0x25,0xc4,
		0xea,0x05,0x80,0x75,0x48,0xbc,0x75,0x73,0xc4,0xe9,0x76,0x68,0xba,0x51,0xc3,0x29,
		0xce,0x7d,0x1b,0xb0,0x8b,0xac,0xc1,0xcc,0x23,0xa7,0x2d,0xa7,0x2c,0x95,0xf6,0x01,
		0x40,0x26,0x01,0x1c,0x1c,0x9c,0xe7,0xa7,0xb4,0x0f,0x8e,0xba,0x01,0x07,0xb3,0xf7,
		0xbe,0x45,0x20,0xa9,0x9e,0x70,0xf0,0xcf,0x9b,0xa0,0x91,0xe3,0x88,0x8f,0x04,0x69,
		0x3d,0x0f,0x2b,0xf3,0xb4,0x03,0x19,0x89,0xcf,0xfa,0x77,0x04,0x15,0xaf,0xdd,0xf7,
		0x32,0x76,0x25,0x25,0x05,0x8d,0xfd,0x18,0x8a,0xda,0xd6,0xbc,0x71,0xb8,0x9f,0x39,
		0xb0,0xaf,0xcc,0x54,0xb0,0x9c,0x4d,0x54,0xfb,0x46,0x53,0x5f,0xf8,0x45),
	  chunk_from_chars(
		0x1d,0x3b,0x1b,0x05,0xd7,0xcb,0x87,0x17,0x49,0x2c,0x6a,0xed,0x3b,0x82,0xa8,0xc3,
		0xaa,0x76,0x72,0x91),
	  chunk_from_chars(
		0xd4,0x6d,0x34,0x22,0xd4,0xdd,0xca,0x63,0x26,0x95,0xb5,0x47,0x9b,0x8b,0x4a,0x30,
		0x67,0x27,0x3e,0xcd),
	},
};

START_TEST(test_load)
{
	private_key_t *privkey;
	public_key_t *pubkey;
	chunk_t encoding, fp;

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA,
								 BUILD_BLOB_ASN1_DER, keys[_i].key, BUILD_END);
	ck_assert(privkey != NULL);
	ck_assert(privkey->get_encoding(privkey, PRIVKEY_ASN1_DER, &encoding));
	if (encoding.len == keys[_i].pkcs8.len)
	{
		ck_assert_chunk_eq(keys[_i].pkcs8, encoding);
	}
	else
	{
		ck_assert_chunk_eq(keys[_i].key, encoding);
	}
	chunk_clear(&encoding);

	ck_assert(privkey->get_fingerprint(privkey, KEYID_PUBKEY_SHA1, &fp));
	ck_assert_chunk_eq(keys[_i].fp_pk, fp);
	ck_assert(privkey->get_fingerprint(privkey, KEYID_PUBKEY_INFO_SHA1, &fp));
	ck_assert_chunk_eq(keys[_i].fp_spki, fp);

	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey != NULL);
	ck_assert(pubkey->get_encoding(pubkey, PUBKEY_SPKI_ASN1_DER, &encoding));
	ck_assert_chunk_eq(keys[_i].pub, encoding);
	chunk_free(&encoding);

	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SHA1, &fp));
	ck_assert_chunk_eq(keys[_i].fp_pk, fp);
	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_INFO_SHA1, &fp));
	ck_assert_chunk_eq(keys[_i].fp_spki, fp);

	test_good_sig(privkey, pubkey);

	test_bad_sigs(pubkey);

	pubkey->destroy(pubkey);
	privkey->destroy(privkey);
}
END_TEST

Suite *ecdsa_suite_create()
{
	Suite *s;
	TCase *tc;
	int gen_count = countof(key_sizes);

	s = suite_create("ecdsa");

	if (getenv("TESTS_REDUCED_KEYLENGTHS") != NULL)
	{
		gen_count = min(1, gen_count);
	}

	tc = tcase_create("generate");
	tcase_add_loop_test(tc, test_gen, 0, gen_count);
	suite_add_tcase(s, tc);

	tc = tcase_create("load");
	tcase_add_loop_test(tc, test_load, 0, countof(keys));
	suite_add_tcase(s, tc);

	return s;
}
