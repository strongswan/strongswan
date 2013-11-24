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

#include "test_suite.h"

#include <plugins/ntru/ntru_drbg.h>
#include <plugins/ntru/ntru_test_rng.h>

/**
 * NTRU parameter sets to test
 */
static struct {
	diffie_hellman_group_t group;
	char *group_name;
} params[] = {
	{ NTRU_112_BIT, "NTRU_112" },
	{ NTRU_128_BIT, "NTRU_128" },
	{ NTRU_192_BIT, "NTRU_192" },
	{ NTRU_256_BIT, "NTRU_256" }
};

/**
 * NTRU parameter set selection
 */
char *parameter_sets[] = {
		"x9_98_speed", "x9_98_bandwidth", "x9_98_balance", "optimum"
};

typedef struct {
	u_int32_t requested;
	u_int32_t standard;
}strength_t;

strength_t strengths[] = {
	{  80, 112 },
	{ 112, 112 },
	{ 120, 128 },
	{ 128, 128 },
	{ 150, 192 },
	{ 192, 192 },
	{ 200, 256 },
	{ 256, 256 },
	{ 512,   0 }
};

START_TEST(test_ntru_drbg_strength)
{
	ntru_drbg_t *drbg;
	rng_t *entropy;

	entropy = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	ck_assert(entropy != NULL);

	drbg = ntru_drbg_create(strengths[_i].requested, chunk_empty, entropy);
	if (strengths[_i].standard)
	{
		ck_assert(drbg != NULL);
		ck_assert(drbg->get_strength(drbg) == strengths[_i].standard);
		drbg->destroy(drbg);
	}
	else
	{
		ck_assert(drbg == NULL);
	}
	entropy->destroy(entropy);
}
END_TEST

START_TEST(test_ntru_dbrg)
{
	typedef struct {
		chunk_t pers_str;
		chunk_t entropy;
		chunk_t out;
	} dbrg_test_t;

	dbrg_test_t dbrg_tests[] = {
		{ chunk_empty,
		  chunk_from_chars(0x06, 0x03, 0x2c, 0xd5, 0xee, 0xd3, 0x3f, 0x39,
						   0x26, 0x5f, 0x49, 0xec, 0xb1, 0x42, 0xc5, 0x11,
						   0xda, 0x9a, 0xff, 0x2a, 0xf7, 0x12, 0x03, 0xbf,
						   0xfa, 0xf3, 0x4a, 0x9c, 0xa5, 0xbd, 0x9c, 0x0d,
						   0x0e, 0x66, 0xf7, 0x1e, 0xdc, 0x43, 0xe4, 0x2a,
						   0x45, 0xad, 0x3c, 0x6f, 0xc6, 0xcd, 0xc4, 0xdf,
						   0x01, 0x92, 0x0a, 0x4e, 0x66, 0x9e, 0xd3, 0xa8,
						   0x5a, 0xe8, 0xa3, 0x3b, 0x35, 0xa7, 0x4a, 0xd7,
						   0xfb, 0x2a, 0x6b, 0xb4, 0xcf, 0x39, 0x5c, 0xe0,
						   0x03, 0x34, 0xa9, 0xc9, 0xa5, 0xa5, 0xd5, 0x52),
		  chunk_from_chars(0x76, 0xfc, 0x79, 0xfe, 0x9b, 0x50, 0xbe, 0xcc,
						   0xc9, 0x91, 0xa1, 0x1b, 0x56, 0x35, 0x78, 0x3a,
						   0x83, 0x53, 0x6a, 0xdd, 0x03, 0xc1, 0x57, 0xfb,
						   0x30, 0x64, 0x5e, 0x61, 0x1c, 0x28, 0x98, 0xbb,
						   0x2b, 0x1b, 0xc2, 0x15, 0x00, 0x02, 0x09, 0x20,
						   0x8c, 0xd5, 0x06, 0xcb, 0x28, 0xda, 0x2a, 0x51,
						   0xbd, 0xb0, 0x38, 0x26, 0xaa, 0xf2, 0xbd, 0x23,
						   0x35, 0xd5, 0x76, 0xd5, 0x19, 0x16, 0x08, 0x42,
						   0xe7, 0x15, 0x8a, 0xd0, 0x94, 0x9d, 0x1a, 0x9e,
						   0xc3, 0xe6, 0x6e, 0xa1, 0xb1, 0xa0, 0x64, 0xb0,
						   0x05, 0xde, 0x91, 0x4e, 0xac, 0x2e, 0x9d, 0x4f,
						   0x2d, 0x72, 0xa8, 0x61, 0x6a, 0x80, 0x22, 0x54,
						   0x22, 0x91, 0x82, 0x50, 0xff, 0x66, 0xa4, 0x1b,
						   0xd2, 0xf8, 0x64, 0xa6, 0xa3, 0x8c, 0xc5, 0xb6,
						   0x49, 0x9d, 0xc4, 0x3f, 0x7f, 0x2b, 0xd0, 0x9e,
						   0x1e, 0x0f, 0x8f, 0x58, 0x85, 0x93, 0x51, 0x24)
		},
		{ chunk_from_chars(0xf2, 0xe5, 0x8f, 0xe6, 0x0a, 0x3a, 0xfc, 0x59,
						   0xda, 0xd3, 0x75, 0x95, 0x41, 0x5f, 0xfd, 0x31,
						   0x8c, 0xcf, 0x69, 0xd6, 0x77, 0x80, 0xf6, 0xfa,
						   0x07, 0x97, 0xdc, 0x9a, 0xa4, 0x3e, 0x14, 0x4c),
		  chunk_from_chars(0xfa, 0x0e, 0xe1, 0xfe, 0x39, 0xc7, 0xc3, 0x90,
						   0xaa, 0x94, 0x15, 0x9d, 0x0d, 0xe9, 0x75, 0x64,
						   0x34, 0x2b, 0x59, 0x17, 0x77, 0xf3, 0xe5, 0xf6,
						   0xa4, 0xba, 0x2a, 0xea, 0x34, 0x2e, 0xc8, 0x40,
						   0xdd, 0x08, 0x20, 0x65, 0x5c, 0xb2, 0xff, 0xdb,
						   0x0d, 0xa9, 0xe9, 0x31, 0x0a, 0x67, 0xc9, 0xe5,
						   0xe0, 0x62, 0x9b, 0x6d, 0x79, 0x75, 0xdd, 0xfa,
						   0x96, 0xa3, 0x99, 0x64, 0x87, 0x40, 0xe6, 0x0f,
						   0x1f, 0x95, 0x57, 0xdc, 0x58, 0xb3, 0xd7, 0x41,
						   0x5f, 0x9b, 0xa9, 0xd4, 0xdb, 0xb5, 0x01, 0xf6),
		  chunk_from_chars(0xf9, 0x2d, 0x4c, 0xf9, 0x9a, 0x53, 0x5b, 0x20,
						   0x22, 0x2a, 0x52, 0xa6, 0x8d, 0xb0, 0x4c, 0x5a,
						   0xf6, 0xf5, 0xff, 0xc7, 0xb6, 0x6a, 0x47, 0x3a,
						   0x37, 0xa2, 0x56, 0xbd, 0x8d, 0x29, 0x8f, 0x9b,
						   0x4a, 0xa4, 0xaf, 0x7e, 0x8d, 0x18, 0x1e, 0x02,
						   0x36, 0x79, 0x03, 0xf9, 0x3b, 0xdb, 0x74, 0x4c,
						   0x6c, 0x2f, 0x3f, 0x34, 0x72, 0x62, 0x6b, 0x40,
						   0xce, 0x9b, 0xd6, 0xa7, 0x0e, 0x7b, 0x8f, 0x93,
						   0x99, 0x2a, 0x16, 0xa7, 0x6f, 0xab, 0x6b, 0x5f,
						   0x16, 0x25, 0x68, 0xe0, 0x8e, 0xe6, 0xc3, 0xe8,
						   0x04, 0xae, 0xfd, 0x95, 0x2d, 0xdd, 0x3a, 0xcb,
						   0x79, 0x1c, 0x50, 0xf2, 0xad, 0x69, 0xe9, 0xa0,
						   0x40, 0x28, 0xa0, 0x6a, 0x9c, 0x01, 0xd3, 0xa6,
						   0x2a, 0xca, 0x2a, 0xaf, 0x6e, 0xfe, 0x69, 0xed,
						   0x97, 0xa0, 0x16, 0x21, 0x3a, 0x2d, 0xd6, 0x42,
						   0xb4, 0x88, 0x67, 0x64, 0x07, 0x2d, 0x9c, 0xbe)
		}
	};

	ntru_drbg_t *drbg;
	rng_t *entropy;
	chunk_t in, out;
	int i;

	/* test ntru_test_rng */
	in = chunk_from_chars(0x01, 0x02, 0x04, 0x04);
	entropy = ntru_test_rng_create(in);
	ck_assert(entropy->allocate_bytes(entropy, 4, &out));
	ck_assert(chunk_equals(in, out));
	chunk_free(&out);
	ck_assert(!entropy->allocate_bytes(entropy, 4, &out));
	entropy->destroy(entropy);

	/* test DRBG with ntru_test_rng providing NIST test vectors */
	out = chunk_alloc(128);
	for (i = 0; i < countof(dbrg_tests); i++)
	{
		entropy = ntru_test_rng_create(dbrg_tests[i].entropy);
		drbg = ntru_drbg_create(256, dbrg_tests[i].pers_str, entropy);
		ck_assert(drbg != NULL);
		ck_assert(drbg->reseed(drbg));
		ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
		ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
		ck_assert(chunk_equals(out, dbrg_tests[i].out));
		drbg->destroy(drbg);
		entropy->destroy(entropy);
	}
	chunk_free(&out);
}
END_TEST

START_TEST(test_ntru_ke)
{
	chunk_t pub_key, cipher_text, i_shared_secret, r_shared_secret;
	diffie_hellman_t *i_ntru, *r_ntru;
	char buf[10];
	int n, len;
	status_t status;
	
	len = snprintf(buf, sizeof(buf), "%N", diffie_hellman_group_names,
				   params[_i].group);
	ck_assert(len == 8);
	ck_assert(streq(buf, params[_i].group_name));

	for (n = 0; n < countof(parameter_sets); n++)
	{
		lib->settings->set_str(lib->settings,
							  "libstrongswan.plugins.ntru.parameter_set",
							   parameter_sets[n]);

		i_ntru = lib->crypto->create_dh(lib->crypto, params[_i].group);
		ck_assert(i_ntru != NULL);
		ck_assert(i_ntru->get_dh_group(i_ntru) == params[_i].group);

		i_ntru->get_my_public_value(i_ntru, &pub_key);
		ck_assert(pub_key.len > 0);

		r_ntru = lib->crypto->create_dh(lib->crypto, params[_i].group);
		ck_assert(r_ntru != NULL);

		r_ntru->set_other_public_value(r_ntru, pub_key);
		r_ntru->get_my_public_value(r_ntru, &cipher_text);
		ck_assert(cipher_text.len > 0);

		status = r_ntru->get_shared_secret(r_ntru, &r_shared_secret);
		ck_assert(status == SUCCESS);
		ck_assert(r_shared_secret.len > 0);

		i_ntru->set_other_public_value(i_ntru, cipher_text);
		status = i_ntru->get_shared_secret(i_ntru, &i_shared_secret);

		if (status == SUCCESS)
		{
			ck_assert(chunk_equals(i_shared_secret, r_shared_secret));
		}
		else
		{
			ck_assert(i_shared_secret.len == 0);
		}

		chunk_clear(&i_shared_secret);
		chunk_clear(&r_shared_secret);
		chunk_free(&pub_key);
		chunk_free(&cipher_text);
		i_ntru->destroy(i_ntru);
		r_ntru->destroy(r_ntru);
	}
}
END_TEST

START_TEST(test_ntru_retransmission)
{
	diffie_hellman_t *i_ntru;
	chunk_t pub_key1, pub_key2;

	i_ntru = lib->crypto->create_dh(lib->crypto, NTRU_256_BIT);
	i_ntru->get_my_public_value(i_ntru, &pub_key1);
	i_ntru->get_my_public_value(i_ntru, &pub_key2);
	ck_assert(chunk_equals(pub_key1, pub_key2));

	chunk_free(&pub_key1);
	chunk_free(&pub_key2);
	i_ntru->destroy(i_ntru);
}
END_TEST

START_TEST(test_ntru_pubkey_oid)
{
	chunk_t test[] = {
		chunk_empty,
		chunk_from_chars(0x00),
		chunk_from_chars(0x01),
		chunk_from_chars(0x02),
		chunk_from_chars(0x02, 0x03, 0x00, 0x03, 0x10),
		chunk_from_chars(0x01, 0x04, 0x00, 0x03, 0x10),
		chunk_from_chars(0x01, 0x03, 0x00, 0x03, 0x10),
		chunk_from_chars(0x01, 0x03, 0xff, 0x03, 0x10),
	};

	diffie_hellman_t *r_ntru;
	chunk_t cipher_text;
	int i;

	for (i = 0; i < countof(test); i++)
	{
		r_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);
		r_ntru->set_other_public_value(r_ntru, test[i]);
		r_ntru->get_my_public_value(r_ntru, &cipher_text);
		ck_assert(cipher_text.len == 0);
		r_ntru->destroy(r_ntru);
	}
}
END_TEST

START_TEST(test_ntru_wrong_set)
{
	diffie_hellman_t *i_ntru, *r_ntru;
	chunk_t pub_key, cipher_text;

	lib->settings->set_str(lib->settings,
						  "libstrongswan.plugins.ntru.parameter_set",
			 			  "x9_98_bandwidth");
	i_ntru = lib->crypto->create_dh(lib->crypto, NTRU_112_BIT);
	i_ntru->get_my_public_value(i_ntru, &pub_key);

	lib->settings->set_str(lib->settings,
						  "libstrongswan.plugins.ntru.parameter_set",
						  "optimum");
	r_ntru = lib->crypto->create_dh(lib->crypto, NTRU_112_BIT);
	r_ntru->set_other_public_value(r_ntru, pub_key);
	r_ntru->get_my_public_value(r_ntru, &cipher_text);
	ck_assert(cipher_text.len == 0);

	chunk_free(&pub_key);
	chunk_free(&cipher_text);
	i_ntru->destroy(i_ntru);
	r_ntru->destroy(r_ntru);
}
END_TEST

START_TEST(test_ntru_ciphertext)
{
	char buf_00[604], buf_ff[604];

	chunk_t test[] = {
		chunk_empty,
		chunk_from_chars(0x00),
		chunk_create(buf_00, sizeof(buf_00)),
		chunk_create(buf_ff, sizeof(buf_ff)),
	};

	diffie_hellman_t *i_ntru;
	chunk_t pub_key, shared_secret;
	int i;

	memset(buf_00, 0x00, sizeof(buf_00));
	memset(buf_ff, 0xff, sizeof(buf_ff));

	for (i = 0; i < countof(test); i++)
	{
		i_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);
		i_ntru->get_my_public_value(i_ntru, &pub_key);
		i_ntru->set_other_public_value(i_ntru, test[i]);
		ck_assert(i_ntru->get_shared_secret(i_ntru, &shared_secret) != SUCCESS);
		ck_assert(shared_secret.len == 0);

		chunk_free(&pub_key);
		i_ntru->destroy(i_ntru);
	}
}
END_TEST

START_TEST(test_ntru_wrong_ciphertext)
{
	diffie_hellman_t *i_ntru, *r_ntru, *m_ntru;
	chunk_t pub_key_i, pub_key_m, cipher_text, shared_secret;

	i_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);
	r_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);
	m_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);

	i_ntru->get_my_public_value(i_ntru, &pub_key_i);
	m_ntru->get_my_public_value(m_ntru, &pub_key_m);
	r_ntru->set_other_public_value(r_ntru, pub_key_m);
	r_ntru->get_my_public_value(r_ntru, &cipher_text);
	i_ntru->set_other_public_value(i_ntru, cipher_text);
	ck_assert(i_ntru->get_shared_secret(i_ntru, &shared_secret) != SUCCESS);
	ck_assert(shared_secret.len == 0);

	chunk_free(&pub_key_i);
	chunk_free(&pub_key_m);
	chunk_free(&cipher_text);
	i_ntru->destroy(i_ntru);
	m_ntru->destroy(m_ntru);
	r_ntru->destroy(r_ntru);
}
END_TEST

Suite *ntru_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ntru");

	tc = tcase_create("dbrg_strength");
	tcase_add_loop_test(tc, test_ntru_drbg_strength, 0, countof(strengths));
	suite_add_tcase(s, tc);

	tc = tcase_create("dbrg");
	tcase_add_test(tc, test_ntru_dbrg);
	suite_add_tcase(s, tc);

	tc = tcase_create("ke");
	tcase_add_loop_test(tc, test_ntru_ke, 0, countof(params));
	suite_add_tcase(s, tc);

	tc = tcase_create("retransmission");
	tcase_add_test(tc, test_ntru_retransmission);
	suite_add_tcase(s, tc);

	tc = tcase_create("pubkey_oid");
	tcase_add_test(tc, test_ntru_pubkey_oid);
	suite_add_tcase(s, tc);

	tc = tcase_create("wrong_set");
	tcase_add_test(tc, test_ntru_wrong_set);
	suite_add_tcase(s, tc);

	tc = tcase_create("ciphertext");
	tcase_add_test(tc, test_ntru_ciphertext);
	suite_add_tcase(s, tc);

	tc = tcase_create("wrong_ciphertext");
	tcase_add_test(tc, test_ntru_wrong_ciphertext);
	suite_add_tcase(s, tc);
	return s;
}
