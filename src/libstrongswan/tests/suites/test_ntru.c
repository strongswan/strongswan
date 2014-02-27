/*
 * Copyright (C) 2013-2014 Andreas Steffen
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

#include <tests/utils/test_rng.h>
#include <plugins/ntru/ntru_drbg.h>
#include <plugins/ntru/ntru_mgf1.h>
#include <plugins/ntru/ntru_trits.h>
#include <plugins/ntru/ntru_poly.h>
#include <utils/test.h>

IMPORT_FUNCTION_FOR_TESTS(ntru, ntru_drbg_create, ntru_drbg_t*,
						  u_int32_t strength, chunk_t pers_str, rng_t *entropy)

IMPORT_FUNCTION_FOR_TESTS(ntru, ntru_mgf1_create, ntru_mgf1_t*,
						  hash_algorithm_t alg, chunk_t seed, bool hash_seed)

IMPORT_FUNCTION_FOR_TESTS(ntru, ntru_trits_create, ntru_trits_t*,
						  size_t len, hash_algorithm_t alg, chunk_t seed)

IMPORT_FUNCTION_FOR_TESTS(ntru, ntru_poly_create_from_seed, ntru_poly_t*,
						  hash_algorithm_t alg, chunk_t seed, uint8_t c_bits,
						  uint16_t N, uint16_t q, uint32_t indices_len_p,
						  uint32_t indices_len_m, bool is_product_form)

IMPORT_FUNCTION_FOR_TESTS(ntru, ntru_poly_create_from_data, ntru_poly_t*,
						  u_int16_t *data, uint16_t N, uint16_t q,
						  uint32_t indices_len_p, uint32_t indices_len_m,
						  bool is_product_form)

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

typedef struct {
	chunk_t pers_str;
	chunk_t entropy;
	chunk_t out;
} drbg_test_t;

/**
 * NIST SP 800-90A Deterministic Random Generator Validation System (DRBGVS)
 */
drbg_test_t drbg_tests[] = {
	/* SHA-256 test case 1 - count 0 */
	{ { NULL, 0 },
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
	/* SHA-256 test case 3 - count 0 */
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
	},
	/* SHA-256 test case 5 - count 0 */
	{ { NULL, 0 },
	  chunk_from_chars(0xff, 0x0c, 0xdd, 0x55, 0x5c, 0x60, 0x46, 0x47,
					   0x60, 0xb2, 0x89, 0xb7, 0xbc, 0x1f, 0x81, 0x1a,
					   0x41, 0xff, 0xf7, 0x2d, 0xe5, 0x90, 0x83, 0x85,
					   0x8c, 0x02, 0x0a, 0x10, 0x53, 0xbd, 0xc7, 0x4a,
					   0x7b, 0xc0, 0x99, 0x28, 0x5a, 0xd5, 0x62, 0x19,
					   0x93, 0xb6, 0x39, 0xc4, 0xa9, 0x4c, 0x37, 0x6b,
					   0x14, 0xfc, 0x6c, 0x9b, 0x17, 0x8d, 0xb6, 0x44,
					   0xa8, 0xcd, 0x71, 0x30, 0xa4, 0xcf, 0x05, 0x16,
					   0x78, 0xc8, 0xf4, 0xfa, 0x8f, 0x24, 0xc2, 0x7b,
					   0x0a, 0x53, 0x13, 0x38, 0xa5, 0xce, 0x85, 0x89),
	  chunk_from_chars(0x2f, 0x26, 0x20, 0x34, 0x7b, 0xdd, 0xca, 0xa2,
					   0x94, 0x36, 0x85, 0x34, 0x6b, 0xbf, 0x31, 0xc4,
					   0x40, 0x81, 0xf8, 0x66, 0x5f, 0x3d, 0xdb, 0x2b,
					   0x42, 0xae, 0x14, 0x16, 0xa7, 0x4c, 0x4b, 0x77,
					   0xfa, 0xb3, 0xfa, 0x19, 0xae, 0xec, 0xc5, 0x47,
					   0xe7, 0x6c, 0x8c, 0xbe, 0x6a, 0xd1, 0xf1, 0x00,
					   0xa3, 0xfc, 0x8b, 0x2c, 0xe2, 0xa1, 0xea, 0x3a,
					   0x3d, 0xd7, 0xcf, 0xad, 0x46, 0xc1, 0xb2, 0x78,
					   0x30, 0xb9, 0x40, 0xba, 0x18, 0xd0, 0x9e, 0x9b,
					   0x7f, 0xa9, 0x02, 0xbb, 0x76, 0x06, 0x69, 0xb1,
					   0x73, 0x5c, 0xc7, 0xb7, 0xbd, 0x39, 0x05, 0x2d,
					   0xa7, 0xf2, 0x62, 0x6f, 0xa8, 0x70, 0x00, 0xcf,
					   0xfa, 0xda, 0x41, 0x00, 0x19, 0xd0, 0x53, 0x38,
					   0x6a, 0xd8, 0x08, 0xbd, 0x3c, 0x0c, 0xfc, 0xf5,
					   0x6b, 0x91, 0x87, 0x9e, 0xb8, 0xd3, 0xf9, 0x32,
					   0xee, 0x2d, 0x18, 0x5e, 0x54, 0xf3, 0x1b, 0x74)
	},
	/* SHA-256 test case 7 - count 0 */
	{ chunk_from_chars(0x40, 0x93, 0x3f, 0xdc, 0xce, 0x41, 0x59, 0xb0,
					   0x95, 0x51, 0x11, 0xf8, 0x44, 0x47, 0x1b, 0x0d,
					   0xb8, 0x5b, 0x73, 0xbd, 0xd2, 0xb7, 0x8c, 0x46,
					   0x8d, 0xd3, 0x9e, 0x2a, 0x9b, 0x29, 0xae, 0xf2),
	  chunk_from_chars(0x28, 0xba, 0x1a, 0x66, 0x16, 0x32, 0xef, 0xc8,
					   0xec, 0xce, 0xd5, 0xf5, 0x1b, 0x79, 0x13, 0x00,
					   0xfb, 0x3b, 0x55, 0xb0, 0x5d, 0x04, 0x17, 0x08,
					   0x63, 0x8d, 0xe4, 0xbe, 0xb7, 0x57, 0xa9, 0xe5,
					   0x76, 0x82, 0x87, 0x96, 0xaf, 0xf0, 0x7f, 0x55,
					   0x79, 0x5c, 0xb5, 0x47, 0x13, 0xc7, 0x7e, 0xd4,
					   0xa5, 0xf5, 0x42, 0xb0, 0x4a, 0xaa, 0x5d, 0xbc,
					   0x93, 0x1e, 0x47, 0x01, 0x9f, 0xeb, 0x38, 0x96,
					   0x26, 0x16, 0xc5, 0x7a, 0xf0, 0x9b, 0x7c, 0x1d,
					   0xf8, 0x3f, 0x2b, 0x86, 0x0f, 0xf7, 0x65, 0x86),
	  chunk_from_chars(0x65, 0xe5, 0xaa, 0x47, 0xb3, 0x85, 0xf1, 0xea,
					   0x42, 0xb2, 0x31, 0xb9, 0xfe, 0x74, 0x42, 0x53,
					   0xb8, 0x59, 0x88, 0x59, 0xd7, 0x01, 0x1e, 0x52,
					   0x5f, 0x5a, 0x2a, 0x1a, 0xd3, 0x2a, 0x97, 0x2a,
					   0x85, 0x08, 0x02, 0xc6, 0x0a, 0x2b, 0xe1, 0x9b,
					   0xe2, 0x70, 0x06, 0x3a, 0x3c, 0xfb, 0xea, 0xae,
					   0x95, 0x4f, 0x10, 0xb1, 0x22, 0x35, 0x2d, 0xe6,
					   0xa0, 0x8a, 0xc4, 0x10, 0xe0, 0x99, 0x16, 0x53,
					   0xaa, 0xb2, 0x71, 0xb3, 0x60, 0xfe, 0x91, 0x91,
					   0xcf, 0x5a, 0xdd, 0xcc, 0xcc, 0xed, 0x8c, 0x4a,
					   0xcf, 0xb6, 0x14, 0x57, 0x04, 0x99, 0x92, 0x98,
					   0x8f, 0xd7, 0xa9, 0xac, 0xca, 0x1f, 0x1b, 0xca,
					   0x35, 0xf1, 0x47, 0x58, 0x13, 0x69, 0x4a, 0x39,
					   0x98, 0x8e, 0x5f, 0xac, 0x9f, 0x4a, 0xc0, 0x57,
					   0x22, 0x86, 0xbc, 0x46, 0x25, 0x82, 0xad, 0x0a,
					   0xf7, 0x8a, 0xb3, 0xb8, 0x5e, 0xc1, 0x7a, 0x25)
	}
};

START_TEST(test_ntru_drbg)
{
	ntru_drbg_t *drbg;
	rng_t *entropy;
	chunk_t out;

	out = chunk_alloc(128);
	entropy = test_rng_create(drbg_tests[_i].entropy);
	drbg = ntru_drbg_create(256, drbg_tests[_i].pers_str, entropy);
	ck_assert(drbg != NULL);
	ck_assert(drbg->reseed(drbg));
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
	ck_assert(chunk_equals(out, drbg_tests[_i].out));
	drbg->destroy(drbg);
	entropy->destroy(entropy);
	chunk_free(&out);
}
END_TEST

START_TEST(test_ntru_drbg_reseed)
{
	ntru_drbg_t *drbg;
	rng_t *entropy;
	chunk_t out;

	lib->settings->set_int(lib->settings,
						  "libstrongswan.plugins.ntru.max_drbg_requests", 2);
	out = chunk_alloc(128);
	entropy = test_rng_create(drbg_tests[0].entropy);
	drbg = ntru_drbg_create(256, chunk_empty, entropy);

	/* bad output parameters */
	ck_assert(!drbg->generate(drbg, 256, 0, out.ptr));
	ck_assert(!drbg->generate(drbg, 256, 128, NULL));

	/* no reseeding occurs */
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));

	/* consuming remaining entropy */
	ck_assert(entropy->get_bytes(entropy, 32, out.ptr));

	/* no entropy available for automatic reseeding */
	ck_assert(!drbg->generate(drbg, 256, 128, out.ptr));
	drbg->destroy(drbg);

	/* no entropy available for DRBG instantiation */
	drbg = ntru_drbg_create(256, chunk_empty, entropy);
	ck_assert(drbg == NULL);
	entropy->destroy(entropy);

	/* one automatic reseeding occurs */
	entropy = test_rng_create(drbg_tests[0].entropy);
	drbg = ntru_drbg_create(256, chunk_empty, entropy);
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));
	ck_assert(drbg->generate(drbg, 256, 128, out.ptr));

	/* no entropy left */
	ck_assert(!entropy->get_bytes(entropy, 32, out.ptr));

	drbg->destroy(drbg);
	entropy->destroy(entropy);
	chunk_free(&out);
	lib->settings->set_int(lib->settings,
						  "libstrongswan.plugins.ntru.max_drbg_requests", 2000);
}
END_TEST

typedef struct {
	uint8_t c_bits;
	uint16_t N;
	uint16_t q;
	bool is_product_form;
	uint32_t indices_len;
	uint32_t indices_size;
	uint16_t *indices;
} poly_test_t;

typedef struct {
	hash_algorithm_t alg;
	size_t hash_size;
	size_t ml1, ml2, ml3, seed_len;
	chunk_t seed;
	chunk_t hashed_seed;
	chunk_t mask;
	chunk_t trits;
	poly_test_t poly_test[2];
} mgf1_test_t;

uint16_t indices_ees439ep1[] = {
	367, 413,  16, 214, 114, 128,  42, 268, 346, 329, 119, 303, 208, 287, 150,
	  3,  45, 321, 110, 109, 272, 430,  80, 305,  51, 381, 322, 140, 207, 315,
	206, 186,  56,   5, 273, 177,  44, 100, 205, 210,  98, 191,   8, 336
};

uint16_t indices_ees613ep1[] = {
	245, 391, 251, 428, 301,   2, 176, 296, 461, 224, 590, 215, 250,  91, 395,
	363,  58, 537, 278, 291, 247,  33, 140, 447, 172, 514, 424, 412,  95,  94,
	281, 159, 196, 302, 277,  63, 404, 150, 608, 315, 195, 334, 207, 376, 398,
	  0, 309, 486, 516,  86, 267, 139, 130,  38, 141, 258,  21, 341, 526, 388,
	194, 116, 138, 524, 547, 383, 542, 406, 270, 438, 240, 445, 527, 168, 320,
	186, 327, 212, 543,  82, 606, 131, 294, 392, 477, 430, 583, 142, 253, 434,
	134, 458, 559, 414, 162, 407, 580, 577, 191, 109, 554, 523,  32,  62, 297,
	283, 268,  54, 539,   5
};

uint16_t indices_ees743ep1[] = {
	285,  62, 136, 655, 460,  35, 450, 208, 340, 212,  61, 234, 454,  52, 520,
	399, 315, 616, 496,  88, 280, 543, 508, 237, 553,  39, 214, 253, 720, 291,
	586, 615, 635, 596,  62, 499, 301, 176, 271, 659, 372, 185, 621, 350, 683,
	180, 717, 509, 641, 738, 666, 171, 639, 606, 353, 706, 237, 358, 410, 423,
	197, 501, 261, 654, 658, 701, 377, 182, 548, 287, 700, 403, 248, 137
};

uint16_t indices_ees1171ep1[] = {
	514, 702, 760, 505, 262, 486, 695, 783, 533,  74, 403, 847, 170,1019, 568,
	676,1057, 277,1021, 238, 203, 884, 124,  87,  65,  93, 131, 881,1102, 133,
	459, 462,  92,  40,   5,1152,1158, 297, 599, 299,   7, 458, 347, 343, 173,
   1044, 264, 871, 819, 679, 328, 438, 990, 982, 308,1135, 423, 470, 254, 295,
   1029, 892, 759, 789, 123, 939, 749, 353,1062, 145, 562, 337, 550, 102, 549,
	821,1098, 823,  96, 365, 135,1110, 334, 391, 638, 963, 962,1002,1069, 993,
	983, 649,1056, 399, 385, 715, 582, 799, 161, 512, 629, 979, 250,  37, 213,
	929, 413, 566, 336, 727, 160, 616,1170, 748, 282,1115, 325, 994, 189, 500,
	913, 332,1118, 753, 946, 775,  59, 809, 782, 612, 909,1090, 223, 777, 940,
	866,1032, 471, 298, 969, 192, 411, 721, 476, 910,1045,1027, 812, 352, 487,
	215, 625, 808, 230, 602, 457, 900, 416, 985, 850, 908, 155, 670, 669,1054,
	400,1126, 733, 647, 786, 195, 148, 362,1094, 389,1086,1166, 231, 436, 210,
	333, 824, 785, 826, 658, 472, 639,1046,1028, 519, 422,  80, 924,1089, 547,
   1157, 579,   2, 508,1040, 998, 902,1058, 600, 220, 805, 945, 140,1117, 179,
	536, 191
};

/**
 * MGF1 Mask Generation Function Test Vectors
 */
mgf1_test_t mgf1_tests[] = {
	{	HASH_SHA1, 20, 60, 20, 15, 24,
		chunk_from_chars( 
						0xED, 0xA5, 0xC3, 0xBC, 0xAF, 0xB3, 0x20, 0x7D,
						0x14, 0xA1, 0x54, 0xF7, 0x8B, 0x37, 0xF2, 0x8D,
						0x8C, 0x9B, 0xD5, 0x63, 0x57, 0x38, 0x11, 0xC2,
						0xB5, 0xCA, 0xBF, 0x06, 0x43, 0x45, 0x19, 0xD5,
						0xE7, 0x36, 0xD0, 0x29, 0x21, 0xDA, 0x02, 0x20,
						0x45, 0xF6, 0x5F, 0x0F, 0x10, 0x04, 0x2A, 0xE3,
						0x6A, 0x1D, 0xD5, 0x9F, 0x1D, 0x66, 0x44, 0x8F,
						0xFA, 0xC6, 0xCA, 0xA4, 0x6E, 0x3B, 0x00, 0x66,
						0xA6, 0xC9, 0x80, 0x5C, 0xF5, 0x2D, 0xD7, 0x72,
						0xC6, 0xD4, 0x4F, 0x30, 0x72, 0xA2, 0xAD, 0xE0,
						0x33, 0xE8, 0x55, 0xD5, 0xE6, 0xD6, 0x00, 0x1D,
						0xA8, 0x68, 0xFF, 0x97, 0x36, 0x8A, 0xF4, 0xD6,
						0xF1, 0xB6, 0x7E, 0x1F, 0x06, 0xCB, 0x57, 0xCB,
						0x35, 0x38, 0xF2, 0x2D, 0xF6, 0x20),
		chunk_from_chars(
						0xF3, 0x9B, 0x0B, 0xB4, 0x97, 0x50, 0xB5, 0xA7,
						0xE6, 0xBD, 0xDA, 0xD0, 0x9A, 0x52, 0xBE, 0xA0,
						0x21, 0xC4, 0x90, 0xB6),
		chunk_from_chars(
						0x10, 0x43, 0x76, 0x72, 0x6C, 0xDE, 0xA0, 0x0E,
						0x77, 0x51, 0xFB, 0x58, 0x39, 0x8A, 0x36, 0xE1,
						0x63, 0x2B, 0xC9, 0x17, 0x56, 0x0C, 0x4B, 0x46,
						0xA4, 0x07, 0xA4, 0x3B, 0x8E, 0x33, 0x4D, 0xD1,
						0x65, 0xF1, 0xAC, 0xC8, 0x59, 0x21, 0x32, 0x16,
						0x44, 0x2B, 0x7F, 0xB2, 0xA8, 0xA7, 0x26, 0x5D,
						0xE8, 0x02, 0xBE, 0x8E, 0xDC, 0x34, 0xEB, 0x10,
						0x76, 0x16, 0x8C, 0xDD, 0x90, 0x92, 0x3D, 0x29,
						0x90, 0x98, 0x46, 0x11, 0x73, 0x53, 0x47, 0xB1,
						0x2C, 0xD4, 0x83, 0x78, 0x9B, 0x93, 0x2F, 0x5B,
						0xFC, 0x26, 0xFF, 0x42, 0x08, 0x1F, 0x70, 0x66,
						0x40, 0x4B, 0xE7, 0x22, 0x3A, 0x56, 0x10, 0x6D,
						0x4D, 0x29, 0x0B, 0xCE, 0xA6, 0x21, 0xB5, 0x5C,
						0x71, 0x66, 0x2F, 0x70, 0x35, 0xD8, 0x8A, 0x92,
						0x33, 0xF0, 0x16, 0xD4, 0x0E, 0x43, 0x8A, 0x14), 
		chunk_from_chars(
				1, 2, 1, 0, 0,  1, 1, 1, 2, 0,  1, 0, 1, 1, 1,  0, 2, 0, 1, 1,
				0, 0, 0, 1, 1,  0, 2, 0, 2, 2,	1, 2, 2, 2, 1,  2, 1, 1, 0, 0,
				2, 0, 1, 1, 1,	0, 0, 0, 0, 1,  1, 2, 0, 0, 1,  0, 1, 0, 2, 0,
				0, 1, 0, 2, 1,  0, 0, 0, 2, 0,  0, 0, 1, 2, 2,	0, 0, 2, 0, 1,
				1, 2, 1, 1, 0,  0, 1, 1, 1, 2,	2, 1, 2, 0, 0,  2, 1, 0, 0, 1,
				0, 1, 1, 0, 0,	0, 1, 2, 2, 0,  1, 2, 1, 2, 0,  2, 0, 0, 0, 2,
				1, 2, 0, 0, 0,  2, 0, 0, 0, 2,  2, 1, 0, 2, 0,	1, 2, 0, 2, 1,
				0, 2, 2, 1, 0,  2, 1, 2, 2, 0,  2, 0, 2, 1, 2,  2, 0, 2, 0, 1,
				1, 2, 2, 2, 2,  1, 0, 1, 0, 2,  2, 0, 1, 1, 2,  2, 2, 0, 0, 1,
				0, 2, 0, 1, 0,  2, 1, 2, 1, 0,  1, 1, 2, 0, 0,  2, 1, 1, 2, 0,
				1, 2, 1, 1, 0,  1, 0, 2, 1, 1,  1, 2, 1, 0, 2,  0, 2, 0, 0, 2,
				2, 1, 0, 0, 2,  2, 0, 1, 1, 0,  0, 1, 1, 0, 1,  1, 2, 1, 2, 2,
				2, 0, 0, 0, 0,  1, 0, 0, 1, 2,  1, 2, 0, 2, 1,  1, 1, 0, 2, 2,
				1, 2, 2, 1, 0,  1, 0, 2, 2, 2,  1, 2, 1, 0, 0,  1, 0, 1, 1, 1,
				1, 1, 2, 0, 0,  2, 1, 0, 2, 1,  2, 1, 0, 2, 2,  0, 0, 1, 2, 1,
				2, 0, 1, 2, 1,  1, 2, 0, 2, 0,  2, 1, 1, 1, 0,  0, 0, 1, 2, 1,
				2, 2, 1, 2, 1,  1, 2, 1, 2, 0,  2, 2, 1, 0, 0,  1, 2, 0, 1, 1,
				2, 0, 0, 0, 1,  2, 2, 1, 2, 0,  0, 2, 1, 0, 2,  2, 2, 1, 1, 0,
				2, 1, 2, 1, 2,  2, 1, 2, 1, 1,  0, 1, 1, 1, 1,  2, 0, 2, 2, 1,
				0, 1, 1, 2, 1,  2, 0, 2, 1, 0,  1, 0, 1, 0, 1,  2, 0, 1, 1, 0,
				0, 1, 1, 2, 0,  2, 2, 0, 0, 0,  1, 1, 0, 1, 0,  1, 1, 0, 1, 1,
				0, 1, 2, 0, 1,  1, 0, 1, 2, 0,  0, 1, 2, 2, 0,  0, 2, 1, 2),
		{
			{	9, 439, 2048, TRUE, 9 + (8 << 8) + (5 << 16),
				countof(indices_ees439ep1), indices_ees439ep1
			},
			{	11, 613, 2048, FALSE, 55,
				countof(indices_ees613ep1), indices_ees613ep1
			}
		}
	},
	{	HASH_SHA256, 32, 64, 32, 33, 40,
		chunk_from_chars(
						0x52, 0xC5, 0xDD, 0x1E, 0xEF, 0x76, 0x1B, 0x53,
						0x08, 0xE4, 0x86, 0x3F, 0x91, 0x12, 0x98, 0x69,
						0xC5, 0x9D, 0xDE, 0xF6, 0xFC, 0xFA, 0x93, 0xCE,
						0x32, 0x52, 0x66, 0xF9, 0xC9, 0x97, 0xF6, 0x42,
						0x00, 0x2C, 0x64, 0xED, 0x1A, 0x6B, 0x14, 0x0A,
						0x4B, 0x04, 0xCF, 0x6D, 0x2D, 0x82, 0x0A, 0x07,
						0xA2, 0x3B, 0xDE, 0xCE, 0x19, 0x8A, 0x39, 0x43,
						0x16, 0x61, 0x29, 0x98, 0x68, 0xEA, 0xE5, 0xCC,
						0x0A, 0xF8, 0xE9, 0x71, 0x26, 0xF1, 0x07, 0x36,
						0x2C, 0x07, 0x1E, 0xEB, 0xE4, 0x28, 0xA2, 0xF4,
						0xA8, 0x12, 0xC0, 0xC8, 0x20, 0x37, 0xF8, 0xF2,
						0x6C, 0xAF, 0xDC, 0x6F, 0x2E, 0xD0, 0x62, 0x58,
						0xD2, 0x37, 0x03, 0x6D, 0xFA, 0x6E, 0x1A, 0xAC,
						0x9F, 0xCA, 0x56, 0xC6, 0xA4, 0x52, 0x41, 0xE8,
						0x0F, 0x1B, 0x0C, 0xB9, 0xE6, 0xBA, 0xDE, 0xE1,
						0x03, 0x5E, 0xC2, 0xE5, 0xF8, 0xF4, 0xF3, 0x46,
						0x3A, 0x12, 0xC0, 0x1F, 0x3A, 0x00, 0xD0, 0x91,
						0x18, 0xDD, 0x53, 0xE4, 0x22, 0xF5, 0x26, 0xA4,
						0x54, 0xEE, 0x20, 0xF0, 0x80),
		chunk_from_chars(
						0x76, 0x89, 0x8B, 0x1B, 0x60, 0xEC, 0x10, 0x9D,
						0x8F, 0x13, 0xF2, 0xFE, 0xD9, 0x85, 0xC1, 0xAB,
						0x7E, 0xEE, 0xB1, 0x31, 0xDD, 0xF7, 0x7F, 0x0C,
						0x7D, 0xF9, 0x6B, 0x7B, 0x19, 0x80, 0xBD, 0x28), 
		chunk_from_chars(
						0xF1, 0x19, 0x02, 0x4F, 0xDA, 0x58, 0x05, 0x9A,
						0x07, 0xDF, 0x61, 0x81, 0x22, 0x0E, 0x15, 0x46,
						0xCB, 0x35, 0x3C, 0xDC, 0xAD, 0x20, 0xD9, 0x3F,
						0x0D, 0xD1, 0xAA, 0x64, 0x66, 0x5C, 0xFA, 0x4A,
						0xFE, 0xD6, 0x8F, 0x55, 0x57, 0x15, 0xB2, 0xA6,
						0xA0, 0xE6, 0xA8, 0xC6, 0xBD, 0x28, 0xB4, 0xD5,
						0x6E, 0x5B, 0x4B, 0xB0, 0x97, 0x09, 0xF5, 0xAC,
						0x57, 0x65, 0x13, 0x97, 0x71, 0x2C, 0x45, 0x13,
						0x3D, 0xEE, 0xFB, 0xBF, 0xFE, 0xAF, 0xBB, 0x4B,
						0x0D, 0x5C, 0x45, 0xD4, 0x2F, 0x17, 0x92, 0x07,
						0x66, 0x11, 0xF5, 0x46, 0xF8, 0x0C, 0x03, 0x92,
						0xF5, 0xF5, 0xFF, 0xA4, 0xF3, 0x52, 0xF4, 0x08,
						0x2C, 0x49, 0x32, 0x1A, 0x93, 0x51, 0x98, 0xB6,
						0x94, 0x83, 0x39, 0xCF, 0x6B, 0x1F, 0x2F, 0xFC,
						0x2B, 0xFF, 0x10, 0x71, 0x7D, 0x35, 0x6C, 0xEA,
						0xC5, 0x66, 0xC7, 0x26, 0x7D, 0x9E, 0xAC, 0xDD,
						0x35, 0xD7, 0x06, 0x3F, 0x40, 0x82, 0xDA, 0xC3,
						0x2B, 0x3C, 0x91, 0x3A, 0x32, 0xF8, 0xB2, 0xC6,
						0x44, 0x4D, 0xCD, 0xB6, 0x54, 0x5F, 0x81, 0x95,
						0x59, 0xA1, 0xE5, 0x4E, 0xA5, 0x0A, 0x4A, 0x42),
		chunk_from_chars(
				1, 2, 2, 2, 2,  1, 2, 2, 0, 0,  2, 0, 0, 0, 0,  1, 2, 2, 2, 0,
				2, 0, 0, 2, 2,  1, 2, 0, 0, 1,  2, 1, 0, 0, 0,  1, 0, 2, 2, 1,
				1, 2, 0, 0, 0,  1, 2, 0, 2, 2,  1, 2, 1, 0, 1,  0, 1, 2, 1, 1,
				1, 2, 0, 1, 0,  2, 1, 1, 0, 0,  0, 1, 2, 0, 0,  1, 2, 1, 2, 0,
				2, 1, 1, 1, 2,  2, 2, 2, 1, 0,  0, 2, 0, 2, 0,  1, 1, 0, 2, 2,
				2, 0, 1, 0, 2,  2, 1, 0, 1, 0,  1, 0, 0, 2, 2,  0, 0, 1, 2, 0,
				1, 1, 1, 0, 0,  2, 0, 2, 1, 2,  2, 2, 0, 0, 2,  1, 0, 2, 0, 1,
				0, 1, 2, 0, 1,  2, 0, 1, 0, 1,  2, 0, 2, 2, 0,  1, 2, 2, 1, 2,
				2, 2, 0, 2, 1,  1, 1, 0, 0, 1,  0, 2, 0, 0, 1,  0, 1, 2, 0, 0,
				1, 2, 1, 0, 2,  1, 1, 0, 0, 2,  1, 2, 2, 2, 1,  2, 1, 1, 2, 2,
				0, 2, 0, 0, 2,  0, 0, 1, 1, 2,  0, 0, 0, 1, 2,  1, 1, 1, 1, 0,
				0, 0, 2, 0, 2,  0, 2, 2, 1, 2,  2, 0, 0, 1, 1,  1, 0, 1, 0, 1,
				0, 1, 2, 2, 0,  2, 1, 1, 0, 2,  1, 2, 1, 2, 1,  0, 0, 1, 0, 0,
				1, 0, 1, 0, 2,  0, 2, 0, 0, 1,  2, 0, 2, 0, 1,  1, 0, 2, 0, 0,
				1, 2, 1, 2, 1,  2, 1, 0, 1, 1,  2, 2, 1, 1, 0,  0, 2, 1, 2, 0,
				1, 0, 2, 0, 0,  1, 2, 0, 2, 0,  1, 1, 2, 2, 2,  2, 0, 0, 1, 2,
				1, 1, 1, 0, 2,  1, 2, 2, 0, 2,  0, 1, 2, 2, 0,  1, 1, 1, 0, 0,
				2, 0, 1, 0, 1,  0, 2, 1, 2, 0,  2, 1, 2, 1, 2,  2, 0, 2, 1, 0,
				2, 1, 2, 0, 0,  2, 0, 1, 2, 1,  1, 2, 0, 0, 0,  0, 1, 2, 0, 1,
				2, 2, 1, 0, 0,  1, 2, 1, 2, 0,  0, 1, 1, 0, 0,  0, 1, 0, 0, 0,
				2, 0, 1, 2, 1,  2, 0, 0, 0, 2,  1, 0, 0, 0, 1,  2, 2, 0, 0, 0,
				2, 2, 1, 1, 0,  1, 0, 2, 2, 0,  2, 1, 2, 1, 0,  2, 2, 2, 0, 0,
				0, 1, 1, 2, 1,  0, 0, 0, 0, 1,  2, 2, 1, 2, 1,  2, 0, 2, 0, 2,
				1, 1, 1, 2, 1,  2, 1, 2, 1, 1,  0, 1, 0, 2, 0,  0, 0, 2, 1, 2,
				2, 2, 2, 0, 1,  1, 1, 0, 1, 0,  2, 0, 2, 1, 0,  1, 2, 1, 1, 0,
				1, 2, 1, 0, 0,  2, 1, 0, 1, 1,  2, 2, 1, 1, 1,  2, 2, 2, 1, 0,
				0, 0, 0, 1, 1,  0, 0, 2, 2, 2,  2, 2, 0, 1, 2,  0, 1, 2, 0, 1,
				1, 0, 1, 1, 2,  2, 0, 1, 1, 0,  2, 2, 1, 1, 1,  2, 1, 2, 2, 1,
				1, 0, 1, 0, 2,  2, 1, 0, 2, 2,  2, 2, 2, 1, 0,  2, 2, 2, 1, 2,
				0, 2, 0, 0, 0,  0, 0, 1, 2, 0,  1, 0, 1),
		{
			{	13, 743, 2048, TRUE, 11 + (11 << 8) + (15 << 16),
				countof(indices_ees743ep1), indices_ees743ep1
			},
			{	12, 1171, 2048, FALSE, 106,
				countof(indices_ees1171ep1), indices_ees1171ep1
			}
		}
	}
};

START_TEST(test_ntru_mgf1)
{
	ntru_mgf1_t *mgf1;
	chunk_t mask, mask1, mask2, mask3;

	mask1 = mgf1_tests[_i].mask;
	mask2 = chunk_skip(mask1, mgf1_tests[_i].ml1);
	mask3 = chunk_skip(mask2, mgf1_tests[_i].ml2);
	mask1.len = mgf1_tests[_i].ml1;
	mask2.len = mgf1_tests[_i].ml2;
	mask3.len = mgf1_tests[_i].ml3;

	mgf1 = ntru_mgf1_create(HASH_UNKNOWN, mgf1_tests[_i].seed, TRUE);
	ck_assert(mgf1 == NULL);

	mgf1 = ntru_mgf1_create(mgf1_tests[_i].alg, chunk_empty, TRUE);
	ck_assert(mgf1 == NULL);

	/* return mask in allocated chunk */
	mgf1 = ntru_mgf1_create(mgf1_tests[_i].alg, mgf1_tests[_i].seed, TRUE);
	ck_assert(mgf1);

	/* check hash size */
	ck_assert(mgf1->get_hash_size(mgf1) == mgf1_tests[_i].hash_size);

	/* get zero number of octets */
	ck_assert(mgf1->allocate_mask(mgf1, 0, &mask));
	ck_assert(mask.len == 0 && mask.ptr == NULL);

	/* get non-zero number of octets */
	ck_assert(mgf1->allocate_mask(mgf1, mgf1_tests[_i].mask.len, &mask));
	ck_assert(chunk_equals(mask, mgf1_tests[_i].mask));
	mgf1->destroy(mgf1);

	/* copy mask to pre-allocated buffer */
	mgf1 = ntru_mgf1_create(mgf1_tests[_i].alg, mgf1_tests[_i].seed, TRUE);
	ck_assert(mgf1);
	ck_assert(mgf1->get_mask(mgf1, mgf1_tests[_i].mask.len, mask.ptr));
	ck_assert(chunk_equals(mask, mgf1_tests[_i].mask));
	mgf1->destroy(mgf1);

	/* get mask in batches without hashing the seed */
	mgf1 = ntru_mgf1_create(mgf1_tests[_i].alg, mgf1_tests[_i].hashed_seed, FALSE);
	ck_assert(mgf1);

	/* first batch */
	ck_assert(mgf1->get_mask(mgf1, mask1.len, mask.ptr));
	mask.len = mask1.len;
	ck_assert(chunk_equals(mask, mask1));

	/* second batch */
	ck_assert(mgf1->get_mask(mgf1, mask2.len, mask.ptr));
	mask.len = mask2.len;
	ck_assert(chunk_equals(mask, mask2));

	/* third batch */
	ck_assert(mgf1->get_mask(mgf1, mask3.len, mask.ptr));
	mask.len = mask3.len;
	ck_assert(chunk_equals(mask, mask3));

	mgf1->destroy(mgf1);
	chunk_free(&mask);
}
END_TEST

START_TEST(test_ntru_trits)
{
	ntru_trits_t *mask;
	chunk_t trits;

	mask = ntru_trits_create(mgf1_tests[_i].trits.len, HASH_UNKNOWN,
							 mgf1_tests[_i].seed);
	ck_assert(mask == NULL);

	mask = ntru_trits_create(mgf1_tests[_i].trits.len, mgf1_tests[_i].alg,
							 chunk_empty);
	ck_assert(mask == NULL);

	mask = ntru_trits_create(mgf1_tests[_i].trits.len, mgf1_tests[_i].alg,
							 mgf1_tests[_i].seed);
	ck_assert(mask);

	trits = chunk_create(mask->get_trits(mask), mask->get_size(mask));
	ck_assert(chunk_equals(trits, mgf1_tests[_i].trits));
	mask->destroy(mask);

	/* generate a multiple of 5 trits */
	mask = ntru_trits_create(10, mgf1_tests[_i].alg, mgf1_tests[_i].seed);
	ck_assert(mask);

	trits = chunk_create(mask->get_trits(mask), mask->get_size(mask));
	ck_assert(chunk_equals(trits, chunk_create(mgf1_tests[_i].trits.ptr, 10)));
	mask->destroy(mask);
}
END_TEST

START_TEST(test_ntru_poly)
{
	ntru_poly_t *poly;
	uint16_t *indices;
	chunk_t seed;
	poly_test_t *p;
	int j, n;

	seed = mgf1_tests[_i].seed;
	seed.len = mgf1_tests[_i].seed_len;

	p = &mgf1_tests[_i].poly_test[0];
	poly = ntru_poly_create_from_seed(HASH_UNKNOWN, seed, p->c_bits, p->N, p->q,
									  p->indices_len, p->indices_len,
									  p->is_product_form);
	ck_assert(poly == NULL);

	for (n = 0; n < 2; n++)
	{
		p = &mgf1_tests[_i].poly_test[n];
		poly = ntru_poly_create_from_seed(mgf1_tests[_i].alg, seed, p->c_bits,
										  p->N, p->q, p->indices_len,
										  p->indices_len, p->is_product_form);
		ck_assert(poly != NULL && poly->get_size(poly) == p->indices_size);

		indices = poly->get_indices(poly);
		for (j = 0; j < p->indices_size; j++)
		{
			ck_assert(indices[j] == p->indices[j]);
		}
		poly->destroy(poly);
	}
}
END_TEST

typedef struct {
	uint16_t N;
	uint16_t q;
	bool is_product_form;
	uint32_t indices_len_p;
	uint32_t indices_len_m;
	uint16_t *indices;
	uint16_t *a;
	uint16_t *c;
} ring_mult_test_t;

uint16_t t1_indices[] = { 1, 6, 5, 3 };

uint16_t t1_a[] = { 1, 0, 0, 0, 0, 0, 0 };
uint16_t t1_c[] = { 0, 1, 0, 7, 0, 7, 1 };

uint16_t t2_a[] = { 5, 0, 0, 0, 0, 0, 0 };
uint16_t t2_c[] = { 0, 5, 0, 3, 0, 3, 5 };

uint16_t t3_a[]  = { 4, 0, 0, 0, 0, 0, 0 };
uint16_t t3_c[]  = { 0, 4, 0, 4, 0, 4, 4 };

uint16_t t4_a[]  = { 0, 6, 0, 0, 0, 0, 0 };
uint16_t t4_c[]  = { 6, 0, 6, 0, 2, 0, 2 };

uint16_t t5_a[]  = { 4, 6, 0, 0, 0, 0, 0 };
uint16_t t5_c[]  = { 6, 4, 6, 4, 2, 4, 6 };

uint16_t t6_a[]  = { 0, 0, 3, 0, 0, 0, 0 };
uint16_t t6_c[]  = { 5, 3, 0, 3, 0, 5, 0 };

uint16_t t7_a[]  = { 4, 6, 3, 0, 0, 0, 0 };
uint16_t t7_c[]  = { 3, 7, 6, 7, 2, 1, 6 };

uint16_t t8_a[]  = { 0, 0, 0, 7, 0, 0, 0 };
uint16_t t8_c[]  = { 0, 1, 7, 0, 7, 0, 1 };

uint16_t t9_a[]  = { 4, 6, 3, 7, 0, 0, 0 };
uint16_t t9_c[]  = { 3, 0, 5, 7, 1, 1, 7 };

uint16_t t10_a[] = { 0, 0, 0, 0, 0, 1, 0 };
uint16_t t10_c[] = { 0, 7, 0, 7, 1, 0, 1 };

uint16_t t11_a[] = { 4, 6, 3, 7, 0, 1, 0 };
uint16_t t11_c[] = { 3, 7, 5, 6, 2, 1, 0 };

uint16_t t2_indices[] = { 1, 6, 5, 2, 3 };

uint16_t t12_c[] = { 0, 1, 7, 7, 0, 1, 1 };
uint16_t t13_c[] = { 0, 1, 7, 7, 0, 7, 1 };
uint16_t t14_c[] = { 0, 1, 0, 31, 0, 31, 1 };
uint16_t t15_c[] = { 0, 5, 0, 2043, 0, 2043, 5 };
uint16_t t16_c[] = { 0, 5, 0, 32763, 0, 32763, 5 };

uint16_t t3_indices[] = { 7, 2, 3, 5, 0, 2, 3, 10, 7, 0, 8, 2 };

uint16_t t17_a[] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint16_t t17_c[] = { 7, 1, 0, 1, 1, 7, 0, 7, 7, 7, 2 };

ring_mult_test_t ring_mult_tests[] = {
	{  7,     8, FALSE, 2, 2, t1_indices, t1_a,  t1_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t2_a,  t2_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t3_a,  t3_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t4_a,  t4_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t5_a,  t5_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t6_a,  t6_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t7_a,  t7_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t8_a,  t8_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t9_a,  t9_c  },
	{  7,     8, FALSE, 2, 2, t1_indices, t10_a, t10_c },
	{  7,     8, FALSE, 2, 2, t1_indices, t11_a, t11_c },
	{  7,     8, FALSE, 3, 2, t2_indices, t1_a,  t12_c },
	{  7,     8, FALSE, 2, 3, t2_indices, t1_a,  t13_c },
	{  7,    32, FALSE, 2, 2, t1_indices, t1_a,  t14_c },
	{  7,  2048, FALSE, 2, 2, t1_indices, t2_a,  t15_c },
	{  7, 32768, FALSE, 2, 2, t1_indices, t2_a,  t16_c },
	{ 11,     8, TRUE, 197121, 197121, t3_indices, t17_a,  t17_c },
};

START_TEST(test_ntru_ring_mult)
{
	ntru_poly_t *poly;
	ring_mult_test_t *t;
	uint16_t *c;
	int i;

	t = &ring_mult_tests[_i];
	poly = ntru_poly_create_from_data(t->indices, t->N, t->q, t->indices_len_p,
									  t->indices_len_m, t->is_product_form);
	ck_assert(poly != NULL);

	c = malloc(t->N * sizeof(uint16_t));
	poly->ring_mult(poly, t->a, c);

	for (i = 0; i < t->N; i++)
	{
		ck_assert(c[i] == t->c[i]);
	}

	free(c);
	poly->destroy(poly);
}
END_TEST

int array_tests[] = { 0, 11, 12, 16 };

START_TEST(test_ntru_array)
{
	ntru_poly_t *poly;
	ring_mult_test_t *t;
	uint16_t *c;
	int i;

	t = &ring_mult_tests[array_tests[_i]];

	poly = ntru_poly_create_from_data(t->indices, t->N, t->q, t->indices_len_p,
									  t->indices_len_m, t->is_product_form);
	ck_assert(poly != NULL);

	c = malloc(t->N * sizeof(uint16_t));
	poly->get_array(poly, c);

	for (i = 0; i < t->N; i++)
	{
		ck_assert(c[i] == t->c[i]);
	}

	free(c);
	poly->destroy(poly);
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

chunk_t oid_tests[] = {
	{ NULL, 0 },
	chunk_from_chars(0x00),
	chunk_from_chars(0x01),
	chunk_from_chars(0x02),
	chunk_from_chars(0x02, 0x03, 0x00, 0x03, 0x10),
	chunk_from_chars(0x01, 0x04, 0x00, 0x03, 0x10),
	chunk_from_chars(0x01, 0x03, 0x00, 0x03, 0x10),
	chunk_from_chars(0x01, 0x03, 0xff, 0x03, 0x10),
};

START_TEST(test_ntru_pubkey_oid)
{
	diffie_hellman_t *r_ntru;
	chunk_t cipher_text;

	r_ntru = lib->crypto->create_dh(lib->crypto, NTRU_128_BIT);
	r_ntru->set_other_public_value(r_ntru, oid_tests[_i]);
	r_ntru->get_my_public_value(r_ntru, &cipher_text);
	ck_assert(cipher_text.len == 0);
	r_ntru->destroy(r_ntru);
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

	tc = tcase_create("drbg_strength");
	tcase_add_loop_test(tc, test_ntru_drbg_strength, 0, countof(strengths));
	suite_add_tcase(s, tc);

	tc = tcase_create("drbg");
	tcase_add_loop_test(tc, test_ntru_drbg, 0, countof(drbg_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("drgb_reseed");
	tcase_add_test(tc, test_ntru_drbg_reseed);
	suite_add_tcase(s, tc);

	tc = tcase_create("mgf1");
	tcase_add_loop_test(tc, test_ntru_mgf1, 0, countof(mgf1_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("trits");
	tcase_add_loop_test(tc, test_ntru_trits, 0, countof(mgf1_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("poly");
	tcase_add_loop_test(tc, test_ntru_poly, 0, countof(mgf1_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("ring_mult");
	tcase_add_loop_test(tc, test_ntru_ring_mult, 0, countof(ring_mult_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("array");
	tcase_add_loop_test(tc, test_ntru_array, 0, countof(array_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("ke");
	tcase_add_loop_test(tc, test_ntru_ke, 0, countof(params));
	suite_add_tcase(s, tc);

	tc = tcase_create("retransmission");
	tcase_add_test(tc, test_ntru_retransmission);
	suite_add_tcase(s, tc);

	tc = tcase_create("pubkey_oid");
	tcase_add_loop_test(tc, test_ntru_pubkey_oid, 0, countof(oid_tests));
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
