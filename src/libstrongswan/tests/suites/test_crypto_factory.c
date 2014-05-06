/*
 * Copyright (C) 2014 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include <crypto/crypto_factory.h>

static rng_t *rng_create(rng_quality_t quality)
{
	rng_quality_t *q = malloc_thing(rng_quality_t);
	*q = quality;
	return (rng_t*)q;
}

static rng_t *rng_create_weak(rng_quality_t quality)
{
	ck_assert(quality == RNG_WEAK);
	return rng_create(RNG_WEAK);
}

static rng_t *rng_create_strong(rng_quality_t quality)
{
	ck_assert(quality <= RNG_STRONG);
	return rng_create(RNG_STRONG);
}

static rng_t *rng_create_true(rng_quality_t quality)
{
	ck_assert(quality <= RNG_TRUE);
	return rng_create(RNG_TRUE);
}

static rng_t *rng_create_true_second(rng_quality_t quality)
{
	fail("should never be called");
	return rng_create(RNG_TRUE);
}

static rng_quality_t rng_weak = RNG_WEAK;
static rng_quality_t rng_strong = RNG_STRONG;
static rng_quality_t rng_true = RNG_TRUE;

static struct {
	rng_quality_t *exp_weak;
	rng_quality_t *exp_strong;
	rng_quality_t *exp_true;
	struct {
		rng_quality_t *q;
		rng_constructor_t create;
	} data[4];
} rng_data[] = {
	{ NULL, NULL, NULL, {
		{ NULL, NULL }
	}},
	{ &rng_weak, NULL, NULL, {
		{ &rng_weak, rng_create_weak },
		{ NULL, NULL }
	}},
	{ &rng_strong, &rng_strong, NULL, {
		{ &rng_strong, rng_create_strong },
		{ NULL, NULL }
	}},
	{ &rng_true, &rng_true, &rng_true, {
		{ &rng_true, rng_create_true },
		{ NULL, NULL }
	}},
	{ &rng_true, &rng_true, &rng_true, {
		{ &rng_true, rng_create_true },
		{ &rng_true, rng_create_true_second },
		{ NULL, NULL }
	}},
	{ &rng_weak, &rng_true, &rng_true, {
		{ &rng_weak, rng_create_weak },
		{ &rng_true, rng_create_true },
		{ NULL, NULL }
	}},
	{ &rng_weak, &rng_strong, &rng_true, {
		{ &rng_true, rng_create_true },
		{ &rng_strong, rng_create_strong },
		{ &rng_weak, rng_create_weak },
		{ NULL, NULL }
	}},
	{ &rng_weak, &rng_strong, &rng_true, {
		{ &rng_weak, rng_create_weak },
		{ &rng_strong, rng_create_strong },
		{ &rng_true, rng_create_true },
		{ NULL, NULL }
	}},
};

static void verify_rng(crypto_factory_t *factory, rng_quality_t request,
					   rng_quality_t *expected)
{
	rng_quality_t *res;

	res = (rng_quality_t*)factory->create_rng(factory, request);
	if (!expected)
	{
		ck_assert(!res);
	}
	else
	{
		ck_assert(res);
		ck_assert_int_eq(*expected, *res);
		free(res);
	}
}

START_TEST(test_create_rng)
{
	crypto_factory_t *factory;
	int i;

	factory = crypto_factory_create();
	for (i = 0; rng_data[_i].data[i].q; i++)
	{
		ck_assert(factory->add_rng(factory, *rng_data[_i].data[i].q, "test",
								   rng_data[_i].data[i].create));
	}
	verify_rng(factory, RNG_WEAK, rng_data[_i].exp_weak);
	verify_rng(factory, RNG_STRONG, rng_data[_i].exp_strong);
	verify_rng(factory, RNG_TRUE, rng_data[_i].exp_true);
	for (i = 0; rng_data[_i].data[i].q; i++)
	{
		factory->remove_rng(factory, rng_data[_i].data[i].create);
	}
	factory->destroy(factory);
}
END_TEST

Suite *crypto_factory_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("crypto-factory");

	tc = tcase_create("create_rng");
	tcase_add_loop_test(tc, test_create_rng, 0, countof(rng_data));
	suite_add_tcase(s, tc);

	return s;
}
