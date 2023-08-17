/*
 * Copyright (C) 2018-2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include <oqs_kem.h>

#include <library.h>

#include <time.h>

const int count = 20;

/**
  * Skip non-supported KE algorithms
  */
static bool unsupported(key_exchange_method_t method)
{
	switch(method)
	{
		default:
			return FALSE;
	}
}

START_TEST(test_oqs_good)
{
	chunk_t i_msg, r_msg, i_shared_secret, r_shared_secret;
	key_exchange_method_t method = _i;
	key_exchange_t *i_ke, *r_ke;
	struct timespec start, stop;
	int k;

	if (unsupported(method))
	{
		return;
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	for (k = 0; k < count; k++)
	{
		i_ke = (key_exchange_t*)oqs_kem_create(method);
		ck_assert(i_ke != NULL);
		ck_assert(i_ke->get_method(i_ke) == method);

		if (k == 0)
		{
			ck_assert(i_ke->get_public_key(i_ke, &i_msg));
			chunk_free(&i_msg);
		}
		ck_assert(i_ke->get_public_key(i_ke, &i_msg));

		r_ke = (key_exchange_t*)oqs_kem_create(method);
		ck_assert(r_ke != NULL);

		if (k == 0)
		{
			ck_assert(r_ke->set_public_key(r_ke, i_msg));
		}
		ck_assert(r_ke->set_public_key(r_ke, i_msg));

		if (k == 0)
		{
			ck_assert(r_ke->get_public_key(r_ke, &r_msg));
			chunk_free(&r_msg);
		}
		ck_assert(r_ke->get_public_key(r_ke, &r_msg));
		ck_assert(r_ke->get_shared_secret(r_ke, &r_shared_secret));

		if (k == 0)
		{
			ck_assert(i_ke->set_public_key(i_ke, r_msg));
		}
		ck_assert(i_ke->set_public_key(i_ke, r_msg));
		ck_assert(i_ke->get_shared_secret(i_ke, &i_shared_secret));
		ck_assert_chunk_eq(i_shared_secret, r_shared_secret);

		/* cleanup */
		chunk_clear(&i_shared_secret);
		chunk_clear(&r_shared_secret);
		chunk_free(&i_msg);
		chunk_free(&r_msg);
		i_ke->destroy(i_ke);
		r_ke->destroy(r_ke);
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &stop);

	DBG0(DBG_LIB, "\n%d %N loops in %d ms", count,
				  key_exchange_method_names, method,
				  (stop.tv_nsec - start.tv_nsec) / 1000000 +
				  (stop.tv_sec - start.tv_sec) * 1000);
}
END_TEST

START_TEST(test_oqs_wrong)
{
	chunk_t i_msg, r_msg, i_shared_secret = chunk_empty, r_shared_secret;
	key_exchange_t *i_ke, *r_ke;
	key_exchange_method_t method = _i;

	if (unsupported(method))
	{
		return;
	}

	/* test non-kem method */
	if (method == KE_KYBER_L1)
	{
		ck_assert(!oqs_kem_create(CURVE_25519));
	}

	/* create initiator */
	i_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(i_ke != NULL);
	ck_assert(i_ke->get_public_key(i_ke, &i_msg));

	/* create responder */
	r_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(r_ke != NULL);

	ck_assert(r_ke->set_public_key(r_ke, i_msg));
	ck_assert(r_ke->get_public_key(r_ke, &r_msg));
	ck_assert(r_ke->get_shared_secret(r_ke, &r_shared_secret));

	DBG0(DBG_LIB, "\n%N shared secret length of %u bytes",
				   key_exchange_method_names, method, r_shared_secret.len);

	/* destroy 1st instance of i_ke */
	i_ke->destroy(i_ke);
	chunk_free(&i_msg);

	/* create 2nd instance of i_ke */
	i_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(i_ke != NULL);

	ck_assert(i_ke->get_public_key(i_ke, &i_msg));
	if (i_ke->set_public_key(i_ke, r_msg))
	{
		ck_assert(i_ke->get_shared_secret(i_ke, &i_shared_secret));
		ck_assert(!chunk_equals(i_shared_secret, r_shared_secret));
	}

	/* cleanup */
	chunk_free(&i_msg);
	chunk_free(&r_msg);
	chunk_clear(&i_shared_secret);
	chunk_clear(&r_shared_secret);
	i_ke->destroy(i_ke);
	r_ke->destroy(r_ke);
}
END_TEST

START_TEST(test_oqs_fail_i)
{
	key_exchange_t *i_ke, *r_ke;
	key_exchange_method_t method = _i;
	char buf_ff[16384];
	chunk_t i_msg, r_msg, fail_msg;

	if (unsupported(method))
	{
		return;
	}

	memset(buf_ff, 0xff, sizeof(buf_ff));
	fail_msg = chunk_create(buf_ff, sizeof(buf_ff));

	i_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(i_ke != NULL);
	ck_assert(i_ke->get_public_key(i_ke, &i_msg));

	r_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(r_ke != NULL);
	ck_assert(r_ke->set_public_key(r_ke, i_msg));
	ck_assert(r_ke->get_public_key(r_ke, &r_msg));

	DBG0(DBG_LIB, "\n%N ciphertext length of %u bytes",
		 key_exchange_method_names, method, r_msg.len);
	fail_msg.len = 0;
	ck_assert(!i_ke->set_public_key(i_ke, fail_msg));
	fail_msg.len = 1;
	ck_assert(!i_ke->set_public_key(i_ke, fail_msg));
	fail_msg.len = r_msg.len - 1;
	ck_assert(!i_ke->set_public_key(i_ke, fail_msg));
	fail_msg.len = r_msg.len + 1;
	ck_assert(!i_ke->set_public_key(i_ke, fail_msg));

	chunk_free(&i_msg);
	chunk_free(&r_msg);
	i_ke->destroy(i_ke);
	r_ke->destroy(r_ke);
}
END_TEST

START_TEST(test_oqs_fail_r)
{
	key_exchange_t *i_ke, *r_ke;
	key_exchange_method_t method = _i;
	char buf_ff[18432];
	chunk_t i_msg, fail_msg;

	if (unsupported(method))
	{
		return;
	}

	memset(buf_ff, 0xff, sizeof(buf_ff));
	fail_msg = chunk_create(buf_ff, sizeof(buf_ff));

	i_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(i_ke != NULL);
	ck_assert(i_ke->get_public_key(i_ke, &i_msg));

	r_ke = (key_exchange_t*)oqs_kem_create(method);
	ck_assert(r_ke != NULL);

	DBG0(DBG_LIB, "\n%N public key length of %u bytes",
				   key_exchange_method_names, method, i_msg.len);
	fail_msg.len = 0;
	ck_assert(!r_ke->set_public_key(r_ke, fail_msg));
	fail_msg.len = 1;
	ck_assert(!r_ke->set_public_key(r_ke, fail_msg));
	fail_msg.len = i_msg.len - 1;
	ck_assert(!r_ke->set_public_key(r_ke, fail_msg));
	fail_msg.len = i_msg.len + 1;
	ck_assert(!r_ke->set_public_key(r_ke, fail_msg));

	chunk_free(&i_msg);
	i_ke->destroy(i_ke);
	r_ke->destroy(r_ke);
}
END_TEST

Suite *oqs_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("oqs");

	tc = tcase_create("good");
	test_case_set_timeout(tc, 30);
	tcase_add_loop_test(tc, test_oqs_good, KE_KYBER_L1, KE_HQC_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("wrong");
	tcase_add_loop_test(tc, test_oqs_wrong, KE_KYBER_L1, KE_HQC_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("fail_i");
	tcase_add_loop_test(tc, test_oqs_fail_i, KE_KYBER_L1, KE_HQC_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("fail_r");
	tcase_add_loop_test(tc, test_oqs_fail_r, KE_KYBER_L1, KE_HQC_L5 + 1);
	suite_add_tcase(s, tc);

	return s;
}
