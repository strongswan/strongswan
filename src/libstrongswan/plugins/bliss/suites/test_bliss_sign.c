/*
 * Copyright (C) 2014 Andreas Steffen
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

#include <bliss_private_key.h>
#include <bliss_public_key.h>

static u_int key_type[] = { 1, 3, 4 };

START_TEST(test_bliss_sign_all)
{
	private_key_t *privkey;
	public_key_t *pubkey;
	chunk_t msg, signature;
	int verify_count = 1000;
	
	msg = chunk_from_str("Hello Dolly!");
	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_BLISS,
								 BUILD_KEY_SIZE, key_type[_i], BUILD_END);
	ck_assert(privkey);

	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey);

	while (verify_count--)
	{
		ck_assert(privkey->sign(privkey, SIGN_BLISS_WITH_SHA512, msg,
								&signature));
		ck_assert(pubkey->verify(pubkey, SIGN_BLISS_WITH_SHA512, msg,
								 signature));
		free(signature.ptr);
	}
	privkey->destroy(privkey);
	pubkey->destroy(pubkey);
}
END_TEST

Suite *bliss_sign_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("bliss_sign");

	tc = tcase_create("all");
	test_case_set_timeout(tc, 30);
	tcase_add_loop_test(tc, test_bliss_sign_all, 0, countof(key_type));
	suite_add_tcase(s, tc);

	return s;
}
