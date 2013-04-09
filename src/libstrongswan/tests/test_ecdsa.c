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
	pubkey->destroy(pubkey);
	privkey->destroy(privkey);
}
END_TEST

Suite *ecdsa_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ecdsa");

	tc = tcase_create("generate");
	tcase_add_loop_test(tc, test_gen, 0, countof(key_sizes));
	suite_add_tcase(s, tc);

	return s;
}
