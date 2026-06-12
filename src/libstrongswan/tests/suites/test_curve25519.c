/*
 * Copyright (C) 2026 Tobias Brunner
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

static chunk_t all_zero = chunk_from_chars(
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

START_TEST(test_reject_all_zero_secret)
{
	key_exchange_t *ke;
	chunk_t secret;

	ke = lib->crypto->create_ke(lib->crypto, CURVE_25519);
	ck_assert(ke);

	/* implementations might already reject setting the public key */
	ignore_result(ke->set_public_key(ke, all_zero));
	ck_assert(!ke->get_shared_secret(ke, &secret));

	ke->destroy(ke);
}
END_TEST

Suite *curve25519_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("curve25519");

	tc = tcase_create("curve25519_secret");
	tcase_add_test(tc, test_reject_all_zero_secret);
	suite_add_tcase(s, tc);

	return s;
}
