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

START_TEST(test_ke)
{
	chunk_t pub_key, cipher_text, i_shared_secret, r_shared_secret;
	diffie_hellman_t *i_ntru, *r_ntru;
	char buf[10];
	int len;
	status_t status;
	
	len = snprintf(buf, sizeof(buf), "%N", diffie_hellman_group_names,
				   params[_i].group);
	ck_assert(len == 8);
	ck_assert(streq(buf, params[_i].group_name));

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

	i_ntru->set_other_public_value(i_ntru, cipher_text);
	status = i_ntru->get_shared_secret(i_ntru, &i_shared_secret);
	ck_assert(status == SUCCESS);
	ck_assert(i_shared_secret.len > 0);

	status = r_ntru->get_shared_secret(r_ntru, &r_shared_secret);
	ck_assert(status == SUCCESS);
	ck_assert(r_shared_secret.len > 0);

	ck_assert(chunk_equals(i_shared_secret, r_shared_secret));

	chunk_clear(&i_shared_secret);
	chunk_clear(&r_shared_secret);
	chunk_free(&pub_key);
	chunk_free(&cipher_text);
	i_ntru->destroy(i_ntru);
	r_ntru->destroy(r_ntru);
}
END_TEST

Suite *ntru_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ntru");

	tc = tcase_create("ke");
	tcase_add_loop_test(tc, test_ke, 0, countof(params));
	suite_add_tcase(s, tc);

	return s;
}
