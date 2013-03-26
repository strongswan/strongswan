/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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


#include <check.h>

#include <utils/chunk.h>

/*******************************************************************************
 * BASE64 encoding test
 */

START_TEST(test_base64)
{
	/* test vectors from RFC4648:
	 *
	 * BASE64("") = ""
	 * BASE64("f") = "Zg=="
	 * BASE64("fo") = "Zm8="
	 * BASE64("foo") = "Zm9v"
	 * BASE64("foob") = "Zm9vYg=="
	 * BASE64("fooba") = "Zm9vYmE="
	 * BASE64("foobar") = "Zm9vYmFy"
	 */
	typedef struct {
		char *in;
		char *out;
	} testdata_t;

	testdata_t test[] = {
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
	};
	int i;

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_to_base64(chunk_create(test[i].in, strlen(test[i].in)), NULL);
		ck_assert_str_eq(out.ptr, test[i].out);
		free(out.ptr);
	}

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_from_base64(chunk_create(test[i].out, strlen(test[i].out)), NULL);
		fail_unless(strneq(out.ptr, test[i].in, out.len),
					"base64 conversion error - should '%s', is %#B",
					test[i].in, &out);
		free(out.ptr);
	}
}
END_TEST

Suite *chunk_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("chunk");

	tc = tcase_create("base64");
	tcase_add_test(tc, test_base64);
	suite_add_tcase(s, tc);

	return s;
}
