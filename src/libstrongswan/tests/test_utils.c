/*
 * Copyright (C) 2013 Tobias Brunner
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

#include <library.h>

/*******************************************************************************
 * object storage on lib
 */

START_TEST(test_objects)
{
	char *k1 = "key1", *k2 = "key2";
	char *v1 = "val1", *val;

	ck_assert(lib->get(lib, k1) == NULL);

	ck_assert(lib->set(lib, k1, v1));
	ck_assert(!lib->set(lib, k1, v1));

	val = lib->get(lib, k1);
	ck_assert(val != NULL);
	ck_assert(streq(val, v1));

	ck_assert(lib->set(lib, k1, NULL));
	ck_assert(!lib->set(lib, k2, NULL));

	ck_assert(lib->get(lib, k1) == NULL);
}
END_TEST

Suite *utils_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("utils");

	tc = tcase_create("objects");
	tcase_add_test(tc, test_objects);
	suite_add_tcase(s, tc);

	return s;
}
