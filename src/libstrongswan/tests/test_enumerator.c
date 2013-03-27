/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2007 Martin Willi
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

#include <collections/enumerator.h>
#include <collections/linked_list.h>

/*******************************************************************************
 * token test
 */

static const char *token_results1[] = { "abc", "cde", "efg" };
static const char *token_results2[] = { "a", "b", "c" };

static struct {
	char *string;
	char *sep;
	char *trim;
	const char **results;
} token_tests[] = {
	{"abc, cde, efg", ",", " ", token_results1},
	{" abc 1:2 cde;3  4efg5.  ", ":;.,", " 12345", token_results1},
	{"abc.cde,efg", ",.", "", token_results1},
	{"  abc   cde  efg  ", " ", " ", token_results1},
	{"a'abc' c 'cde' cefg", " ", " abcd", token_results1},
	{"'abc' abc 'cde'd 'efg'", " ", " abcd", token_results1},

	{"a, b, c", ",", " ", token_results2},
	{"a,b,c", ",", " ", token_results2},
	{" a 1:2 b;3  4c5.  ", ":;.,", " 12345", token_results2},
	{"a.b,c", ",.", "", token_results2},
	{"  a   b  c  ", " ", " ", token_results2},
};

START_TEST(test_token)
{
	enumerator_t *enumerator;
	const char **results;
	char *token;
	int tok = 0;

	enumerator = enumerator_create_token(token_tests[_i].string,
									token_tests[_i].sep, token_tests[_i].trim);
	results = token_tests[_i].results;
	while (enumerator->enumerate(enumerator, &token))
	{
		switch (tok)
		{
			case 0:
			case 1:
			case 2:
				ck_assert_str_eq(token, results[tok]);
				break;
			default:
				fail("unexpected token '%s'", token);
		}
		tok++;
	}
	fail_if(tok != 3, "not enough tokens (%d) extracted from '%s'",
			tok, token_tests[_i].string);
	enumerator->destroy(enumerator);
}
END_TEST

/*******************************************************************************
 * utility for filtered and nested tests
 */

static void destroy_data(void *data)
{
	fail_if(data != (void*)101, "data does not match '101' in destructor");
}

/*******************************************************************************
 * filtered test
 */

static bool filter(void *data, int *v, int *vo, int *w, int *wo,
				   int *x, int *xo, int *y, int *yo, int *z, int *zo)
{
	int val = *v;

	*vo = val++;
	*wo = val++;
	*xo = val++;
	*yo = val++;
	*zo = val++;
	fail_if(data != (void*)101, "data does not match '101' in filter function");
	return TRUE;
}

START_TEST(test_filtered)
{
	int round, v, w, x, y, z;
	linked_list_t *list;
	enumerator_t *enumerator;

	list = linked_list_create_with_items((void*)1, (void*)2, (void*)3, (void*)4,
										 (void*)5, NULL);

	round = 1;
	enumerator = enumerator_create_filter(list->create_enumerator(list),
									(void*)filter, (void*)101, destroy_data);
	while (enumerator->enumerate(enumerator, &v, &w, &x, &y, &z))
	{
		ck_assert_int_eq(v, round);
		ck_assert_int_eq(w, round + 1);
		ck_assert_int_eq(x, round + 2);
		ck_assert_int_eq(y, round + 3);
		ck_assert_int_eq(z, round + 4);
		round++;
	}
	enumerator->destroy(enumerator);

	list->destroy(list);
}
END_TEST

/*******************************************************************************
 * nested test
 */

static enumerator_t* create_inner(linked_list_t *outer, void *data)
{
	fail_if(data != (void*)101, "data does not match '101' in nested constr.");
	return outer->create_enumerator(outer);
}

START_TEST(test_nested)
{
	intptr_t x;
	int round;
	linked_list_t *list, *l1, *l2, *l3;
	enumerator_t *enumerator;

	l1 = linked_list_create_with_items((void*)1, (void*)2, NULL);
	l2 = linked_list_create();
	l3 = linked_list_create_with_items((void*)3, (void*)4, (void*)5, NULL);
	list = linked_list_create_with_items(l1, l2, l3, NULL);

	round = 1;
	enumerator = enumerator_create_nested(list->create_enumerator(list),
					(void*)create_inner, (void*)101, destroy_data);
	while (enumerator->enumerate(enumerator, &x))
	{
		ck_assert_int_eq(round, x);
		round++;
	}
	enumerator->destroy(enumerator);

	list->destroy(list);
	l1->destroy(l1);
	l2->destroy(l2);
	l3->destroy(l3);
}
END_TEST

Suite *enumerator_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("enumerator");

	tc = tcase_create("tokens");
	tcase_add_loop_test(tc, test_token, 0, countof(token_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("filtered");
	tcase_add_test(tc, test_filtered);
	suite_add_tcase(s, tc);

	tc = tcase_create("nested");
	tcase_add_test(tc, test_nested);
	suite_add_tcase(s, tc);

	return s;
}
