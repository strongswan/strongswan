/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
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

#include <utils/identification.h>

/*******************************************************************************
 * equals
 */

static bool id_equals(identification_t *a, char *b_str)
{
	identification_t *b;
	bool equals;

	b = identification_create_from_string(b_str);
	equals = a->equals(a, b);
	b->destroy(b);
	return equals;
}

START_TEST(test_equals)
{
	identification_t *a;
	chunk_t encoding, fuzzed;
	int i;

	a = identification_create_from_string(
							 "C=CH, E=martin@strongswan.org, CN=martin");

	ck_assert(id_equals(a, "C=CH, E=martin@strongswan.org, CN=martin"));
	ck_assert(id_equals(a, "C=ch, E=martin@STRONGSWAN.ORG, CN=Martin"));
	ck_assert(!id_equals(a, "C=CN, E=martin@strongswan.org, CN=martin"));
	ck_assert(!id_equals(a, "E=martin@strongswan.org, C=CH, CN=martin"));
	ck_assert(!id_equals(a, "E=martin@strongswan.org, C=CH, CN=martin"));

	encoding = chunk_clone(a->get_encoding(a));
	a->destroy(a);

	/* simple fuzzing, increment each byte of encoding */
	for (i = 0; i < encoding.len; i++)
	{
		if (i == 11 || i == 30 || i == 62)
		{	/* skip ASN.1 type fields, as equals() handles them graceful */
			continue;
		}
		fuzzed = chunk_clone(encoding);
		fuzzed.ptr[i]++;
		a = identification_create_from_encoding(ID_DER_ASN1_DN, fuzzed);
		ck_assert(!id_equals(a, "C=CH, E=martin@strongswan.org, CN=martin"));
		a->destroy(a);
		free(fuzzed.ptr);
	}

	/* and decrement each byte of encoding */
	for (i = 0; i < encoding.len; i++)
	{
		if (i == 11 || i == 30 || i == 62)
		{
			continue;
		}
		fuzzed = chunk_clone(encoding);
		fuzzed.ptr[i]--;
		a = identification_create_from_encoding(ID_DER_ASN1_DN, fuzzed);
		ck_assert(!id_equals(a, "C=CH, E=martin@strongswan.org, CN=martin"));
		a->destroy(a);
		free(fuzzed.ptr);
	}
	free(encoding.ptr);
}
END_TEST

/*******************************************************************************
 * matches
 */

static bool id_matches(identification_t *a, char *b_str, id_match_t expected)
{
	identification_t *b;
	id_match_t match;

	b = identification_create_from_string(b_str);
	match = a->matches(a, b);
	b->destroy(b);
	return match == expected;
}

START_TEST(test_matches)
{
	identification_t *a;

	a = identification_create_from_string("C=CH, E=martin@strongswan.org, CN=martin");

	ck_assert(id_matches(a, "C=CH, E=martin@strongswan.org, CN=martin", ID_MATCH_PERFECT));
	ck_assert(id_matches(a, "C=CH, E=*, CN=martin", ID_MATCH_ONE_WILDCARD));
	ck_assert(id_matches(a, "C=CH, E=*, CN=*", ID_MATCH_ONE_WILDCARD - 1));
	ck_assert(id_matches(a, "C=*, E=*, CN=*", ID_MATCH_ONE_WILDCARD - 2));
	ck_assert(id_matches(a, "C=*, E=*, CN=*, O=BADInc", ID_MATCH_NONE));
	ck_assert(id_matches(a, "C=*, E=*", ID_MATCH_NONE));
	ck_assert(id_matches(a, "C=*, E=a@b.c, CN=*", ID_MATCH_NONE));

	a->destroy(a);
}
END_TEST

/*******************************************************************************
 * identification part enumeration
 */

START_TEST(test_parts)
{
	identification_t *id;
	enumerator_t *enumerator;
	id_part_t part;
	chunk_t data;
	int i = 0;

	id = identification_create_from_string("C=CH, O=strongSwan, CN=tester");

	enumerator = id->create_part_enumerator(id);
	while (enumerator->enumerate(enumerator, &part, &data))
	{
		switch (i++)
		{
			case 0:
				ck_assert(part == ID_PART_RDN_C &&
						  chunk_equals(data, chunk_create("CH", 2)));
				break;
			case 1:
				ck_assert(part == ID_PART_RDN_O &&
						  chunk_equals(data, chunk_from_str("strongSwan")));
				break;
			case 2:
				ck_assert(part == ID_PART_RDN_CN &&
						  chunk_equals(data, chunk_from_str("tester")));
				break;
			default:
				fail("unexpected identification part %d", part);
		}
	}
	ck_assert_int_eq(i, 3);
	enumerator->destroy(enumerator);
	id->destroy(id);
}
END_TEST

/*******************************************************************************
 * wildcards
 */

static bool id_contains_wildcards(char *string)
{
	identification_t *id;
	bool contains;

	id = identification_create_from_string(string);
	contains = id->contains_wildcards(id);
	id->destroy(id);
	return contains;
}

START_TEST(test_contains_wildcards)
{
	ck_assert(id_contains_wildcards("%any"));
	ck_assert(id_contains_wildcards("C=*, O=strongSwan, CN=gw"));
	ck_assert(id_contains_wildcards("C=CH, O=strongSwan, CN=*"));
	ck_assert(id_contains_wildcards("*@strongswan.org"));
	ck_assert(id_contains_wildcards("*.strongswan.org"));
	ck_assert(!id_contains_wildcards("C=**, O=a*, CN=*a"));
}
END_TEST

Suite *identification_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("identification");

	tc = tcase_create("equals");
	tcase_add_test(tc, test_equals);
	suite_add_tcase(s, tc);

	tc = tcase_create("matches");
	tcase_add_test(tc, test_matches);
	suite_add_tcase(s, tc);

	tc = tcase_create("part enumeration");
	tcase_add_test(tc, test_parts);
	suite_add_tcase(s, tc);

	tc = tcase_create("wildcards");
	tcase_add_test(tc, test_contains_wildcards);
	suite_add_tcase(s, tc);

	return s;
}
