/*
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

#include <daemon.h>

/*******************************************************************************
 * identification part enumeration test
 ******************************************************************************/
bool test_id_parts()
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
				if (part != ID_PART_RDN_C ||
					!chunk_equals(data, chunk_create("CH", 2)))
				{
					return FALSE;
				}
				break;
			case 1:
				if (part != ID_PART_RDN_O ||
					!chunk_equals(data, chunk_create("strongSwan", 10)))
				{
					return FALSE;
				}
				break;
			case 2:
				if (part != ID_PART_RDN_CN ||
					!chunk_equals(data, chunk_create("tester", 6)))
				{
					return FALSE;
				}
				break;
			default:
				return FALSE;
		}
	}
	if (i < 3)
	{
		return FALSE;
	}
	enumerator->destroy(enumerator);
	id->destroy(id);
	return TRUE;
}

/*******************************************************************************
 * identification contains_wildcards() test
 ******************************************************************************/

static bool test_id_wildcards_has(char *string)
{
	identification_t *id;
	bool contains;

	id = identification_create_from_string(string);
	contains = id->contains_wildcards(id);
	id->destroy(id);
	return contains;
}

bool test_id_wildcards()
{
	if (!test_id_wildcards_has("C=*, O=strongSwan, CN=gw"))
	{
		return FALSE;
	}
	if (!test_id_wildcards_has("C=CH, O=strongSwan, CN=*"))
	{
		return FALSE;
	}
	if (test_id_wildcards_has("C=**, O=a*, CN=*a"))
	{
		return FALSE;
	}
	if (!test_id_wildcards_has("*@strongswan.org"))
	{
		return FALSE;
	}
	if (!test_id_wildcards_has("*.strongswan.org"))
	{
		return FALSE;
	}
	return TRUE;
}

/*******************************************************************************
 * identification equals test
 ******************************************************************************/

static bool test_id_equals_one(identification_t *a, char *b_str)
{
	identification_t *b;
	bool equals;

	b = identification_create_from_string(b_str);
	equals = a->equals(a, b);
	b->destroy(b);
	return equals;
}

bool test_id_equals()
{
	identification_t *a;
	chunk_t encoding, fuzzed;
	int i;

	a = identification_create_from_string(
							   "C=CH, E=martin@strongswan.org, CN=martin");

	if (!test_id_equals_one(a, "C=CH, E=martin@strongswan.org, CN=martin"))
	{
		return FALSE;
	}
	if (!test_id_equals_one(a, "C=ch, E=martin@STRONGSWAN.ORG, CN=Martin"))
	{
		return FALSE;
	}
	if (test_id_equals_one(a, "C=CN, E=martin@strongswan.org, CN=martin"))
	{
		return FALSE;
	}
	if (test_id_equals_one(a, "E=martin@strongswan.org, C=CH, CN=martin"))
	{
		return FALSE;
	}
	if (test_id_equals_one(a, "E=martin@strongswan.org, C=CH, CN=martin"))
	{
		return FALSE;
	}
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
		if (test_id_equals_one(a, "C=CH, E=martin@strongswan.org, CN=martin"))
		{
			return FALSE;
		}
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
		if (test_id_equals_one(a, "C=CH, E=martin@strongswan.org, CN=martin"))
		{
			return FALSE;
		}
		a->destroy(a);
		free(fuzzed.ptr);
	}
	free(encoding.ptr);
	return TRUE;
}

/*******************************************************************************
 * identification matches test
 ******************************************************************************/

static id_match_t test_id_matches_one(identification_t *a, char *b_str)
{
	identification_t *b;
	id_match_t match;

	b = identification_create_from_string(b_str);
	match = a->matches(a, b);
	b->destroy(b);
	return match;
}

bool test_id_matches()
{
	identification_t *a;

	a = identification_create_from_string(
							   "C=CH, E=martin@strongswan.org, CN=martin");

	if (test_id_matches_one(a, "C=CH, E=martin@strongswan.org, CN=martin")
															!= ID_MATCH_PERFECT)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=CH, E=*, CN=martin") != ID_MATCH_ONE_WILDCARD)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=CH, E=*, CN=*") != ID_MATCH_ONE_WILDCARD - 1)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=*, E=*, CN=*") != ID_MATCH_ONE_WILDCARD - 2)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=*, E=*, CN=*, O=BADInc") != ID_MATCH_NONE)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=*, E=*") != ID_MATCH_NONE)
	{
		return FALSE;
	}
	if (test_id_matches_one(a, "C=*, E=a@b.c, CN=*") != ID_MATCH_NONE)
	{
		return FALSE;
	}
	a->destroy(a);
	return TRUE;
}
