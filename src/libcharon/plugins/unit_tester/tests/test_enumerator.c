/*
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

#include <collections/linked_list.h>


/*******************************************************************************
 * linked list remove test
 ******************************************************************************/
bool test_list_remove()
{
	void *a = (void*)1, *b = (void*)2;
	linked_list_t *list;

	list = linked_list_create();
	list->insert_last(list, a);
	if (list->remove(list, a, NULL) != 1)
	{
		return FALSE;
	}
	list->insert_last(list, a);
	list->insert_first(list, a);
	list->insert_last(list, a);
	list->insert_last(list, b);
	if (list->remove(list, a, NULL) != 3)
	{
		return FALSE;
	}
	if (list->remove(list, a, NULL) != 0)
	{
		return FALSE;
	}
	if (list->get_count(list) != 1)
	{
		return FALSE;
	}
	if (list->remove(list, b, NULL) != 1)
	{
		return FALSE;
	}
	if (list->remove(list, b, NULL) != 0)
	{
		return FALSE;
	}
	list->destroy(list);
	return TRUE;
}

/*******************************************************************************
 * Simple insert first/last and enumerate test
 ******************************************************************************/
bool test_enumerate()
{
	int round, x;
	void *a = (void*)4, *b = (void*)3, *c = (void*)2, *d = (void*)5, *e = (void*)1;
	linked_list_t *list;
	enumerator_t *enumerator;

	list = linked_list_create();

	list->insert_last(list, a);
	list->insert_first(list, b);
	list->insert_first(list, c);
	list->insert_last(list, d);
	list->insert_first(list, e);

	round = 1;
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &x))
	{
		if (round != x)
		{
			return FALSE;
		}
		round++;
	}
	enumerator->destroy(enumerator);

	list->destroy(list);
	return TRUE;
}

/*******************************************************************************
 * nested enumerator test
 ******************************************************************************/

static bool bad_data;

static enumerator_t* create_inner(linked_list_t *outer, void *data)
{
	if (data != (void*)101)
	{
		bad_data = TRUE;
	}
	return outer->create_enumerator(outer);
}


static void destroy_data(void *data)
{
	if (data != (void*)101)
	{
		bad_data = TRUE;
	}
}

bool test_enumerate_nested()
{
	int round, x;
	void *a = (void*)1, *b = (void*)2, *c = (void*)3, *d = (void*)4, *e = (void*)5;
	linked_list_t *list, *l1, *l2, *l3;
	enumerator_t *enumerator;

	bad_data = FALSE;
	list = linked_list_create();
	l1 = linked_list_create();
	l2 = linked_list_create();
	l3 = linked_list_create();
	list->insert_last(list, l1);
	list->insert_last(list, l2);
	list->insert_last(list, l3);

	l1->insert_last(l1, a);
	l1->insert_last(l1, b);
	l3->insert_last(l3, c);
	l3->insert_last(l3, d);
	l3->insert_last(l3, e);

	round = 1;
	enumerator = enumerator_create_nested(list->create_enumerator(list),
					(void*)create_inner, (void*)101, destroy_data);
	while (enumerator->enumerate(enumerator, &x))
	{
		if (round != x)
		{
			return FALSE;
		}
		round++;
	}
	enumerator->destroy(enumerator);

	list->destroy(list);
	l1->destroy(l1);
	l2->destroy(l2);
	l3->destroy(l3);
	return !bad_data;
}


/*******************************************************************************
 * filtered enumerator test
 ******************************************************************************/
static bool filter(void *data, int *v, int *vo, int *w, int *wo,
				   int *x, int *xo, int *y, int *yo, int *z, int *zo)
{
	int val = *v;

	*vo = val++;
	*wo = val++;
	*xo = val++;
	*yo = val++;
	*zo = val++;
	if (data != (void*)101)
	{
		return FALSE;
	}
	return TRUE;
}

bool test_enumerate_filtered()
{
	int round, v, w, x, y, z;
	void *a = (void*)1, *b = (void*)2, *c = (void*)3, *d = (void*)4, *e = (void*)5;
	linked_list_t *list;
	enumerator_t *enumerator;

	bad_data = FALSE;
	list = linked_list_create();

	list->insert_last(list, a);
	list->insert_last(list, b);
	list->insert_last(list, c);
	list->insert_last(list, d);
	list->insert_last(list, e);

	round = 1;
	enumerator = enumerator_create_filter(list->create_enumerator(list),
									(void*)filter, (void*)101, destroy_data);
	while (enumerator->enumerate(enumerator, &v, &w, &x, &y, &z))
	{
		if (v != round || w != round + 1 || x != round + 2 ||
			y != round + 3 || z != round + 4)
		{
			return FALSE;
		}
		round++;
	}
	enumerator->destroy(enumerator);

	list->destroy(list);
	return !bad_data;
}

/*******************************************************************************
 * token parser test
 ******************************************************************************/

bool test_enumerate_token()
{
	enumerator_t *enumerator;
	char *token;
	int i, num;
	struct {
		char *string;
		char *sep;
		char *trim;
	} tests1[] = {
		{"abc, cde, efg", ",", " "},
		{" abc 1:2 cde;3  4efg5.  ", ":;.,", " 12345"},
		{"abc.cde,efg", ",.", ""},
		{"  abc   cde  efg  ", " ", " "},
		{"a'abc' c 'cde' cefg", " ", " abcd"},
		{"'abc' abc 'cde'd 'efg'", " ", " abcd"},
	}, tests2[] = {
		{"a, b, c", ",", " "},
		{"a,b,c", ",", " "},
		{" a 1:2 b;3  4c5.  ", ":;.,", " 12345"},
		{"a.b,c", ",.", ""},
		{"  a   b  c  ", " ", " "},
	};

	for (num = 0; num < countof(tests1); num++)
	{
		i = 0;
		enumerator = enumerator_create_token(tests1[num].string,
											 tests1[num].sep, tests1[num].trim);
		while (enumerator->enumerate(enumerator, &token))
		{
			switch (i)
			{
				case 0:
					if (!streq(token, "abc")) return FALSE;
					break;
				case 1:
					if (!streq(token, "cde")) return FALSE;
					break;
				case 2:
					if (!streq(token, "efg")) return FALSE;
					break;
				default:
					return FALSE;
			}
			i++;
		}
		if (i != 3)
		{
			return FALSE;
		}
		enumerator->destroy(enumerator);
	}

	for (num = 0; num < countof(tests2); num++)
	{
		i = 0;
		enumerator = enumerator_create_token(tests2[num].string,
											 tests2[num].sep, tests2[num].trim);
		while (enumerator->enumerate(enumerator, &token))
		{
			switch (i)
			{
				case 0:
					if (!streq(token, "a")) return FALSE;
					break;
				case 1:
					if (!streq(token, "b")) return FALSE;
					break;
				case 2:
					if (!streq(token, "c")) return FALSE;
					break;
				default:
					return FALSE;
			}
			i++;
		}
		if (i != 3)
		{
			return FALSE;
		}
		enumerator->destroy(enumerator);
	}

	return TRUE;
}

