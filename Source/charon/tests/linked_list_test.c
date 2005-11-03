/**
 * @file linked_list_test.c
 * 
 * @brief Tests to test the Linked List type linked_list_t
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <string.h>
 
#include "../tester.h"
#include "../linked_list.h"
 
 /*
 * Description in header-file
 */
void test_linked_list(tester_t *tester)
{
	void *test_value = NULL;

	linked_list_t *linked_list = linked_list_create();
	tester->assert_true(tester,(linked_list->count == 0), "count check");
	
	linked_list->insert_first(linked_list,"one");
	tester->assert_true(tester,(linked_list->count == 1), "count check");

	linked_list->insert_first(linked_list,"two");
	tester->assert_true(tester,(linked_list->count == 2), "count check");
		
	linked_list->insert_first(linked_list,"three");
	tester->assert_true(tester,(linked_list->count == 3), "count check");

	linked_list->insert_first(linked_list,"four");
	tester->assert_true(tester,(linked_list->count == 4), "count check");

	linked_list->insert_first(linked_list,"five");
	tester->assert_true(tester,(linked_list->count == 5), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->count == 5), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");
	tester->assert_true(tester,(linked_list->count == 5), "count check");
	tester->assert_true(tester,(linked_list->remove_first(linked_list,&test_value) == SUCCESS), "remove_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "remove_first value check");	
	tester->assert_true(tester,(linked_list->count == 4), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->count == 4), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");	
	tester->assert_true(tester,(linked_list->count == 4), "count check");

	tester->assert_true(tester,(linked_list->remove_last(linked_list,&test_value) == SUCCESS), "remove_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "remove_last value check");	
	tester->assert_true(tester,(linked_list->count == 3), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"two") == 0), "get_last value check");		
	tester->assert_true(tester,(linked_list->count == 3), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->count == 3), "count check");
	
	tester->assert_true(tester,(linked_list->destroy(linked_list) == SUCCESS), "destroy call check");
}
