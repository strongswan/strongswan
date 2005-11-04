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
	int count;

	linked_list_t *linked_list = linked_list_create();
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 0), "count check");
	
	linked_list->insert_first(linked_list,"one");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 1), "count check");

	linked_list->insert_first(linked_list,"two");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 2), "count check");
		
	linked_list->insert_first(linked_list,"three");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 3), "count check");

	linked_list->insert_first(linked_list,"four");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 4), "count check");

	linked_list->insert_first(linked_list,"five");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 5), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "get_first value check");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 5), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 5), "count check");
	
	tester->assert_true(tester,(linked_list->remove_first(linked_list,&test_value) == SUCCESS), "remove_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "remove_first value check");	
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 4), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 4), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");	
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 4), "count check");

	tester->assert_true(tester,(linked_list->remove_last(linked_list,&test_value) == SUCCESS), "remove_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "remove_last value check");	
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 3), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"two") == 0), "get_last value check");		
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 3), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	linked_list->get_count(linked_list,&count);
	tester->assert_true(tester,(count == 3), "count check");
	
	tester->assert_true(tester,(linked_list->destroy(linked_list) == SUCCESS), "destroy call check");
}

 /*
 * Description in header-file
 */
void test_linked_list_iterator(tester_t *tester)
{
	bool has_next;
	linked_list_element_t * element;
	
	linked_list_t *linked_list = linked_list_create();
	linked_list->insert_first(linked_list,"one");
	linked_list->insert_first(linked_list,"two");	
	linked_list->insert_first(linked_list,"three");
	linked_list->insert_first(linked_list,"four");
	linked_list->insert_first(linked_list,"five");

	linked_list_iterator_t * iterator;
	linked_list_iterator_t * iterator2;
	
	
	tester->assert_true(tester,(linked_list->create_iterator(linked_list,&iterator,TRUE) == SUCCESS), "create_iterator for it 1 call check");
	
	iterator->has_next(iterator,&has_next);
	tester->assert_true(tester,has_next, "it 1 has_next value check");	
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"five") == 0), "it 1 current value check");
	
	iterator->has_next(iterator,&has_next);
	tester->assert_true(tester,has_next, "it 1 has_next value check");	
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"four") == 0), "it 1 current value check");

	tester->assert_true(tester,(linked_list->create_iterator(linked_list,&iterator2,FALSE) == SUCCESS), "create_iterator for it 2 call check");

	iterator2->has_next(iterator2,&has_next);
	tester->assert_true(tester,has_next, "it 2 has_next value check");	
	iterator2->current(iterator2,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"one") == 0), "it 2 current value check");

	iterator->has_next(iterator,&has_next);
	tester->assert_true(tester,has_next, "it 1 has_next value check");	
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"three") == 0), "it 1 current value check");

	iterator2->has_next(iterator2,&has_next);
	tester->assert_true(tester,has_next, "it 2 has_next value check");	
	iterator2->current(iterator2,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"two") == 0), "it 2 current value check");

	iterator->has_next(iterator,&has_next);
	tester->assert_true(tester,has_next, "it 1 has_next value check");	
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"two") == 0), "it 1 current value check");

	iterator2->has_next(iterator2,&has_next);
	tester->assert_true(tester,has_next, "it 2 has_next value check");	
	iterator2->current(iterator2,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"three") == 0), "it 2 current value check");

	iterator->has_next(iterator,&has_next);
	tester->assert_true(tester,has_next, "it 1 has_next value check");	
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"one") == 0), "it 1 current value check");

	iterator->has_next(iterator,&has_next);
	tester->assert_false(tester,has_next, "it 1 has_next value check");

	iterator2->has_next(iterator2,&has_next);
	tester->assert_true(tester,has_next, "it 2 has_next value check");	
	iterator2->has_next(iterator2,&has_next);
	tester->assert_true(tester,has_next, "it 2 has_next value check");	
	iterator2->has_next(iterator2,&has_next);
	tester->assert_false(tester,has_next, "it 2 has_next value check");	

	tester->assert_true(tester,(iterator->destroy(iterator) == SUCCESS), "it 1 destroy call check");
	
	tester->assert_true(tester,(iterator2->destroy(iterator2) == SUCCESS), "it 2 destroy call check");
	
	linked_list->destroy(linked_list);
}

 /*
 * Description in header-file
 */
void test_linked_list_insert_and_remove(tester_t *tester)
{
	bool has_next;
	linked_list_element_t * element;
	linked_list_iterator_t * iterator;
	
	linked_list_t *linked_list = linked_list_create();
	linked_list->insert_first(linked_list,"one");
	linked_list->insert_first(linked_list,"two");
	
	linked_list->insert_first(linked_list,"three");
	linked_list->insert_first(linked_list,"four");
	linked_list->insert_first(linked_list,"five");
	

	
	linked_list->create_iterator(linked_list,&iterator,TRUE);
	
	iterator->has_next(iterator,&has_next);
	iterator->has_next(iterator,&has_next);
	iterator->has_next(iterator,&has_next);
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"three") == 0), "current value check");

	tester->assert_true(tester,(linked_list->insert_before(linked_list,element,"before_three") == SUCCESS), "insert_before call check");

	tester->assert_true(tester,(linked_list->insert_after(linked_list,element,"after_three") == SUCCESS), "insert_after call check");
	
	tester->assert_true(tester,(linked_list->remove(linked_list,element) == SUCCESS), "remove call check");
	
	iterator->reset(iterator);
	
	iterator->has_next(iterator,&has_next);
	iterator->has_next(iterator,&has_next);
	iterator->has_next(iterator,&has_next);
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"before_three") == 0), "current value check");
	iterator->has_next(iterator,&has_next);
	iterator->current(iterator,&element);
	tester->assert_true(tester,(strcmp((char *) element->value,"after_three") == 0), "current value check");
	
	iterator->destroy(iterator);
	
	linked_list->destroy(linked_list);
}
