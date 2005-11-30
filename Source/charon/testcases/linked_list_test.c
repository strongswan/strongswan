/**
 * @file linked_list_test.c
 * 
 * @brief Tests for the linked_list_t class.
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

#include "linked_list_test.h"
 
#include <utils/linked_list.h>
 
 /*
 * Description in header-file
 */
void test_linked_list(tester_t *tester)
{
	void *test_value = NULL;

	linked_list_t *linked_list = linked_list_create();
	
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 0), "count check");
	
	linked_list->insert_first(linked_list,"one");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 1), "count check");

	linked_list->insert_first(linked_list,"two");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 2), "count check");
		
	linked_list->insert_first(linked_list,"three");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 3), "count check");

	linked_list->insert_first(linked_list,"four");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 4), "count check");

	linked_list->insert_first(linked_list,"five");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 5), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 5), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");
	tester->assert_true(tester,(	linked_list->get_count(linked_list) == 5), "count check");
	
	tester->assert_true(tester,(linked_list->remove_first(linked_list,&test_value) == SUCCESS), "remove_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"five") == 0), "remove_first value check");	
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 4), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 4), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_last value check");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 4), "count check");

	tester->assert_true(tester,(linked_list->get_at_position(linked_list,0,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_at_position value check");

	tester->assert_true(tester,(linked_list->get_at_position(linked_list,1,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"three") == 0), "get_at_position value check");
	
	tester->assert_true(tester,(linked_list->get_at_position(linked_list,2,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"two") == 0), "get_at_position value check");
	
	tester->assert_true(tester,(linked_list->get_at_position(linked_list,3,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_at_position value check");

	tester->assert_false(tester,(linked_list->get_at_position(linked_list,4,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_false(tester,(linked_list->remove_at_position(linked_list,4,&test_value) == SUCCESS), "remove_at_position call check");
	tester->assert_false(tester,(linked_list->insert_at_position(linked_list,5,test_value) == SUCCESS), "insert_at_position call 1 check");

	tester->assert_true(tester,(linked_list->insert_at_position(linked_list,3,"six") == SUCCESS), "insert_at_position call 2 check");
	tester->assert_true(tester,(linked_list->insert_at_position(linked_list,3,"seven") == SUCCESS), "insert_at_position call 3 check");

	tester->assert_true(tester,(linked_list->get_at_position(linked_list,3,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"seven") == 0), "get_at_position value 1 check");	

	tester->assert_true(tester,(linked_list->get_at_position(linked_list,4,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"six") == 0), "get_at_position value 2 check");	

	tester->assert_true(tester,(linked_list->get_at_position(linked_list,5,&test_value) == SUCCESS), "get_at_position call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "get_at_position value 3 check");	
	
	tester->assert_true(tester,(linked_list->remove_at_position(linked_list,3,&test_value) == SUCCESS), "remove_at_position call check");	
	tester->assert_true(tester,(linked_list->remove_at_position(linked_list,3,&test_value) == SUCCESS), "remove_at_position call check");	


	tester->assert_true(tester,(linked_list->remove_last(linked_list,&test_value) == SUCCESS), "remove_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"one") == 0), "remove_last value check");	
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 3), "count check");

	tester->assert_true(tester,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"two") == 0), "get_last value check");		
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 3), "count check");

	tester->assert_true(tester,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	tester->assert_true(tester,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	tester->assert_true(tester,(linked_list->get_count(linked_list) == 3), "count check");
	
	linked_list->destroy(linked_list);
}

 /*
 * Description in header-file
 */
void test_linked_list_iterator(tester_t *tester)
{
	void * value;

	linked_list_t *linked_list = linked_list_create();
	linked_list->insert_first(linked_list,"one");
	linked_list->insert_first(linked_list,"two");	
	linked_list->insert_first(linked_list,"three");
	linked_list->insert_first(linked_list,"four");
	linked_list->insert_first(linked_list,"five");

	iterator_t * iterator;
	iterator_t * iterator2;
	
	
	iterator = linked_list->create_iterator(linked_list,TRUE);
	
	tester->assert_true(tester,iterator->has_next(iterator), "it 1 has_next value check");	
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"five") == 0), "it 1 current value check");
	
	tester->assert_true(tester,iterator->has_next(iterator), "it 1 has_next value check");	
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"four") == 0), "it 1 current value check");

	iterator2 = linked_list->create_iterator(linked_list,FALSE);

	tester->assert_true(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	
	iterator2->current(iterator2,&value);
	tester->assert_true(tester,(strcmp((char *) value,"one") == 0), "it 2 current value check");

	tester->assert_true(tester,iterator->has_next(iterator), "it 1 has_next value check");	
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"three") == 0), "it 1 current value check");

	tester->assert_true(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	
	iterator2->current(iterator2,&value);
	tester->assert_true(tester,(strcmp((char *) value,"two") == 0), "it 2 current value check");

	tester->assert_true(tester,iterator->has_next(iterator), "it 1 has_next value check");	
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"two") == 0), "it 1 current value check");

	tester->assert_true(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	
	iterator2->current(iterator2,&value);
	tester->assert_true(tester,(strcmp((char *) value,"three") == 0), "it 2 current value check");

	tester->assert_true(tester,iterator->has_next(iterator), "it 1 has_next value check");	
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"one") == 0), "it 1 current value check");

	tester->assert_false(tester,iterator->has_next(iterator), "it 1 has_next value check");

	tester->assert_true(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	
	tester->assert_true(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	
	tester->assert_false(tester,iterator2->has_next(iterator2), "it 2 has_next value check");	

	iterator->destroy(iterator);
	iterator2->destroy(iterator2);
	linked_list->destroy(linked_list);
}

 /*
 * Description in header-file
 */
void test_linked_list_insert_and_remove(tester_t *tester)
{
	void *value;
	iterator_t * iterator;
	
	linked_list_t *linked_list = linked_list_create();
	linked_list->insert_first(linked_list,"one");
	linked_list->insert_first(linked_list,"two");
	
	linked_list->insert_first(linked_list,"three");
	linked_list->insert_first(linked_list,"four");
	linked_list->insert_first(linked_list,"five");
	

	
	iterator = linked_list->create_iterator(linked_list,TRUE);
	
	iterator->has_next(iterator);
	iterator->has_next(iterator);
	iterator->has_next(iterator);
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"three") == 0), "current value check");

	iterator->insert_before(iterator,"before_three");
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"three") == 0), "current value check");


	iterator->insert_after(iterator,"after_three");
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"three") == 0), "current value check");
	
	
	tester->assert_true(tester,(iterator->remove(iterator) == SUCCESS), "remove call check");
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"before_three") == 0), "current value check");	
	
	iterator->reset(iterator);
	
	iterator->has_next(iterator);
	iterator->has_next(iterator);
	iterator->has_next(iterator);
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"before_three") == 0), "current value check");
	iterator->has_next(iterator);
	iterator->current(iterator,&value);
	tester->assert_true(tester,(strcmp((char *) value,"after_three") == 0), "current value check");
	
	iterator->destroy(iterator);
	
	linked_list->destroy(linked_list);
}
