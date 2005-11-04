/**
 * @file linked_list_test.h
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

#ifndef LINKED_LIST_TEST_H_
#define LINKED_LIST_TEST_H_

#include "../tester.h"

/**
 * @brief Test function for the type linked_list_t
 *
 * Performs different kinds of assertions to check the functionality
 * of the linked_list_t in a Single-Threaded environment. 
 * 
 * @warning To be usable in multi-threaded software 
 * this list has to get protected with locks.
 *  
 * @param tester tester object
 */
void test_linked_list(tester_t *tester);

/**
 * @brief Test function for the type linked_list_t and its iterator
 *
 * Performs different kinds of assertions to check the functionality
 * of the linked_list_t and its iterator in a Single-Threaded environment. 
 * 
 * @warning To be usable in multi-threaded software 
 * this list has to get protected with locks.
 *  
 * @param tester tester object
 */
void test_linked_list_iterator(tester_t *tester);

/**
 * @brief Test function for the type linked_list_t and its insert and remove
 * 		  functions
 *
 * Performs different kinds of assertions to check the functionality
 * of the linked_list_t and its insert and remove functions
 * 
 * @warning To be usable in multi-threaded software 
 * this list has to get protected with locks.
 *  
 * @param tester tester object
 */
void test_linked_list_insert_and_remove(tester_t *tester);

/**
 * Test for linked_list_t
 */
test_t linked_list_test = {test_linked_list,"Linked List"};

/**
 * Test for linked_list_t with iterator
 */
test_t linked_list_iterator_test = {test_linked_list_iterator,"Linked List Iterator"};

/**
 * Test for linked_list_t insert and remove
 */
test_t linked_list_insert_and_remove_test = {test_linked_list_insert_and_remove,"Linked List Insert and remove"};


#endif /*LINKED_LIST_TEST_H_*/
