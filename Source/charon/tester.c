/**
 * @file tester.c
 * 
 * @brief Test module for automatic testing
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


#include <stdlib.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
 
#include "tester.h"
#include "linked_list.h"

/**
 * @brief Private Variables and Functions of tester class
 * 
 */
typedef struct private_tester_s private_tester_t;
 
struct private_tester_s {
 	tester_t tester;
 	
	/* Private values */
 	FILE* output;
 	int tests_count;
 	int failed_tests_count;
 	int failed_asserts_count;

	/* Private functions */
	/**
	 * @brief is called in a testcase to check a specific situation
	 * 
	 * @param this tester object
	 * @param to_be_true assert which has to be true
	 * @param Name of the assertion
	 */
	void (*assert_true) (private_tester_t *this, bool to_be_true, char *assert_name); 	

	/**
	 * @brief run a specific test case
	 * 
	 * @param this tester object
	 * @param test_function implements the test case
	 * @param Name of the Test
	 */
 	void (*run_test) (private_tester_t *this, void (*test_function) (private_tester_t * tester), char * test_name);
};
 
/**
 * @brief Test function to test the linked list class
 */
static void	test_linked_list(private_tester_t * this){
	linked_list_t *linked_list = linked_list_create();
	linked_list->insert_first(linked_list,"aha");
	void *value;
	linked_list->get_first(linked_list,&value);
	this->assert_true(this,(2 == 3), "zwei ist drei");
	this->assert_true(this,(2 == 2), "zwei ist zwei");
	
}

/**
 * @brief Testing of all registered tests
 * 
 * New tests have to be added in this function
 */
static status_t test_all(tester_t *tester) 
{
	private_tester_t *this =(private_tester_t*) tester;
	fprintf(this->output,"Start testing\n");

	/* Add new Tests here! */
	this->run_test(this,test_linked_list,"Linked List");
	
	fprintf(this->output,"End testing. %d tests failed of %d tests\n",this->failed_tests_count,this->tests_count);

#ifdef LEAK_DETECTIVE
	/* Leaks are reported in log file */
	report_leaks();
#endif
	return SUCCESS;
}


/**
 * @brief implements the private run_test-Function
 * 
 */
static void run_test(private_tester_t *tester, void (*test_function) (private_tester_t * tester), char * test_name)
{
	private_tester_t *this = tester;
	this->tests_count++;
	this->failed_asserts_count = 0;
	fprintf(this->output,"Start Test '%s'\n", test_name);
	test_function(this);
	fprintf(this->output,"End Test '%s'\n", test_name);
	if (this->failed_asserts_count > 0)
	{
		this->failed_tests_count++;
	}
}

/**
 * @brief implements the private assert_true-Function
 * 
 */
static void assert_true(private_tester_t *tester, bool to_be_true,char * assert_name)
{
	private_tester_t *this = tester;
	
	if (assert_name == NULL)
	{
		assert_name = "unknown";
	}
	
	if (!to_be_true)
	{
		this->failed_asserts_count++;
		fprintf(this->output,"  Assert '%s' failed!\n", assert_name);		
	}else
	{
		fprintf(this->output,"  Assert '%s' succeeded\n", assert_name);		
	}
}

/**
 * Implements the destroy function
 * 
 */
static status_t destroy(tester_t *this) 
{
	pfree(this);
	return SUCCESS;
}

tester_t *tester_create(FILE *output) 
{
	private_tester_t *this = alloc_thing(private_tester_t, "private_tester_t");
	
	this->tester.destroy = destroy;
	this->tester.test_all = test_all;
	this->run_test = run_test;
	this->assert_true = assert_true;
	
	this->failed_tests_count = 0;
	this->tests_count = 0;
	this->output = output;
	
	return &(this->tester);
}
