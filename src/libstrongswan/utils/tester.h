/**
 * @file tester.h
 *
 * @brief Interface of tester_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef TESTER_H_
#define TESTER_H_

#include <stdio.h>

#include <types.h>


/* must be defined here cause it is used in test_t */
typedef struct protected_tester_t protected_tester_t;

typedef struct test_t test_t;

/**
 * @brief Representing a specified test.
 * 
 * @ingroup utils
 */
struct test_t {
	/**
	 * Testfunction called for this test.
	 * 
	 * @param tester		associated tester_t object
	 */
	void (*test_function) (protected_tester_t * tester);
	
	/**
	 * Name of the test.
	 */
	char * test_name;
};


typedef struct tester_t tester_t;

/**
 * @brief A class to perform tests.
 * 
 * @b Constructors:
 *  - tester_create()
 * 
 * @ingroup utils
 */
struct tester_t {
	/**
	 * @brief Test all testcases in array tests with specific tester_t object.
	 *
	 * @param tester 	tester_t object
 	 * @param tests		pointer	to an array of test_t-pointers.
 	 * 			      	The last item has to be NULL to mark end of array.
	 */
	void (*perform_tests) (tester_t *tester,test_t **tests);

	/**
	 * @brief Run a specific test case.
	 *
	 * @param this 		tester_t object
	 * @param test 		pointer to a test_t object which will be performed
	 */
 	void (*perform_test) (tester_t *tester, test_t *test);

	/**
	 * @brief Destroys a tester_t object.
	 *
	 * @param tester 	tester_t object
	 */
	void (*destroy) (tester_t *tester);
};


/**
 * @brief A class used in a specific testcase.
 * 
 * For each testcase an object of this type is passed to the testfunction. The testfunction uses this 
 * object to check specific asserts with protected_tester_t.assert_true and protected_tester_t.assert_false.
 * 
 * @b Constructors:
 *  - tester_create()
 * 
 * @ingroup utils
 */
struct protected_tester_t {
	
	/**
	 * Public functions of a tester_t object
	 */
	tester_t public;
	
	/**
	 * @brief Is called in a testcase to check a specific situation for TRUE.
	 *
	 * Log-Values to the tester output are protected from multiple access.
	 *
	 * @param this 			tester_t object
	 * @param to_be_true 	assert which has to be TRUE
	 * @param assert_name	name of the assertion
	 */
	void (*assert_true) (protected_tester_t *tester, bool to_be_true, char *assert_name);

	/**
	 * @brief Is called in a testcase to check a specific situation for FALSE.
	 *
	 * Log-Values to the tester output are protected from multiple access.
	 *
	 * @param this 			tester_t object
	 * @param to_be_false 	assert which has to be FALSE
	 * @param assert_name	name of the assertion
	 */
	void (*assert_false) (protected_tester_t *tester, bool to_be_false, char *assert_name);
};


/**
 * @brief Creates a tester_t object used to perform tests with.
 *
 * @param output 					test output is written to this output.
 * @param display_succeeded_asserts has to be TRUE, if all asserts should be displayed,
 * 									FALSE otherwise
 *
 * @return							tester_t object
 * 
 * @ingroup utils
 */
tester_t *tester_create(FILE *output, bool display_succeeded_asserts);

#endif /*TESTER_H_*/
