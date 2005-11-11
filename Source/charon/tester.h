/**
 * @file tester.h
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

#ifndef TESTER_H_
#define TESTER_H_

#include <stdio.h>

#include "types.h"



/**
 * @brief Specifies a test
 */
typedef struct test_s test_t;

/**
 * @brief A tester object to perform tests with
 */
typedef struct tester_s tester_t;

struct test_s{
	void (*test_function) (tester_t * tester);
	char * test_name;
};

struct tester_s {

	/**
	 * @brief Tests all testcases in array tests with specific tester object
	 *
	 * @param tester tester object
 	 * @param pointer to a array of test_t-pointers.
 	 * 			      the last item has to be NULL.
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*perform_tests) (tester_t *tester,test_t **tests);

	/**
	 * @brief run a specific test case
	 *
	 * @param this tester object
	 * @param test pointer to a test_t object which will be performed
	 * @param Name of the Test
	 */
 	status_t (*perform_test) (tester_t *tester, test_t *test);

	/**
	 * @brief is called in a testcase to check a specific situation for TRUE
	 *
	 * Log-Values to the tester output are protected from multiple access
	 *
	 * @warning this function should only be called in a test_function
	 *
	 * @param this tester object
	 * @param to_be_true assert which has to be TRUE
	 * @param Name of the assertion
	 */
	void (*assert_true) (tester_t *tester, bool to_be_true, char *assert_name);

	/**
	 * @brief is called in a testcase to check a specific situation for FALSE
	 *
	 * Log-Values to the tester output are protected from multiple access
	 *
	 * @warning this function should only be called in a test_function
	 *
	 * @param this tester object
	 * @param to_be_false assert which has to be FALSE
	 * @param Name of the assertion
	 */
	void (*assert_false) (tester_t *tester, bool to_be_false, char *assert_name);

	/**
	 * @brief Destroys a tester object
	 *
	 * @param tester tester object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (tester_t *tester);
};

/**
 * @brief creates a tester object needed to perform tests
 *
 * @param output test output is written to this output
 * @param display_succeeded_asserts has to be TRUE, if all asserts should be displayed,
 * 									else otherwise
 *
 * @return tester object
 */
tester_t *tester_create(FILE *output, bool display_succeeded_asserts);

#endif /*TESTER_H_*/
