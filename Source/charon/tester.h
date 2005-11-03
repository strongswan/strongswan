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
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "types.h"

/**
 * @brief Specifies a test
 */
typedef struct test_s test_t;

/**
 * @brief A tester object to perform tests
 */
typedef struct tester_s tester_t;

struct test_s{
	void (*test_function) (tester_t * tester);
	char * test_name;
};

struct tester_s {
	
	/**
	 * @brief Tests all testcases of specific tester object
	 * 
	 * @param tester tester object
 	 * @param pointer to a list of tests to perform.
 	 * 			      the last list item has to be NULL.
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*test_all) (tester_t *tester,test_t **tests);
	
	/**
	 * @brief is called in a testcase to check a specific situation
	 * 
	 * Log-Values to the tester output are protected from multiple access
	 * 
	 * @param this tester object
	 * @param to_be_true assert which has to be true
	 * @param Name of the assertion
	 */
	void (*assert_true) (tester_t *tester, bool to_be_true, char *assert_name); 	

	/**
	 * @brief run a specific test case
	 * 
	 * @param this tester object
	 * @param test_function implements the test case
	 * @param Name of the Test
	 */
 	void (*run_test) (tester_t *this, void (*test_function) (tester_t * tester), char * test_name);

	/**
	 * @brief Destroys a tester object
	 * 
	 * @param tester tester object
	 * @param Name of the Test
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (tester_t *tester);
};

tester_t *tester_create(FILE *output);

#endif /*TESTER_H_*/
