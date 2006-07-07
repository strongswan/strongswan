/**
 * @file tester.c
 *
 * @brief Implementation of tester_t.
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


#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include "tester.h"



typedef struct private_tester_t private_tester_t;

/**
 * @brief Private Data of tester_t class.
 *
 */
struct private_tester_t {
 	
 	/**
 	 * Protected interface of tester_t.
 	 */
 	protected_tester_t protected;

	/**
	 * Runs a specific test.
	 * 
	 * @param tester 			associated tester object
	 * @param test_function		test function to perform
	 * @param test_name			name for the given test
	 */
	void (*run_test) (private_tester_t *tester, void (*test_function) (protected_tester_t * tester), char * test_name);
	
	/**
	 * Returns the difference of to timeval structs in microseconds.
	 *
	 * @warning this function is also defined in the event queue
	 * 			in later improvements, this function can be added to a general
	 *          class type!
	 *
	 * @param end_time 		end time
	 * @param start_time 	start time
	 * 
	 * @TODO make object function or move to utils!
	 *
	 * @return difference in microseconds
	 */
	long (*time_difference) (private_tester_t *tester,struct timeval *end_time, struct timeval *start_time);

	/**
	 * Output is written into this file.
	 */
 	FILE* output;
 	
 	/**
 	 * Number of already performed tests.
 	 */
 	int tests_count;
 	
 	/**
 	 * Number of failed tests.
 	 */
 	int failed_tests_count;
 	
 	/**
 	 * Number of failed asserts in current test.
 	 */ 
 	int failed_asserts_count;
 	
 	/**
 	 * TRUE if also succeeded asserts should be written to output.
 	 */
 	bool display_succeeded_asserts;
 	
 	/**
 	 * Mutex to make this class thread-save.
 	 */
 	pthread_mutex_t mutex;
};

/**
 * Implementation of tester_t.perform_tests.
 */
static void perform_tests(private_tester_t *this,test_t **tests)
{
	int current_test = 0;
	fprintf(this->output,"\nStart testing...\n\n");
	fprintf(this->output,"_____________________________________________________________________\n");
	fprintf(this->output,"Testname                                               | running time\n");
	fprintf(this->output,"_______________________________________________________|_____________\n");

	while (tests[current_test] != NULL)
	{
		this->run_test(this,tests[current_test]->test_function,tests[current_test]->test_name);
		current_test++;
	}
	fprintf(this->output,"=====================================================================\n");
	fprintf(this->output,"End testing. %d of %d tests succeeded\n",this->tests_count - this->failed_tests_count,this->tests_count);
	fprintf(this->output,"=====================================================================\n");
}

/**
 * Implementation of tester_t.perform_test.
 */
static void perform_test(private_tester_t *this, test_t *test)
{
	test_t *tests[] = {test, NULL};
	return (perform_tests(this,tests));
}

/**
 * Returns the difference of to timeval structs in microseconds.
 *
 * @warning this function is also defined in the event queue
 * 			in later improvements, this function can be added to a general
 *          class type!
 *
 * @param end_time 		end time
 * @param start_time 	start time
 * 
 * @TODO make object function or move to utils!
 *
 * @return difference in microseconds
 */
static long time_difference(private_tester_t *this,struct timeval *end_time, struct timeval *start_time)
{
	long seconds, microseconds;

	seconds = (end_time->tv_sec - start_time->tv_sec);
	microseconds = (end_time->tv_usec - start_time->tv_usec);
	return ((seconds * 1000000) + microseconds);
}


/**
 * Implementation of private_tester_t.run_test.
 */
static void run_test(private_tester_t *this, void (*test_function) (protected_tester_t * tester), char * test_name)
{
	struct timeval start_time, end_time;
	long timediff;
	this->tests_count++;
	this->failed_asserts_count = 0;
	fprintf(this->output,"%-55s\n", test_name);
	gettimeofday(&start_time,NULL);
	test_function(&(this->protected));
	gettimeofday(&end_time,NULL);
	timediff = this->time_difference(this,&end_time, &start_time);

	if (this->failed_asserts_count > 0)
	{
		fprintf(this->output,"  => Test failed: %-37s|%10ld us\n",test_name,timediff);
	}else
	{
		fprintf(this->output,"\033[1A\033[55C|%10ld us\033[1B\033[80D",timediff);
	}
	if (this->failed_asserts_count > 0)
	{
		this->failed_tests_count++;
	}
}
 

/**
 * Implementation of tester_t.assert_true.
 */
static void assert_true(private_tester_t *this, bool to_be_true,char * assert_name)
{
	if (assert_name == NULL)
	{
		assert_name = "unknown";
	}

	pthread_mutex_lock(&(this->mutex));
	if (!to_be_true)
	{
		this->failed_asserts_count++;
		fprintf(this->output,"  check '%s' failed!\n", assert_name);
	}else
	{
		if (this->display_succeeded_asserts)
		{
			fprintf(this->output,"  check '%s' succeeded\n", assert_name);
		}
	}
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of tester_t.assert_false.
 */
static void assert_false(private_tester_t *this, bool to_be_false,char * assert_name)
{
	this->protected.assert_true(&(this->protected),(!to_be_false),assert_name);
}

/**
 * Implementation of tester_t.destroy.
 */
static void destroy(private_tester_t *tester)
{
	private_tester_t *this = (private_tester_t*) tester;
	pthread_mutex_destroy(&(this->mutex));
	free(this);
}

/*
 * Described in header.
 */
tester_t *tester_create(FILE *output, bool display_succeeded_asserts)
{
	private_tester_t *this = malloc_thing(private_tester_t);

	/* public functions */
	this->protected.public.destroy = (void (*) (tester_t *))destroy;
	this->protected.public.perform_tests = (void (*) (tester_t *, test_t**)) perform_tests;
	this->protected.public.perform_test = (void (*) (tester_t *, test_t*))perform_test;
	this->protected.assert_true =  (void (*) (protected_tester_t *, bool, char*)) assert_true;
	this->protected.assert_false = (void (*) (protected_tester_t *, bool, char*)) assert_false;
	
	/* private functions */
	this->run_test = run_test;
	this->time_difference = time_difference;
	
	/* private data */
	this->display_succeeded_asserts = display_succeeded_asserts;
	this->failed_tests_count = 0;
	this->tests_count = 0;
	this->output = output;
	pthread_mutex_init(&(this->mutex),NULL);

	return &(this->protected.public);
}
