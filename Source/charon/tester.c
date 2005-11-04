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
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
 
#include "tester.h"
#include "linked_list.h"
#include "thread_pool.h"
#include "job_queue.h"

/**
 * @brief Private Variables and Functions of tester class
 * 
 */
typedef struct private_tester_s private_tester_t;
 
struct private_tester_s {
 	tester_t public;
 	
	/* Private values */
 	FILE* output;
 	int tests_count;
 	int failed_tests_count;
 	int failed_asserts_count;
 	bool display_succeeded_asserts;
 	pthread_mutex_t mutex;
};
 
/*
 * Implementation of function test_all
 */
static status_t test_all(tester_t *tester,test_t **tests) 
{
	private_tester_t *this =(private_tester_t*) tester;
	int current_test = 0;
	fprintf(this->output,"Start testing\n");

	while (tests[current_test] != NULL)
	{
		tester->run_test(tester,tests[current_test]->test_function,tests[current_test]->test_name);
		current_test++;
	}
	
	fprintf(this->output,"End testing. %d of %d tests succeeded\n",this->tests_count - this->failed_tests_count,this->tests_count);

	return SUCCESS;
}

/**
 * Returns the difference of to timeval structs in microseconds
 * 
 * @param end_time end time
 * @param start_time start time
 * 
 * @warning this function is also defined in the event queue
 * 			in later improvements, this function can be added to a general
 *          class type!
 * 
 * @return difference in microseconds
 */
static long time_difference(struct timeval *end_time, struct timeval *start_time)
{
	long seconds, microseconds;
	
	seconds = (end_time->tv_sec - start_time->tv_sec);
	microseconds = (end_time->tv_usec - start_time->tv_usec);
	return ((seconds * 1000000) + microseconds);
}


/**
 * Implementation of function run_test 
 */
static void run_test(tester_t *tester, void (*test_function) (tester_t * tester), char * test_name)
{
	struct timeval start_time, end_time;
	long timediff;
	private_tester_t *this = (private_tester_t *) tester;
	this->tests_count++;
	this->failed_asserts_count = 0;
	fprintf(this->output,"Start Test '%s'\n", test_name);
	gettimeofday(&start_time,NULL);
	test_function(tester);
	gettimeofday(&end_time,NULL);
	timediff = time_difference(&end_time, &start_time);
	
	fprintf(this->output,"End Test '%s' in %ld microseconds\n", test_name,timediff);
	if (this->failed_asserts_count > 0)
	{
		this->failed_tests_count++;
	}
}

/**
 * Implementation of function assert_true 
 */
static void assert_true(tester_t *tester, bool to_be_true,char * assert_name)
{
	private_tester_t *this = (private_tester_t *) tester;
	
	if (assert_name == NULL)
	{
		assert_name = "unknown";
	}
	
	pthread_mutex_lock(&(this->mutex));
	if (!to_be_true)
	{
		this->failed_asserts_count++;
		fprintf(this->output,"  Assert '%s' failed!\n", assert_name);		
	}else
	{
		if (this->display_succeeded_asserts)
		{
			fprintf(this->output,"  Assert '%s' succeeded\n", assert_name);		
		}
	}
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of function assert_false
 */
static void assert_false(tester_t *tester, bool to_be_false,char * assert_name)
{
	tester->assert_true(tester,(!to_be_false),assert_name);
}

/**
 * Implements the destroy function
 */
static status_t destroy(tester_t *tester) 
{
	private_tester_t *this = (private_tester_t*) tester;
	pthread_mutex_destroy(&(this->mutex));
	pfree(this);
	return SUCCESS;
}

tester_t *tester_create(FILE *output, bool display_succeeded_asserts) 
{
	private_tester_t *this = alloc_thing(private_tester_t, "private_tester_t");
	
	this->public.destroy = destroy;
	this->public.test_all = test_all;
	this->public.run_test = run_test;
	this->public.assert_true = assert_true;
	this->public.assert_false = assert_false;

	this->display_succeeded_asserts = display_succeeded_asserts;	
	this->failed_tests_count = 0;
	this->tests_count = 0;
	this->output = output;
	pthread_mutex_init(&(this->mutex),NULL);
	
	return &(this->public);
}
