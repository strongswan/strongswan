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
 	tester_t tester;
 	
	/* Private values */
 	FILE* output;
 	int tests_count;
 	int failed_tests_count;
 	int failed_asserts_count;
 	pthread_mutex_t mutex;

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
static void	test_linked_list(private_tester_t *this)
{
	void *test_value = NULL;

	linked_list_t *linked_list = linked_list_create();
	this->assert_true(this,(linked_list->count == 0), "count check");
	
	linked_list->insert_first(linked_list,"one");
	this->assert_true(this,(linked_list->count == 1), "count check");

	linked_list->insert_first(linked_list,"two");
	this->assert_true(this,(linked_list->count == 2), "count check");
		
	linked_list->insert_first(linked_list,"three");
	this->assert_true(this,(linked_list->count == 3), "count check");

	linked_list->insert_first(linked_list,"four");
	this->assert_true(this,(linked_list->count == 4), "count check");

	linked_list->insert_first(linked_list,"five");
	this->assert_true(this,(linked_list->count == 5), "count check");

	this->assert_true(this,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	this->assert_true(this,(strcmp((char *) test_value,"five") == 0), "get_first value check");
	this->assert_true(this,(linked_list->count == 5), "count check");

	this->assert_true(this,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	this->assert_true(this,(strcmp((char *) test_value,"one") == 0), "get_last value check");
	this->assert_true(this,(linked_list->count == 5), "count check");
	this->assert_true(this,(linked_list->remove_first(linked_list,&test_value) == SUCCESS), "remove_first call check");
	this->assert_true(this,(strcmp((char *) test_value,"five") == 0), "remove_first value check");	
	this->assert_true(this,(linked_list->count == 4), "count check");

	this->assert_true(this,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	this->assert_true(this,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	this->assert_true(this,(linked_list->count == 4), "count check");

	this->assert_true(this,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	this->assert_true(this,(strcmp((char *) test_value,"one") == 0), "get_last value check");	
	this->assert_true(this,(linked_list->count == 4), "count check");

	this->assert_true(this,(linked_list->remove_last(linked_list,&test_value) == SUCCESS), "remove_last call check");
	this->assert_true(this,(strcmp((char *) test_value,"one") == 0), "remove_last value check");	
	this->assert_true(this,(linked_list->count == 3), "count check");

	this->assert_true(this,(linked_list->get_last(linked_list,&test_value) == SUCCESS), "get_last call check");
	this->assert_true(this,(strcmp((char *) test_value,"two") == 0), "get_last value check");		
	this->assert_true(this,(linked_list->count == 3), "count check");

	this->assert_true(this,(linked_list->get_first(linked_list,&test_value) == SUCCESS), "get_first call check");
	this->assert_true(this,(strcmp((char *) test_value,"four") == 0), "get_first value check");
	this->assert_true(this,(linked_list->count == 3), "count check");
	
	this->assert_true(this,(linked_list->destroy(linked_list) == SUCCESS), "destroy call check");
}

/**
 * @brief Test function to test the thread pool class
 */
static void test_thread_pool(private_tester_t *this)
{
	size_t desired_pool_size = 10;
	size_t pool_size;
	
	thread_pool_t *pool = thread_pool_create(desired_pool_size);
	pool->get_pool_size(pool, &pool_size);
	this->assert_true(this, (desired_pool_size == pool_size), "thread creation");
	pool->destroy(pool);
}

typedef struct job_queue_test_s job_queue_test_t;

struct job_queue_test_s{
	private_tester_t *tester;
	job_queue_t *job_queue;
	int max_queue_item_count;	
};

/**
 * @brief sender thread used in the the job_queue test function
 */
static void test_job_queue_sender(job_queue_test_t * testinfo)
{
	
	int i;
	
	for (i = 0; i < testinfo->max_queue_item_count; i++)
	{
		int *value = alloc_thing(int,"int");
		*value = i;
		job_t *job = job_create(INCOMING_PACKET,value);
		testinfo->job_queue->add(testinfo->job_queue,job);
	}
}

/**
 * @brief receiver thread used in the the job_queue test function
 */
static void test_job_queue_receiver(job_queue_test_t * testinfo)
{
	int i;
	
	for (i = 0; i < testinfo->max_queue_item_count; i++)
	{
		job_t *job;
		testinfo->tester->assert_true(testinfo->tester,(testinfo->job_queue->get(testinfo->job_queue,&job) == SUCCESS), "get job call check");
		testinfo->tester->assert_true(testinfo->tester,(job->type == INCOMING_PACKET), "job type check");
		testinfo->tester->assert_true(testinfo->tester,((*((int *) (job->assigned_data))) == i), "job value check");
		
		pfree(job->assigned_data);
		testinfo->tester->assert_true(testinfo->tester,(job->destroy(job) == SUCCESS), "job destroy call check");
	}
}

/**
 * @brief Test function test the job_queue functionality
 */
static void	test_job_queue(private_tester_t *this)
{
	pthread_t sender_thread, receiver_thread;
	job_queue_t *job_queue = job_queue_create();
	job_queue_test_t test_infos;
	test_infos.tester = this;
	test_infos.job_queue = job_queue;
	test_infos.max_queue_item_count = 100;
	
	pthread_create( &receiver_thread, NULL,(void*(*)(void*)) &test_job_queue_receiver, (void*) &test_infos);
	pthread_create( &sender_thread, NULL,(void*(*)(void*)) &test_job_queue_sender, (void*) &test_infos);

	pthread_join(sender_thread, NULL);
	pthread_join(receiver_thread, NULL);

	this->assert_true(this,(job_queue->destroy(job_queue) == SUCCESS), "destroy call check");
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
	this->run_test(this,test_thread_pool,"Thread Pool");
	this->run_test(this,test_job_queue,"Job-Queue");
	
	fprintf(this->output,"End testing. %d of %d tests succeeded\n",this->tests_count - this->failed_tests_count,this->tests_count);

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
	
	pthread_mutex_lock(&(this->mutex));
	if (!to_be_true)
	{
		this->failed_asserts_count++;
		fprintf(this->output,"  Assert '%s' failed!\n", assert_name);		
	}else
	{
		fprintf(this->output,"  Assert '%s' succeeded\n", assert_name);		
	}
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implements the destroy function
 * 
 */
static status_t destroy(tester_t *tester) 
{
	private_tester_t *this = (private_tester_t*) tester;
	pthread_mutex_destroy(&(this->mutex));
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
	pthread_mutex_init(&(this->mutex),NULL);
	
	return &(this->tester);
}
