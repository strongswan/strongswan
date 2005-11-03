/**
 * @file job_queue_test.c
 * 
 * @brief Tests to test the Job-Queue type job_queue_t
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

 
//#include <stdlib.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
#include <pthread.h>
 
#include "../tester.h"
#include "../job_queue.h"
 
 
typedef struct job_queue_test_s job_queue_test_t;

struct job_queue_test_s{
	tester_t *tester;
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

/*
 * 
 * description is in header file
 */
void test_job_queue(tester_t *tester)
{
	int value = 1000;
	pthread_t sender_thread, receiver_thread;
	job_queue_t *job_queue = job_queue_create();
	job_queue_test_t test_infos;
	test_infos.tester = tester;
	test_infos.job_queue = job_queue;
	test_infos.max_queue_item_count = 100000;
	
	pthread_create( &receiver_thread, NULL,(void*(*)(void*)) &test_job_queue_receiver, (void*) &test_infos);
	pthread_create( &sender_thread, NULL,(void*(*)(void*)) &test_job_queue_sender, (void*) &test_infos);

	pthread_join(sender_thread, NULL);
	pthread_join(receiver_thread, NULL);
	
	tester->assert_true(tester,(job_queue->get_count(job_queue,&value) == SUCCESS), "get count call check");
	tester->assert_true(tester,(value == 0), "get count value check");
	tester->assert_true(tester,(job_queue->destroy(job_queue) == SUCCESS), "destroy call check");
}
