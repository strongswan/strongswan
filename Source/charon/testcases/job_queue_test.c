/**
 * @file job_queue_test.c
 *
 * @brief Tests for the job_queue_t class.
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
#include <pthread.h>
#include <unistd.h>

#include "job_queue_test.h"

#include <utils/allocator.h>
#include <queues/job_queue.h>
#include <queues/jobs/initiate_ike_sa_job.h>


typedef struct job_queue_test_s job_queue_test_t;

/**
 * @brief Informations for the involved test-thread used in this test
 *
 */
struct job_queue_test_s{
	protected_tester_t *tester;
	job_queue_t *job_queue;
	/**
	 * number of items to be inserted in the job-queue
	 */
	int insert_item_count;
	/**
	 * number of items to be removed by each
	 * receiver thread from the job-queue
	 */
	int remove_item_count;
};

/**
 * @brief sender thread used in the the job_queue test function
 *
 * @param testinfo informations for the specific thread.
 */
static void test_job_queue_sender(job_queue_test_t * testinfo)
{
	int i;
	for (i = 0; i < testinfo->insert_item_count; i++)
	{
		job_t *job = (job_t *) initiate_ike_sa_job_create(NULL);
		testinfo->job_queue->add(testinfo->job_queue,job);
	}
}

/**
 * @brief receiver thread used in the the job_queue test function
 *
 * @param testinfo informations for the specific thread.
 */
static void test_job_queue_receiver(job_queue_test_t * testinfo)
{
	int i;
	for (i = 0; i < testinfo->remove_item_count; i++)
	{
		job_t *job;
		job = testinfo->job_queue->get(testinfo->job_queue);
		testinfo->tester->assert_true(testinfo->tester,(job->get_type(job) == INITIATE_IKE_SA), "job type check");
		job->destroy(job);
	}
}

/*
 * description is in header file
 */
void test_job_queue(protected_tester_t *tester)
{
	int desired_value, i;
	int sender_count = 10;
	int receiver_count = 2;
	pthread_t sender_threads[sender_count];
	pthread_t receiver_threads[receiver_count];
	job_queue_t *job_queue = job_queue_create();
	job_queue_test_t test_infos;

	test_infos.tester = tester;
	test_infos.job_queue = job_queue;
	test_infos.insert_item_count = 10000;
	test_infos.remove_item_count = 50000;


	desired_value = test_infos.insert_item_count * sender_count -
					test_infos.remove_item_count * receiver_count;

	for (i = 0; i < receiver_count;i++)
	{
		pthread_create( &receiver_threads[i], NULL,(void*(*)(void*)) &test_job_queue_receiver, (void*) &test_infos);
	}
	for (i = 0; i < sender_count;i++)
	{
		pthread_create( &sender_threads[i], NULL,(void*(*)(void*)) &test_job_queue_sender, (void*) &test_infos);
	}


	/* Wait for all threads */
	for (i = 0; i < sender_count;i++)
	{
		pthread_join(sender_threads[i], NULL);
	}
	for (i = 0; i < receiver_count;i++)
	{
		pthread_join(receiver_threads[i], NULL);
	}

	/* the job-queue has to have disered_value count entries! */
	tester->assert_true(tester,(job_queue->get_count(job_queue) == desired_value), "get count value check");

	job_queue->destroy(job_queue);
}
