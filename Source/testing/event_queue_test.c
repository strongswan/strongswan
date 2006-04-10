/**
 * @file event_queue_test.h
 *
 * @brief Tests for the event_queue_t class.
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

#include "event_queue_test.h"

#include <queues/event_queue.h>
#include <queues/jobs/initiate_ike_sa_job.h>

/**
 * Number of different times to insert per thread
 */
#define EVENT_QUEUE_TIMES 5
/**
 * Number of entries per time per thread
 */
#define EVENT_QUEUE_ENTRY_PER_TIME 20

/**
 * Number of test-thread
 */
#define EVENT_QUEUE_INSERT_THREADS 1

/**
 * @brief Informations for the involved test-thread used in this test
 *
 */
typedef struct event_queue_test_s event_queue_test_t;

struct event_queue_test_s{
	protected_tester_t *tester;
	event_queue_t *event_queue;

	/**
	 * number of different event times to be inserted in the event-queue by each thread
	 */
	int insert_times_count;

	/**
	 * number of event to insert at one time
	 */
	int entries_per_time;
};


static void event_queue_insert_thread(event_queue_test_t * testinfos)
{
	timeval_t current_time;
	timeval_t time;
	job_t * job;
	int i,j;
	connection_t *connection;

	gettimeofday(&current_time,NULL);
	for (i = 0; i < testinfos->insert_times_count;i++)
	{

		for (j = 0; j < testinfos->entries_per_time;j++)
		{
			job = (job_t *) initiate_ike_sa_job_create(connection);
			time.tv_usec = 0;
			time.tv_sec = current_time.tv_sec + i;

			testinfos->event_queue->add_absolute(testinfos->event_queue,job,time);
		}
	}
}


void test_event_queue(protected_tester_t *tester)
{
	event_queue_t * event_queue = event_queue_create();
	event_queue_test_t testinfos;
	pthread_t threads[EVENT_QUEUE_INSERT_THREADS];
	int i,j, number_of_total_events;
	timeval_t current_time, start_time;

	testinfos.tester = tester;
	testinfos.event_queue = event_queue;
	testinfos.insert_times_count = EVENT_QUEUE_TIMES;
	testinfos.entries_per_time = EVENT_QUEUE_ENTRY_PER_TIME;

	number_of_total_events = EVENT_QUEUE_ENTRY_PER_TIME * EVENT_QUEUE_TIMES * EVENT_QUEUE_INSERT_THREADS;

	gettimeofday(&start_time,NULL);

	for (i = 0; i < EVENT_QUEUE_INSERT_THREADS; i++)
	{
		int retval;
		retval = pthread_create( &(threads[i]), NULL,(void*(*)(void*)) &event_queue_insert_thread, (void*) &testinfos);
		tester->assert_true(tester,(retval== 0), "thread creation call check");
	}


	/* wait for all threads */
	for (i = 0; i < EVENT_QUEUE_INSERT_THREADS; i++)
	{
		int retval;
		retval = pthread_join(threads[i], NULL);
		tester->assert_true(tester,(retval== 0), "thread creation call check");

	}		

	tester->assert_true(tester,(event_queue->get_count(event_queue) == number_of_total_events), "event count check");

	for (i = 0; i < EVENT_QUEUE_TIMES;i++)
	{
		for (j = 0; j < (EVENT_QUEUE_ENTRY_PER_TIME * EVENT_QUEUE_INSERT_THREADS);j++)
		{
			job_t *job;
		
			job = event_queue->get(event_queue);
			gettimeofday(&current_time,NULL);
			tester->assert_true(tester,((current_time.tv_sec - start_time.tv_sec) == i), "value of entry check");
			job->destroy(job);
		}
	}


	event_queue->destroy(event_queue);
	return;
}
