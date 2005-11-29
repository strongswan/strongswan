/**
 * @file scheduler_test.c
 * 
 * @brief Tests to test the Scheduler (type scheduler_t)
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
 
#include <string.h>
#include <unistd.h>

#include "scheduler_test.h"

#include <globals.h>
#include <threads/scheduler.h>
#include <queues/event_queue.h>
#include <queues/job_queue.h>
#include <queues/jobs/incoming_packet_job.h>


/**
 * @brief implementation of a scheduler test
 * 
 * This one uses relative time events, which are not that exact.
 * Test may fail on too slow machines.
 */
void test_scheduler(tester_t *tester)
{
	int job_count = 5;
	job_t *jobs[job_count];
	int current;
	scheduler_t *scheduler = scheduler_create();
	
	/* schedule 5 jobs */
	for (current = 0; current < job_count; current++)
	{
		/* misusing for testing only */
		jobs[current] = (job_t *) incoming_packet_job_create((packet_t*)(current+1));
		global_event_queue->add_relative(global_event_queue, jobs[current], (current+1) * 500);
	}
	
	
	for (current = 0; current < job_count; current++)
	{
		jobs[current] = NULL;
	}
	
	usleep(50 * 1000);
	
	/* check if times are correct */
	for (current = 0; current < job_count; current++)
	{
		usleep(400 * 1000); 
		
		tester->assert_true(tester, (global_job_queue->get_count(global_job_queue) == current ), "job-queue size before event");
		tester->assert_true(tester, (global_event_queue->get_count(global_event_queue) == job_count - current), "event-queue size before event");
		usleep(100 * 1000);

		tester->assert_true(tester, (global_job_queue->get_count(global_job_queue) == current + 1), "job-queue size after event");
		tester->assert_true(tester, (global_event_queue->get_count(global_event_queue) == job_count - current - 1), "event-queue size after event");
	}
	
	/* check job order */
	for (current = 0; current < job_count; current++)
	{
		jobs[current] =	global_job_queue->get(global_job_queue);
		incoming_packet_job_t *current_job;
		current_job = (incoming_packet_job_t*) jobs[current];
		packet_t *packet;
		current_job->get_packet(current_job,&packet);
		
		tester->assert_true(tester, (((int)packet) == current+1), "job order");
		jobs[current]->destroy(jobs[current]);
	}

	/* destruction test */
	scheduler->destroy(scheduler);
}
