/**
 * @file event_queue_test.h
 * 
 * @brief Tests to test the Event-Queue type event_queue_t
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
 
 
#include "event_queue_test.h"
#include "../tester.h"
#include "../event_queue.h"

void test_event_queue(tester_t *tester)
{
	event_queue_t * event_queue = event_queue_create();
	timeval_t current_time;
	timeval_t time1, time2, time3;
	job_t * current_job;
	int count;
	job_t * job1 = job_create(INCOMING_PACKET,"incoming packet");
	job_t * job2 = job_create(RETRANSMIT_REQUEST,"retransmit request");
	job_t * job3 = job_create(ESTABLISH_IKE_SA,"establish ike sa");
	
	gettimeofday(&current_time,NULL);
	time1.tv_usec = 0;
	time1.tv_sec = current_time.tv_sec + 3;
	time2.tv_usec = 0;
	time2.tv_sec = current_time.tv_sec + 12;
	time3.tv_usec = 0;
	time3.tv_sec = current_time.tv_sec + 12;

	tester->assert_true(tester,(event_queue->add(event_queue,job1,time1) == SUCCESS), "add call check");
	tester->assert_true(tester,(event_queue->get_count(event_queue,&count) == SUCCESS), "get_count call check");
	tester->assert_true(tester,(count == 1), "count value check");
	
	tester->assert_true(tester,(event_queue->add(event_queue,job2,time2) == SUCCESS), "add call check");
	tester->assert_true(tester,(event_queue->get_count(event_queue,&count) == SUCCESS), "get_count call check");
	tester->assert_true(tester,(count == 2), "count value check");
	
	tester->assert_true(tester,(event_queue->add(event_queue,job3,time3) == SUCCESS), "add call check");
	tester->assert_true(tester,(event_queue->get_count(event_queue,&count) == SUCCESS), "get_count call check");
	tester->assert_true(tester,(count == 3), "count value check");

	tester->assert_true(tester,(event_queue->get(event_queue,&current_job) == SUCCESS), "get call check");
	fprintf(stderr,"%s\n",(char *) current_job->assigned_data);
	tester->assert_true(tester,(event_queue->get(event_queue,&current_job) == SUCCESS), "get call check");
	fprintf(stderr,"%s\n",(char *) current_job->assigned_data);
	tester->assert_true(tester,(event_queue->get(event_queue,&current_job) == SUCCESS), "get call check");
	fprintf(stderr,"%s\n",(char *) current_job->assigned_data);

	tester->assert_true(tester,(event_queue->destroy(event_queue) == SUCCESS), "destroy call check");
}
