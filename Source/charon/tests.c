/**
 * @file tests.c
 * 
 * @brief Main for all tests
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
 
 
#include <stdio.h>
#
#include "tester.h"
#include "job_queue.h"
#include "event_queue.h"
#include "send_queue.h"
#include "socket.h"
#include "tests/linked_list_test.h"
#include "tests/thread_pool_test.h"
#include "tests/job_queue_test.h"
#include "tests/event_queue_test.h"
#include "tests/send_queue_test.h"
#include "tests/socket_test.h"


/* output for test messages */
extern FILE * stderr;

/**
 * Test for linked_list_t
 */
test_t linked_list_test = {test_linked_list,"Linked List"};

/**
 * Test for linked_list_t with iterator
 */
test_t linked_list_iterator_test = {test_linked_list_iterator,"Linked List Iterator"};

/**
 * Test for linked_list_t insert and remove
 */
test_t linked_list_insert_and_remove_test = {test_linked_list_insert_and_remove,"Linked List Insert and remove"};

/**
 * Test for event_queue_t
 */
test_t event_queue_test = {test_event_queue,"Event-Queue Test"};

/**
 * Test 1 for job_queue_t
 */
test_t job_queue_test1 = {test_job_queue,"Job-Queue Test1"};

/**
 * Test 1 for linked_list_t
 */
test_t send_queue_test = {test_send_queue,"Send-Queue Test"};

/**
 * Test for socket_t
 */
test_t socket_test = {test_socket,"Socket"};

/**
 * Test for thread_pool_t
 */
test_t thread_pool_test = {test_thread_pool,"Thread Pool"};


/**
 * Global job-queue
 */
job_queue_t *global_job_queue;

/**
 * Global event-queue
 */
event_queue_t *global_event_queue;
 
 /**
  * Global send-queue
  */
send_queue_t *global_send_queue;

 /**
  * Global socket
  */
socket_t *global_socket;
  
 int main()
{
 	FILE * test_output = stderr;
 	
 	test_t *all_tests[] ={
	&linked_list_test,
	&linked_list_iterator_test,
	&linked_list_insert_and_remove_test,
	&thread_pool_test,
	&job_queue_test1,
	&event_queue_test,
	&send_queue_test,
	&socket_test,
	NULL
	};
 	
	global_socket = socket_create(4600);
 	
 	global_job_queue = job_queue_create();
 	global_event_queue = event_queue_create();
 	global_send_queue = send_queue_create();
 	 	
 	tester_t *tester = tester_create(test_output, FALSE);

	tester->perform_tests(tester,all_tests);
// 	tester->perform_test(tester,&event_queue_test);
 	
	tester->destroy(tester);

	/* Destroy all queues */
	global_job_queue->destroy(global_job_queue);
	global_event_queue->destroy(global_event_queue);	
	global_send_queue->destroy(global_send_queue);
	
	global_socket->destroy(global_socket);
	
#ifdef LEAK_DETECTIVE
	/* Leaks are reported in log file */
	report_leaks();
#endif
	
	return 0;
}
