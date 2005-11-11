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

#include "../logger_manager.h"
#include "../allocator.h"
#include "../tester.h"
#include "../queues/job_queue.h"
#include "../queues/event_queue.h"
#include "../queues/send_queue.h"
#include "../socket.h"
#include "linked_list_test.h"
#include "thread_pool_test.h"
#include "job_queue_test.h"
#include "event_queue_test.h"
#include "send_queue_test.h"
#include "socket_test.h"
#include "sender_test.h"
#include "scheduler_test.h"
#include "receiver_test.h"
#include "ike_sa_id_test.h"
#include "ike_sa_test.h"
#include "ike_sa_manager_test.h"
#include "generator_test.h"
#include "parser_test.h"
#include "packet_test.h"


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
test_t event_queue_test = {test_event_queue,"Event-Queue"};

/**
 * Test 1 for job_queue_t
 */
test_t job_queue_test1 = {test_job_queue,"Job-Queue"};

/**
 * Test 1 for linked_list_t
 */
test_t send_queue_test = {test_send_queue,"Send-Queue"};

/**
 * Test for socket_t
 */
test_t socket_test = {test_socket,"Socket"};

/**
 * Test for thread_pool_t
 */
test_t thread_pool_test = {test_thread_pool,"Thread Pool"};

/**
 * Test for sender_t
 */
test_t sender_test = {test_sender,"Sender"};

/**
 * Test for scheduler_t
 */
test_t scheduler_test = {test_scheduler,"Scheduler"};

/**
 * Test for receiver_t
 */
test_t receiver_test = {test_receiver,"Receiver"};

/**
 * Test for ike_sa_id_t
 */
test_t ike_sa_id_test = {test_ike_sa_id,"IKE_SA-Identifier"};

/**
 * Test for ike_sa_t
 */
test_t ike_sa_test = {test_ike_sa,"IKE_SA"};


/**
 * Test for ike_sa_manager_t
 */
test_t ike_sa_manager_test = {test_ike_sa_manager, "IKE_SA-Manager"};

/**
 * Test for generator_t
 */
test_t generator_test1 = {test_generator_with_unsupported_payload,"Generator: unsupported payload"};

/**
 * Test 2 for generator_t
 */
test_t generator_test2 = {test_generator_with_header_payload,"Generator: header payload"};

/**
 * Test 2 for generator_t
 */
test_t parser_test = {test_parser_with_header_payload, "Parser: header payload"};


/**
 * Test for packet_t
 */
test_t packet_test = {test_packet,"Packet"};


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


/**
 * Global logger
 */
logger_manager_t *global_logger_manager;
  
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
	&scheduler_test,
	&socket_test,
	&sender_test,
	&receiver_test,
	&ike_sa_id_test,
	&ike_sa_test,
	&generator_test1,
	&generator_test2,
	&parser_test,
	&ike_sa_manager_test,
	&packet_test,
	NULL
	};
 	global_logger_manager = logger_manager_create(CONTROL);
 	
	global_socket = socket_create(4600);
 	
 	global_job_queue = job_queue_create();
 	global_event_queue = event_queue_create();
 	global_send_queue = send_queue_create();
 	

 	 	
 	tester_t *tester = tester_create(test_output, FALSE);

	tester->perform_tests(tester,all_tests);
/*	tester->perform_test(tester,&parser_test);   */
 	
	tester->destroy(tester);


	/* Destroy all queues */
	global_job_queue->destroy(global_job_queue);
	global_event_queue->destroy(global_event_queue);	
	global_send_queue->destroy(global_send_queue);
	
	global_socket->destroy(global_socket);
	
	global_logger_manager->destroy(global_logger_manager);
	
#ifdef LEAK_DETECTIVE
	/* Leaks are reported on stderr */
	report_memory_leaks(void);
#endif
	
	return 0;
}
