/**
 * @file send_queue_test.c
 *
 * @brief Tests for the send_queue_t class.
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

#include <pthread.h>

#include "send_queue_test.h"

#include <queues/send_queue.h>


/**
 * @brief Informations for the involved test-thread used in this test
 *
 */
typedef struct send_queue_test_s send_queue_test_t;


struct send_queue_test_s{
	/**
	 * Associated protected_tester_t object
	 */
	protected_tester_t *tester;

	/**
	 * Queue to test
	 */
	send_queue_t *send_queue;

	/**
	 * number of items to be inserted in the send-queue by each thread
	 */
	int insert_item_count;

	/**
	 * number of items to be removed by each
	 * receiver thread from the send-queue
	 */
	int remove_item_count;
};

/**
 * @brief sender thread used in the the send_queue test function
 *
 * @param testinfo informations for the specific thread.
 */
static void test_send_queue_sender(send_queue_test_t * testinfo)
{
	int i;
	for (i = 0; i < testinfo->insert_item_count; i++)
	{
		packet_t *packet = packet_create();
		testinfo->tester->assert_true(testinfo->tester,(packet != NULL), "create packet call check");
		testinfo->send_queue->add(testinfo->send_queue,packet);
	}
}

/**
 * @brief receiver thread used in the the send_queue test function
 *
 * @param testinfo informations for the specific thread.
 */
static void test_send_queue_receiver(send_queue_test_t * testinfo)
{
	int i;
	for (i = 0; i < testinfo->remove_item_count; i++)
	{
		packet_t *packet;
		packet = testinfo->send_queue->get(testinfo->send_queue);

		testinfo->tester->assert_true(testinfo->tester,(	packet != NULL), "packet not NULL call check");

		packet->destroy(packet);
	}
}

/*
 * description is in header file
 */
void test_send_queue(protected_tester_t *tester)
{
	int desired_value, i;
	int sender_count = 10;
	int receiver_count = 2;
	pthread_t sender_threads[sender_count];
	pthread_t receiver_threads[receiver_count];
	send_queue_t *send_queue = send_queue_create();
	send_queue_test_t test_infos;

	test_infos.tester = tester;
	test_infos.send_queue = send_queue;
	test_infos.insert_item_count = 10000;
	test_infos.remove_item_count = 10000;


	desired_value = test_infos.insert_item_count * sender_count -
					test_infos.remove_item_count * receiver_count;

	for (i = 0; i < receiver_count;i++)
	{
		pthread_create( &receiver_threads[i], NULL,(void*(*)(void*)) &test_send_queue_receiver, (void*) &test_infos);
	}

	for (i = 0; i < sender_count;i++)
	{
		pthread_create( &sender_threads[i], NULL,(void*(*)(void*)) &test_send_queue_sender, (void*) &test_infos);
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


	/* the send-queue has to have diserd_value count entries*/
	tester->assert_true(tester,(send_queue->get_count(send_queue) == desired_value), "count value check");
	send_queue->destroy(send_queue);
}
