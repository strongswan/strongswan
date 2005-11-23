/**
 * @file receiver_test.c
 *
 * @brief Tests to test the Receiver (type receiver_t)
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

#include "receiver_test.h"

#include <globals.h>
#include <receiver.h>
#include <network/packet.h>
#include <network/socket.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <queues/jobs/incoming_packet_job.h>
#include <payloads/encodings.h>
#include <utils/allocator.h>

/**
 * Number of packets to send by sender-thread
 */
#define NUMBER_OF_PACKETS_TO_SEND 100

/**
 * Port to send the packets to
 */
#define PORT_TO_SEND 4600

/**
 * Destination IP Address
 */
#define DESTINATION_IP "127.0.0.1"

void test_receiver(tester_t *tester)
{
	int i;
	receiver_t *receiver;
	packet_t *packet;
	job_t *job;
	packet_t *received_packet;
	receiver = receiver_create();

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		packet = packet_create();
		packet->destination = host_create(AF_INET,DESTINATION_IP,PORT_TO_SEND);
		packet->data.ptr = allocator_alloc_thing(int);
		packet->data.len = ( sizeof(int));
		*((int *) (packet->data.ptr)) = i;
		global_socket->send(global_socket,packet);
		packet->destroy(packet);
	}

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		global_job_queue->get(global_job_queue,&job);
		tester->assert_true(tester, (job->get_type(job) == INCOMING_PACKET), "job type check");
		
		((incoming_packet_job_t *)(job))->get_packet((incoming_packet_job_t *)(job),&received_packet);
		tester->assert_true(tester, (received_packet->data.len == (sizeof(int))), "received data length check");
		tester->assert_true(tester, (i == *((int *)(received_packet->data.ptr))), "received data value check");
		received_packet->destroy(received_packet);

		job->destroy(job);
	}

	tester->assert_true(tester, (receiver->destroy(receiver) == SUCCESS), "destroy call check");
}
