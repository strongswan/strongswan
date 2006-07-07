/**
 * @file sender_test.h
 *
 * @brief Tests for the sender_t class.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "sender_test.h"

#include <daemon.h>
#include <threads/sender.h>
#include <network/packet.h>
#include <network/socket.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <queues/jobs/incoming_packet_job.h>

/**
 * Number of packets to send by sender-thread
 */
#define NUMBER_OF_PACKETS_TO_SEND 5

void test_sender(protected_tester_t *tester)
{
	int i;
	sender_t *sender;
	receiver_t *receiver;
	job_t *job;
	packet_t *packet;
	packet_t *received_packet;	
	char test_data[] = {
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03, /* spi */
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05, /* spi */
		0x05, /* next payload */
		0x20, /* IKE version */
		0x00, /* exchange type */
		0x00, /* flags */
		0x00,0x00,0x00,0x01, /* message id */
		0x00,0x00,0x00,0x24, /* length */
		0x12,0x34,0x56,0x67, /* some data */
		0x12,0x34,0x56,0x67, 
	};
	chunk_t data = chunk_from_buf(test_data);
	chunk_t received;
	sender = sender_create();
	receiver = receiver_create();

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		packet = packet_create();
		packet->set_destination(packet, host_create(AF_INET, "127.0.0.1", 500));
		packet->set_source(packet, host_create(AF_INET, "127.0.0.1", 500));
		packet->set_data(packet, chunk_clone(data));
		charon->send_queue->add(charon->send_queue,packet);
	}

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		job = charon->job_queue->get(charon->job_queue);
		tester->assert_true(tester, (job->get_type(job) == INCOMING_PACKET), "job type check");
		received_packet = ((incoming_packet_job_t *)(job))->get_packet((incoming_packet_job_t *)(job));
		received = received_packet->get_data(received_packet);
		tester->assert_true(tester, received.len == data.len, "received data length check");
		tester->assert_true(tester, memcmp(received.ptr, data.ptr, data.len) == 0, "received data value check");
		received_packet->destroy(received_packet);
		job->destroy(job);
	}

	sender->destroy(sender);
	receiver->destroy(receiver);
}
