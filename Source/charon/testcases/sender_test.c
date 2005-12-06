/**
 * @file sender_test.h
 *
 * @brief Tests for the sender_t class.
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

#include "sender_test.h"

#include <daemon.h>
#include <threads/sender.h>
#include <network/packet.h>
#include <network/socket.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <utils/allocator.h>

/**
 * Number of packets to send by sender-thread
 */
#define NUMBER_OF_PACKETS_TO_SEND 50

/**
 * Port to send the packets to
 */
#define PORT_TO_SEND 4600

/**
 * Destination IP Address
 */
#define DESTINATION_IP "127.0.0.1"

void test_sender(tester_t *tester)
{
	int i;
	sender_t *sender;
	packet_t *packet;
	packet_t *received_packet;
	chunk_t packet_data;
	sender = sender_create();

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		packet = packet_create(AF_INET);
		packet->set_destination(packet, host_create(AF_INET,DESTINATION_IP,PORT_TO_SEND));
		packet_data.ptr = allocator_alloc_thing(int);
		packet_data.len = ( sizeof(int));
		*((int *) (packet_data.ptr)) = i;
		packet->set_data(packet, packet_data);
		charon->send_queue->add(charon->send_queue,packet);
	}

	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		charon->socket->receive(charon->socket,&received_packet);
		packet_data = received_packet->get_data(received_packet);
		tester->assert_true(tester, (packet_data.len == (sizeof(int))), "received data length check");
		tester->assert_true(tester, (i == *((int *)(packet_data.ptr))), "received data value check");
		received_packet->destroy(received_packet);
	}

	sender->destroy(sender);
}
