/**
 * @file sender_test.h
 * 
 * @brief Tests to test the Sender (type sender_t)
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
#include "../sender.h"
#include "../packet.h"
#include "../socket.h"
#include "../send_queue.h"
#include "../job_queue.h"

extern send_queue_t *global_send_queue;

extern socket_t *global_socket;

/**
 * Number of packets to send by sender-thread
 */
#define NUMBER_OF_PACKETS_TO_SEND 400

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
	sender = sender_create();
	
	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		packet = packet_create(AF_INET);
		packet->set_destination(packet,DESTINATION_IP,PORT_TO_SEND);
		packet->data.ptr = alloc_thing(int, "packet data");
		packet->data.len = ( sizeof(int));
		*((int *) (packet->data.ptr)) = i;
		global_send_queue->add(global_send_queue,packet);
	}
	
	for (i = 0; i < NUMBER_OF_PACKETS_TO_SEND; i++)
	{
		global_socket->receive(global_socket,&received_packet);
		tester->assert_true(tester, (received_packet->data.len == (sizeof(int))), "received data length check");
		tester->assert_true(tester, (i == *((int *)(received_packet->data.ptr))), "received data value check");
		received_packet->destroy(received_packet);
	}		
	
	tester->assert_true(tester, (sender->destroy(sender) == SUCCESS), "destroy call check");
}
