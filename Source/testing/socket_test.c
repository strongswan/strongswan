/**
 * @file socket_test.c
 *
 * @brief Tests for the socket_t class.
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
#include <string.h>

#include "socket_test.h"

#include <network/socket.h>
#include <utils/logger.h>

/*
 * Description in header file
 */
void test_socket(protected_tester_t *tester)
{
	int packet_count = 10;
	int current;
	socket_t *skt = socket_create(500);
	packet_t *pkt = packet_create(AF_INET);
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

	/* send to previously bound socket */
	pkt->set_destination(pkt, host_create(AF_INET, "127.0.0.1", 500));
	pkt->set_source(pkt, host_create(AF_INET, "127.0.0.1", 500));
	pkt->set_data(pkt, chunk_clone(data));

	/* send packet_count packets */
   	for (current = 0; current < packet_count; current++)
	{
		if (skt->send(skt, pkt) == FAILED)
		{
			tester->assert_true(tester, 0, "packet send");
		}
   	}
	pkt->destroy(pkt);
	

	/* receive packet_count packets */
   	for (current = 0; current < packet_count; current++)
   	{
		skt->receive(skt, &pkt);
		received = pkt->get_data(pkt);
		tester->assert_false(tester, memcmp(received.ptr, data.ptr, max(received.len, data.len)), "packet exchange");
		pkt->destroy(pkt);
   	}

	skt->destroy(skt);

}
