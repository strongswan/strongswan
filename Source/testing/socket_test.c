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
#include <utils/allocator.h>

/*
 * Description in header file
 */
void test_socket(protected_tester_t *tester)
{
	int packet_count = 5;
	int current;
	socket_t *skt = socket_create(4500);
	packet_t *pkt = packet_create(AF_INET);
	char *test_string = "Testing functionality of socket_t";
	chunk_t data;


	data.ptr = allocator_alloc(strlen(test_string) + 1);
	memcpy(data.ptr,test_string,strlen(test_string) + 1);
	data.len = strlen(test_string) + 1;

	/* send to previously bound socket */
	pkt->set_destination(pkt, host_create(AF_INET, "127.0.0.1", 4500));
	pkt->set_data(pkt, data);

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
		data = pkt->get_data(pkt);
		tester->assert_false(tester, strcmp(test_string, data.ptr), "packet exchange");
		pkt->destroy(pkt);
   	}

	skt->destroy(skt);

}
