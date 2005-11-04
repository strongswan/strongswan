/**
 * @file thread_pool_test.c
 * 
 * @brief Tests to test the Socket (type socket_t)
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
#include "../tester.h"
#include "../socket.h"

/*
 * Description in header file
 */
void test_socket(tester_t *tester)
{	
	socket_t *skt = socket_create();
	packet_t *pkt = packet_create();
	char *test_string = "Testing functionality of socket_t";
	
	pkt->data.ptr = test_string;
	pkt->data.len = strlen(test_string);
	
	pkt->receiver.addr.sin_family = AF_INET;
    pkt->receiver.addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    pkt->receiver.addr.sin_port = htons(500);
	
	skt->send(skt, pkt);
	pkt->destroy(pkt);
	skt->receive(skt, &pkt);
	
	tester->assert_false(tester, strcmp(test_string, pkt->data.ptr), "packet exchange");
}

