/**
 * @file packet_test.c
 *
 * @brief Tests to test the class type packet_t
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

#include "packet_test.h"

#include "../packet.h"
#include "../utils/allocator.h"


/*
 * Described in Header 
 */
void test_packet(tester_t *tester)
{
	packet_t *packet = packet_create(AF_INET);
	packet_t *packet2;
	char * string_to_copy = "aha, soso";
	
	packet->data.ptr = allocator_alloc_thing(string_to_copy);
	packet->data.len = sizeof(string_to_copy);
	memcpy(packet->data.ptr,string_to_copy,packet->data.len);

	tester->assert_true(tester,(packet != NULL),"NULL pointer check");
	
	tester->assert_true(tester,(packet->clone(packet,&packet2) == SUCCESS),"clone call check");

	tester->assert_false(tester,(packet->data.ptr == packet2->data.ptr),"value pointer check");
	
	tester->assert_true(tester,(memcmp(packet->data.ptr,packet2->data.ptr,packet->data.len) == 0),"cloned value check");

	tester->assert_true(tester,(packet->family == packet2->family),"cloned value check");
	tester->assert_true(tester,(packet->sockaddr_len == packet2->sockaddr_len),"cloned value check");
	tester->assert_true(tester,(memcmp(&(packet->source),&(packet2->source), sizeof(struct sockaddr)) == 0),"cloned value check");
	tester->assert_true(tester,(memcmp(&(packet->destination),&(packet2->destination), sizeof(struct sockaddr)) == 0),"cloned value check");
	
	
	packet2->destroy(packet2);
	packet->destroy(packet);
	
	
	
}
