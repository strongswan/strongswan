/**
 * @file packet_test.c
 *
 * @brief Tests for the packet_t class.
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

#include <globals.h>
#include <network/packet.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>


/*
 * Described in Header 
 */
void test_packet(tester_t *tester)
{
	packet_t *packet = packet_create();
	packet_t *packet2;
	char * string_to_copy = "aha, soso";
	
	packet->data.ptr = allocator_alloc(strlen(string_to_copy) + 1);
	tester->assert_true(tester,(packet->data.ptr != NULL),"NULL pointer check");
	
	packet->data.len = strlen(string_to_copy) + 1;
	strcpy(packet->data.ptr,string_to_copy);

	tester->assert_true(tester,(packet != NULL),"NULL pointer check");
	packet2 = packet->clone(packet);

	tester->assert_false(tester,(packet->data.ptr == packet2->data.ptr),"value pointer check");
	
	tester->assert_true(tester,(packet->data.len == (strlen(string_to_copy) + 1)),"value length check");
	
	tester->assert_true(tester,(memcmp(packet->data.ptr,packet2->data.ptr,packet->data.len) == 0),"cloned value check");
	
	packet2->destroy(packet2);
	packet->destroy(packet);
}
