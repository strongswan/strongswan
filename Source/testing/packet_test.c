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

#include <daemon.h>
#include <network/packet.h>
#include <utils/logger_manager.h>


/*
 * Described in Header 
 */
void test_packet(protected_tester_t *tester)
{
	packet_t *packet = packet_create();
	packet_t *packet2;
	chunk_t data;
	char *string_to_copy = "aha, soso";
	
	data.len = strlen(string_to_copy) + 1;
	data.ptr = malloc(data.len);
	memcpy(data.ptr, string_to_copy, data.len);
	
	packet->set_data(packet, data);
	packet2 = packet->clone(packet);
	data = packet2->get_data(packet2);
	
	tester->assert_true(tester,(data.len == (strlen(string_to_copy) + 1)),"value length check");
	tester->assert_true(tester,(memcmp(data.ptr,string_to_copy,data.len) == 0),"cloned value check");
	
	packet2->destroy(packet2);
	packet->destroy(packet);
}
