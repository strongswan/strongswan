/*
 * Copyright (C) 2026 Arthur SC Chan
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

#include <daemon.h>
#include <library.h>
#include <encoding/message.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
dbg_default_set_level(-1);
library_init(NULL, "fuzz_ikev1");
libcharon_init();
return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	message_t *message;
	packet_t *packet;
	host_t *src, *dst;
	chunk_t data;

	if (len < 28)
	{
		return 0;
	}

	src = host_create_from_string("192.0.2.1", 500);
	dst = host_create_from_string("192.0.2.2", 500);
	data = chunk_clone(chunk_create((u_char*)buf, len));
	packet = packet_create_from_data(src, dst, data);

	if (!packet)
	{
		return 0;
	}

	message = message_create_from_packet(packet);
	if (message)
	{
		if (message->parse_header(message) == SUCCESS)
		{
			message->parse_body(message, NULL);
		}
		message->destroy(message);
	}

	return 0;
}
