/*
 * Copyright (C) 2026 Arthur SC Chan
 *
 * Copyright (C) secunet Security Networks AG
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

#include <library.h>
#include <utils/debug.h>
#include <radius_message.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_radius");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	radius_message_t *msg;
	chunk_t data;
	enumerator_t *enumerator;
	int type, count, vendor, vtype;
	chunk_t attr_data;

	if (len < 20)
	{
		return 0;
	}

	/* Fuzz RADIUS message creation and parsing */
	data = chunk_create((u_char*)buf, len);
	msg = radius_message_parse(data);

	/* Fuzz RADIUS message methods */
	if (msg)
	{
		enumerator = msg->create_enumerator(msg);
		count = 0;
		while (count++ < 10000 && enumerator->enumerate(enumerator, &type, &attr_data))
		{
		}
		enumerator->destroy(enumerator);

		enumerator = msg->create_vendor_enumerator(msg);
		count = 0;
		while (count++ < 10000 && enumerator->enumerate(enumerator, &vendor, &vtype, &attr_data))
		{
		}
		enumerator->destroy(enumerator);

		/* Fuzz message verification */
		msg->verify(msg, NULL, chunk_empty, NULL, NULL);

		msg->destroy(msg);
	}

	return 0;
}
