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

#include <daemon.h>
#include <library.h>
#include <plugins/vici/vici_message.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_vici");
	libcharon_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	enumerator_t *enumerator;
	vici_message_t *msg;
	chunk_t data, value;
	vici_type_t type;
	char *name;
	int count;

	if (len < 1)
	{
		return 0;
	}

	data = chunk_create((u_char*)buf, len);
	msg = vici_message_create_from_data(data, FALSE);

	msg->get_str(msg, NULL, "version");
	msg->get_int(msg, 0, "timeout");
	msg->get_bool(msg, FALSE, "enabled");
	msg->get_value(msg, chunk_empty, "data");

	enumerator = msg->create_enumerator(msg);
	count = 0;
	while (count++ < 10000 &&
		   enumerator->enumerate(enumerator, &type, &name, &value));
	enumerator->destroy(enumerator);

	msg->destroy(msg);
	return 0;
}
