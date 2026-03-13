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

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	radius_message_t *msg;
	chunk_t data;
	enumerator_t *enumerator;
	int type;
	chunk_t attr_data;

	if (len < 20)
	{
		return 0;
	}

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_radius");
	plugin_loader_add_plugindirs(PLUGINDIR, PLUGINS);
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	/* Fuzz RADIUS message creation and parsing */
	data = chunk_create((u_char*)buf, len);
	msg = radius_message_parse(data);

	/* Fuzz RADIUS message methods */
	if (msg)
	{
		msg->get_code(msg);
		msg->get_identifier(msg);
		msg->get_authenticator(msg);
		msg->get_encoding(msg);

		enumerator = msg->create_enumerator(msg);
		int count = 0;
		while (count++ < 10000 && enumerator->enumerate(enumerator, &type, &attr_data))
		{
		}
		enumerator->destroy(enumerator);

		enumerator = msg->create_vendor_enumerator(msg);
		int vendor, vtype;
		count = 0;
		while (count++ < 10000 && enumerator->enumerate(enumerator, &vendor, &vtype, &attr_data))
		{
		}
		enumerator->destroy(enumerator);

		msg->destroy(msg);
	}

	lib->plugins->unload(lib->plugins);
	library_deinit();
	return 0;
}
