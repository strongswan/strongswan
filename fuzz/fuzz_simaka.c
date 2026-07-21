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
#include <simaka_message.h>
#include <simaka_crypto.h>
#include <simaka_manager.h>
#include <utils/debug.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	simaka_manager_t *mgr;

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_simaka");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	mgr = simaka_manager_create();
	lib->set(lib, "sim-manager", mgr);
	mgr = simaka_manager_create();
	lib->set(lib, "aka-manager", mgr);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	simaka_message_t *message;
	simaka_crypto_t *crypto;
	eap_type_t type;
	chunk_t chunk;

	if (len < 1)
	{
		return 0;
	}

	/* First byte picks the EAP method passed to simaka_crypto_create() */
	type = (buf[0] & 1) ? EAP_AKA : EAP_SIM;
	buf++;
	len--;

	crypto = simaka_crypto_create(type);
	if (!crypto)
	{
		return 0;
	}

	chunk = chunk_create((u_char*)buf, len);
	message = simaka_message_create_from_payload(chunk, crypto);
	if (message)
	{
		message->parse(message);
		message->destroy(message);
	}

	crypto->destroy(crypto);
	return 0;
}
