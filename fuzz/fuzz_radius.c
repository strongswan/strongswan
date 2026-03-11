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
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	enumerator_t *enumerator;
	radius_message_t *msg;
	hasher_t *hasher;
	signer_t *signer;
	chunk_t data, attr_data;
	int type, count, vendor;

	if (len < 20)
	{
		return 0;
	}

	data = chunk_create((u_char*)buf, len);
	msg = radius_message_parse(data);

	if (msg)
	{
		enumerator = msg->create_enumerator(msg);
		count = 0;
		while (count++ < 10000 &&
			   enumerator->enumerate(enumerator, &type, &attr_data));
		enumerator->destroy(enumerator);

		enumerator = msg->create_vendor_enumerator(msg);
		count = 0;
		while (count++ < 10000 &&
			   enumerator->enumerate(enumerator, &vendor, &type, &attr_data));
		enumerator->destroy(enumerator);

		hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
		signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_MD5_128);
		if (!hasher || !signer)
		{
			return 1;
		}
		msg->verify(msg, NULL, chunk_empty, hasher, signer);
		hasher->destroy(hasher);
		signer->destroy(signer);
		msg->destroy(msg);
	}
	return 0;
}
