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

static chunk_t shared_secret = chunk_from_chars(
	't','e','s','t','i','n','g','1','2','3');

static uint8_t known_req_auth[16] = {
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
};

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
	chunk_t data, attr_data, crypt_in, crypt_out;
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

		/* Known-secret pass: sign() writes a valid Message-Authenticator and */
		/* exercises the Response-Authenticator path; verify() then succeeds. */
		if (signer->set_key(signer, shared_secret))
		{
			msg->sign(msg, known_req_auth, shared_secret, hasher, signer, NULL,
					  TRUE);
			msg->verify(msg, known_req_auth, shared_secret, hasher, signer);

			/* Exercise RFC 2865 5.2 / RFC 2548 password en/decryption. */
			if (len >= 16)
			{
				crypt_in = chunk_create((u_char*)buf, 16);
				crypt_out = chunk_alloc(16);
				msg->crypt(msg, chunk_empty, crypt_in, crypt_out,
						   shared_secret, hasher);
				chunk_free(&crypt_out);
			}
		}
		hasher->destroy(hasher);
		signer->destroy(signer);
		msg->destroy(msg);
	}
	return 0;
}
