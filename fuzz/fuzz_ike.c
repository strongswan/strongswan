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
#include <encoding/message.h>
#include <sa/keymat.h>
#include <crypto/aead.h>
#include <crypto/iv/iv_gen.h>

/* Identity-en/decrypt AEAD: lets parse_body() walk past SK framing. */
typedef struct {
	aead_t public;
} fuzz_aead_t;

static bool aead_encrypt(aead_t *this, chunk_t plain, chunk_t assoc, chunk_t iv,
						 chunk_t *encrypted)
{
	/* NULL means inline encryption per aead_t contract. */
	if (encrypted)
	{
		*encrypted = chunk_clone(plain);
	}
	return TRUE;
}

static bool aead_decrypt(aead_t *this, chunk_t encrypted, chunk_t assoc,
						 chunk_t iv, chunk_t *plain)
{
	/* NULL means inline decryption; identity-decrypt is a no-op then. */
	if (plain)
	{
		*plain = chunk_clone(encrypted);
	}
	return TRUE;
}

static size_t aead_get_block_size(aead_t *this) { return 1; }
static size_t aead_get_icv_size(aead_t *this) { return 0; }
static size_t aead_get_iv_size(aead_t *this) { return 0; }
static iv_gen_t *aead_get_iv_gen(aead_t *this) { return NULL; }
static size_t aead_get_key_size(aead_t *this) { return 0; }
static bool aead_set_key(aead_t *this, chunk_t key) { return TRUE; }
static void aead_destroy(aead_t *this) { free(this); }

static aead_t *fuzz_aead_create()
{
	fuzz_aead_t *aead;
	INIT(aead,
		.public = {
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.get_block_size = aead_get_block_size,
			.get_icv_size = aead_get_icv_size,
			.get_iv_size = aead_get_iv_size,
			.get_iv_gen = aead_get_iv_gen,
			.get_key_size = aead_get_key_size,
			.set_key = aead_set_key,
			.destroy = aead_destroy,
		},
	);
	return &aead->public;
}

/* Stub keymat returning the fuzz AEAD for inbound and outbound. */
typedef struct {
	keymat_t public;
	aead_t *aead;
} fuzz_keymat_t;

static ike_version_t keymat_get_version(keymat_t *this) { return IKEV2; }

static key_exchange_t *keymat_create_ke(keymat_t *this,
										key_exchange_method_t method)
{
	return NULL;
}

static nonce_gen_t *keymat_create_nonce_gen(keymat_t *this) { return NULL; }

static aead_t *keymat_get_aead(keymat_t *this, bool in)
{
	return ((fuzz_keymat_t*)this)->aead;
}

static void keymat_destroy(keymat_t *this)
{
	fuzz_keymat_t *km = (fuzz_keymat_t*)this;
	km->aead->destroy(km->aead);
	free(km);
}

static keymat_t *fuzz_keymat_create()
{
	fuzz_keymat_t *km;
	INIT(km,
		.public = {
			.get_version = keymat_get_version,
			.create_ke = keymat_create_ke,
			.create_nonce_gen = keymat_create_nonce_gen,
			.get_aead = keymat_get_aead,
			.destroy = keymat_destroy,
		},
		.aead = fuzz_aead_create(),
	);
	return &km->public;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ike");
	libcharon_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	message_t *message;
	packet_t *packet;
	keymat_t *keymat;

	/* Minimum IKE header size for meaningful header parsing. */
	if (len < 28)
	{
		return 0;
	}

	packet = packet_create_from_data(host_create_from_string("192.0.2.1", 500),
									 host_create_from_string("192.0.2.2", 500),
									 chunk_clone(chunk_create((u_char*)buf, len)));
	if (!packet)
	{
		return 0;
	}

	/* Stub keymat with identity-AEAD lets parse_body() decrypt SK payloads */
	/* and reach the inner IKEv2 payload parsers (ID, AUTH, SA, TS, CP, ...). */
	keymat = fuzz_keymat_create();
	message = message_create_from_packet(packet);
	if (message)
	{
		if (message->parse_header(message) == SUCCESS)
		{
			message->parse_body(message, keymat);
		}
		message->destroy(message);
	}
	keymat->destroy(keymat);
	return 0;
}
