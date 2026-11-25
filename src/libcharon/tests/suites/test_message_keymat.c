/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2026 Javier Blanco-Romero
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

#include "test_suite.h"

#include <encoding/message.h>

static aead_t *aead;
static keymat_t *keymat;

METHOD(keymat_t, get_version, ike_version_t,
	keymat_t *this)
{
	return IKEV2;
}

METHOD(keymat_t, get_aead, aead_t*,
	keymat_t *this, bool in)
{
	return aead;
}

START_SETUP(setup_keymat)
{
	chunk_t key;

	aead = lib->crypto->create_aead(lib->crypto, ENCR_AES_GCM_ICV16, 16, 4);
	ck_assert(aead);
	key = chunk_alloca(aead->get_key_size(aead));
	memset(key.ptr, 0x42, key.len);
	ck_assert(aead->set_key(aead, key));

	INIT(keymat,
		.get_version = _get_version,
		.create_ke = (void*)return_null,
		.create_nonce_gen = (void*)return_null,
		.get_aead = _get_aead,
	);
}
END_SETUP

START_TEARDOWN(teardown_keymat)
{
	aead->destroy(aead);
	free(keymat);
}
END_TEARDOWN

/**
 * The IntAuth data (RFC 9242) the sender and the receiver compute for the
 * same IKE_INTERMEDIATE message must be identical, also when its encrypted
 * payload contains no payloads.
 */
START_TEST(test_int_auth_data)
{
	ike_sa_id_t *id;
	message_t *sent, *received;
	packet_t *packet;
	chunk_t plain_sent, plain_received;

	id = ike_sa_id_create(IKEV2, 0x0011223344556677, 0x8899aabbccddeeff, _i % 2);
	sent = message_create(IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION);
	sent->set_exchange_type(sent, IKE_INTERMEDIATE);
	sent->set_message_id(sent, 1);
	sent->set_ike_sa_id(sent, id);
	sent->set_request(sent, _i % 2);
	sent->set_source(sent, host_create_from_string("192.0.2.1", 500));
	sent->set_destination(sent, host_create_from_string("192.0.2.2", 500));
	if (_i >= 2)
	{
		sent->add_notify(sent, FALSE, NO_ADDITIONAL_ADDRESSES, chunk_empty);
	}
	ck_assert_int_eq(SUCCESS, sent->generate(sent, keymat, &packet));
	ck_assert(sent->get_plain(sent, &plain_sent));

	received = message_create_from_packet(packet);
	ck_assert_int_eq(SUCCESS, received->parse_header(received));
	ck_assert_int_eq(SUCCESS, received->parse_body(received, keymat));
	ck_assert_int_eq(_i >= 2 ? PLV2_NOTIFY : PL_NONE,
					 received->get_first_payload_type(received));
	ck_assert(received->get_plain(received, &plain_received));

	ck_assert_chunk_eq(plain_sent, plain_received);

	chunk_free(&plain_sent);
	chunk_free(&plain_received);
	sent->destroy(sent);
	received->destroy(received);
	id->destroy(id);
}
END_TEST

Suite *message_keymat_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("message keymat");

	tc = tcase_create("IntAuth data");
	tcase_add_checked_fixture(tc, setup_keymat, teardown_keymat);
	tcase_add_loop_test(tc, test_int_auth_data, 0, 4);
	suite_add_tcase(s, tc);

	return s;
}
