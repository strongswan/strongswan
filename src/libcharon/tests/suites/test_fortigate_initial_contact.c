/*
 * Copyright (C) 2026 Kristóf Havasi
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

#ifdef __linux__

#include <tests/utils/exchange_test_helper.h>
#include <encoding/payloads/notify_payload.h>

static struct {
	listener_t listener;
	ike_sa_t *initiator, *responder;
	char *directory, *metadata;
	unsigned int messages, initial_contact, endpoint, eap_only;
} fixture;

static bool capture_auth(listener_t *listener, ike_sa_t *sa,
						 message_t *message, bool incoming, bool plain)
{
	enumerator_t *enumerator;
	payload_t *payload;
	notify_payload_t *notify;

	if (plain && !incoming && sa == fixture.initiator &&
		message->get_exchange_type(message) == IKE_AUTH &&
		message->get_request(message))
	{
		fixture.messages++;
		enumerator = message->create_payload_enumerator(message);
		while (enumerator->enumerate(enumerator, &payload))
		{
			if (payload->get_type(payload) != PLV2_NOTIFY)
			{
				continue;
			}
			notify = (notify_payload_t*)payload;
			switch ((int)notify->get_notify_type(notify))
			{
				case INITIAL_CONTACT: fixture.initial_contact++; break;
				case EAP_ONLY_AUTHENTICATION: fixture.eap_only++; break;
				case 0xF100: fixture.endpoint++; break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return TRUE;
}

START_SETUP(setup)
{
	FILE *file;

	memset(&fixture, 0, sizeof(fixture));
	fixture.listener.message = capture_auth;
	fixture.directory = strdup("/tmp/strongswan-fortigate-XXXXXX");
	ck_assert(mkdtemp(fixture.directory));
	ck_assert(asprintf(&fixture.metadata, "%s/fct", fixture.directory) > 0);
	file = fopen(fixture.metadata, "w");
	ck_assert(file);
	ck_assert(fputs("synthetic-endpoint", file) >= 0);
	ck_assert_int_eq(fclose(file), 0);
	lib->settings->set_str(lib->settings, "%s.fortigate_fct_file",
						  fixture.metadata, lib->ns);
	lib->settings->set_str(lib->settings, "%s.fortigate_mfa_connection",
						  NULL, lib->ns);
}
END_SETUP

START_TEARDOWN(teardown)
{
	if (fixture.initiator)
	{
		call_ikesa(fixture.initiator, destroy);
	}
	if (fixture.responder)
	{
		call_ikesa(fixture.responder, destroy);
	}
	unlink(fixture.metadata);
	ck_assert_int_eq(rmdir(fixture.directory), 0);
	free(fixture.metadata);
	free(fixture.directory);
}
END_TEARDOWN

/** Replace the config through public APIs to exercise UNIQUE_NEVER. */
static void disable_uniqueness(ike_sa_t *sa)
{
	peer_cfg_t *old, *peer;
	peer_cfg_create_t create = {
		.unique = UNIQUE_NEVER,
		.cert_policy = CERT_SEND_IF_ASKED,
		.keyingtries = 1,
	};
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	child_cfg_t *child;
	int local;

	old = sa->get_peer_cfg(sa);
	peer = peer_cfg_create("init", old->get_ike_cfg(old)->get_ref(
										 old->get_ike_cfg(old)), &create);
	for (local = 0; local < 2; local++)
	{
		enumerator = old->create_auth_cfg_enumerator(old, local);
		while (enumerator->enumerate(enumerator, &auth))
		{
			peer->add_auth_cfg(peer, auth->clone(auth), local);
		}
		enumerator->destroy(enumerator);
	}
	enumerator = old->create_child_cfg_enumerator(old);
	while (enumerator->enumerate(enumerator, &child))
	{
		peer->add_child_cfg(peer, child->get_ref(child));
	}
	enumerator->destroy(enumerator);
	sa->set_peer_cfg(sa, peer);
	peer->destroy(peer);
}

START_TEST(test_initial_contact)
{
	exchange_test_sa_conf_t conf = { .initiator.eap = TRUE };
	ike_sa_t *old_i, *old_r, *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child;
	peer_cfg_t *peer;
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	identification_t *me, *other;
	bool existing = _i == 2 || _i == 3;
	bool wildcard = _i == 0 || _i == 3;

	if (existing)
	{
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &old_i, &old_r, NULL);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, old_i);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, old_r);
		me = identification_create_from_string("init");
		other = identification_create_from_string("resp");
		ck_assert(charon->ike_sa_manager->has_contact(charon->ike_sa_manager,
													me, other, AF_INET));
		me->destroy(me);
		other->destroy(other);
	}
	child = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
											   &conf);
	fixture.initiator = a;
	fixture.responder = b;
	if (_i == 4)
	{
		disable_uniqueness(a);
	}
	if (wildcard)
	{
		peer = a->get_peer_cfg(a);
		enumerator = peer->create_auth_cfg_enumerator(peer, FALSE);
		ck_assert(enumerator->enumerate(enumerator, &auth));
		auth->add(auth, AUTH_RULE_IDENTITY,
				  identification_create_from_string("%any"));
		enumerator->destroy(enumerator);
	}
	lib->settings->set_str(lib->settings, "%s.fortigate_mfa_connection",
						  _i == 5 ? NULL : "init", lib->ns);
	exchange_test_helper->add_listener(exchange_test_helper, &fixture.listener);
	id_a = a->get_id(a);
	id_b = b->get_id(b);
	call_ikesa(a, initiate, child, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert_int_eq(fixture.messages, 1);
	ck_assert_int_eq(fixture.initial_contact, _i == 1 || _i == 5 ? 1 : 0);
	ck_assert_int_eq(fixture.endpoint, _i == 5 ? 0 : 1);
	ck_assert_int_eq(fixture.eap_only, _i == 5 ? 1 : 0);
}
END_TEST

Suite *fortigate_initial_contact_suite_create()
{
	Suite *suite;
	TCase *tc;

	suite = suite_create("fortigate-initial-contact");
	tc = tcase_create("first IKE_AUTH");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_initial_contact, 0, 6);
	suite_add_tcase(suite, tc);
	return suite;
}

#endif /* __linux__ */
