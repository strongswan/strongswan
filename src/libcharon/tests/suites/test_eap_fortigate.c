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

/* The runtime helper is supported only on Linux. */
#ifdef __linux__

#include <daemon.h>
#include <credentials/sets/mem_cred.h>
#include <encoding/message.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/eap_payload.h>
#include <plugins/eap_gtc/eap_gtc.h>
#include <plugins/eap_identity/eap_identity.h>
#include <sa/ikev2/authenticators/eap_authenticator.h>
#include <sa/ikev2/keymat_v2.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#define CONNECTION "fortigate-test"
#define PRINCIPAL "eap-user"
#define MSK "01234567890123456789012345678901"
#define SIGNATURE "synthetic-auth"

/** Only MSCHAPv2 and keymat are mocked; Identity/GTC use their real plugins. */
static struct {
	ike_sa_t sa;
	keymat_v2_t keymat;
	eap_authenticator_t *auth;
	identification_t *my_id, *other_id;
	auth_cfg_t *local, *remote, *completed;
	mem_cred_t *creds;
	uint32_t conditions;
	eap_type_t mschap_type;
	pen_t mschap_vendor;
	status_t msk_status;
	bool empty_msk, missing_identity, verified;
	uint8_t ack_operation;
	unsigned int msk_queries, signatures;
	chunk_t signature_key;
	char *directory, *helper, *ready, *returned;
	sigset_t saved_mask;
	struct sigaction saved_pipe;
	bool signals_saved;
	eap_method_t *(*factory)(eap_manager_t*, eap_type_t, pen_t, eap_role_t,
							identification_t*, identification_t*);
} fixture;

typedef struct {
	eap_method_t public;
	uint8_t identifier;
} mock_mschap_t;

METHOD(eap_method_t, mschap_type, eap_type_t,
	mock_mschap_t *this, pen_t *vendor)
{
	*vendor = fixture.mschap_vendor;
	return fixture.mschap_type;
}

METHOD(eap_method_t, mschap_identifier, uint8_t,
	mock_mschap_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, mschap_set_identifier, void,
	mock_mschap_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, mschap_msk, status_t,
	mock_mschap_t *this, chunk_t *msk)
{
	fixture.msk_queries++;
	if (fixture.msk_status == SUCCESS)
	{
		*msk = fixture.empty_msk ? chunk_empty : chunk_from_str(MSK);
	}
	return fixture.msk_status;
}

METHOD(eap_method_t, mschap_process, status_t,
	mock_mschap_t *this, eap_payload_t *in, eap_payload_t **out)
{
	this->identifier = in->get_identifier(in);
	*out = eap_payload_create_data(chunk_from_chars(EAP_RESPONSE,
		this->identifier, 0, 6, EAP_MSCHAPV2, fixture.ack_operation));
	return NEED_MORE;
}

static eap_method_t *method_factory(eap_manager_t *manager, eap_type_t type,
		pen_t vendor, eap_role_t role, identification_t *server,
		identification_t *peer)
{
	mock_mschap_t *method;

	ck_assert_int_eq(vendor, 0);
	ck_assert_int_eq(role, EAP_PEER);
	switch (type)
	{
		case EAP_IDENTITY:
			if (fixture.missing_identity)
			{
				return NULL;
			}
			return &eap_identity_create_peer(server, peer)->eap_method;
		case EAP_GTC:
			return &eap_gtc_create_peer(server, peer)->eap_method_interface;
		default:
			ck_assert_int_eq(type, EAP_MSCHAPV2);
			INIT(method,
				.public = {
					.get_type = _mschap_type,
					.get_identifier = _mschap_identifier,
					.set_identifier = _mschap_set_identifier,
					.get_msk = _mschap_msk,
					.process = _mschap_process,
					.is_mutual = (void*)return_false,
					.destroy = (void*)free,
				},
			);
			return &method->public;
	}
}

METHOD(ike_sa_t, get_name, char*,
	ike_sa_t *this)
{
	return CONNECTION;
}

METHOD(ike_sa_t, get_unique_id, uint32_t,
	ike_sa_t *this)
{
	return 42;
}

METHOD(ike_sa_t, get_my_id, identification_t*,
	ike_sa_t *this)
{
	return fixture.my_id;
}

METHOD(ike_sa_t, get_other_id, identification_t*,
	ike_sa_t *this)
{
	return fixture.other_id;
}

METHOD(ike_sa_t, get_auth_cfg, auth_cfg_t*,
	ike_sa_t *this, bool local)
{
	return local ? fixture.local : fixture.remote;
}

METHOD(ike_sa_t, completed_auth, enumerator_t*,
	ike_sa_t *this, bool local)
{
	return local ? enumerator_create_empty() :
				   enumerator_create_single(fixture.completed, NULL);
}

METHOD(ike_sa_t, get_keymat, keymat_t*,
	ike_sa_t *this)
{
	return &fixture.keymat.keymat;
}

METHOD(ike_sa_t, set_condition, void,
	ike_sa_t *this, ike_condition_t condition, bool enabled)
{
	if (enabled)
	{
		fixture.conditions |= condition;
	}
	else
	{
		fixture.conditions &= ~condition;
	}
}

METHOD(ike_sa_t, has_condition, bool,
	ike_sa_t *this, ike_condition_t condition)
{
	return (fixture.conditions & condition) != 0;
}

METHOD(keymat_v2_t, get_psk_sig, bool,
	keymat_v2_t *this, bool verify, chunk_t init, chunk_t nonce,
	chunk_t int_auth, chunk_t secret, chunk_t ppk, identification_t *id,
	char reserved[3], chunk_t *signature)
{
	chunk_clear(&fixture.signature_key);
	fixture.signature_key = chunk_clone(secret);
	fixture.signatures++;
	fixture.verified = verify;
	*signature = chunk_clone(chunk_from_str(SIGNATURE));
	return TRUE;
}

static void select_connection(char *name)
{
	lib->settings->set_str(lib->settings, "%s.fortigate_mfa_connection",
						  name, lib->ns);
}

/** No installed config/credential files or sockets are used by these tests. */
START_SETUP(setup)
{
	char reserved[3] = {};

	memset(&fixture, 0, sizeof(fixture));
	fixture.sa = (ike_sa_t){
		.get_name = _get_name,
		.get_unique_id = _get_unique_id,
		.get_my_id = _get_my_id,
		.get_other_id = _get_other_id,
		.get_auth_cfg = _get_auth_cfg,
		.create_auth_cfg_enumerator = _completed_auth,
		.get_keymat = _get_keymat,
		.supports_extension = (void*)return_false,
		.has_condition = _has_condition,
		.set_condition = _set_condition,
	};
	fixture.keymat.get_psk_sig = _get_psk_sig;
	fixture.my_id = identification_create_from_string("ike-user");
	fixture.other_id = identification_create_from_string("gateway");
	fixture.local = auth_cfg_create();
	fixture.remote = auth_cfg_create();
	fixture.completed = auth_cfg_create();
	fixture.local->add(fixture.local, AUTH_RULE_EAP_TYPE, EAP_MSCHAPV2);
	fixture.local->add(fixture.local, AUTH_RULE_EAP_IDENTITY,
					  identification_create_from_string(PRINCIPAL));
	fixture.completed->add(fixture.completed, AUTH_RULE_AUTH_CLASS,
						  AUTH_CLASS_PSK);
	fixture.mschap_type = EAP_MSCHAPV2;
	fixture.msk_status = SUCCESS;
	fixture.ack_operation = 3;
	select_connection(CONNECTION);
	fixture.auth = eap_authenticator_create_builder(&fixture.sa,
			chunk_empty, chunk_empty, chunk_empty, chunk_empty, reserved);
	fixture.factory = charon->eap->create_instance;
	charon->eap->create_instance = method_factory;
	charon->bus->set_sa(charon->bus, &fixture.sa);
	fixture.creds = mem_cred_create();
	fixture.creds->add_shared(fixture.creds, shared_key_create(SHARED_EAP,
			chunk_clone(chunk_from_str("static-password"))),
			identification_create_from_string("%any"), NULL);
	lib->credmgr->add_set(lib->credmgr, &fixture.creds->set);
	fixture.directory = strdup("/tmp/strongswan-fortigate-XXXXXX");
	ck_assert(mkdtemp(fixture.directory));
	ck_assert(asprintf(&fixture.helper, "%s/helper", fixture.directory) > 0);
	ck_assert(asprintf(&fixture.ready, "%s.ready", fixture.helper) > 0);
	ck_assert(asprintf(&fixture.returned, "%s.returned", fixture.helper) > 0);
	lib->settings->set_str(lib->settings, "%s.plugins.eap-gtc.otp_helper",
						  fixture.helper, lib->ns);
}
END_SETUP


static void restore_signals()
{
	if (fixture.signals_saved)
	{
		sigaction(SIGPIPE, &fixture.saved_pipe, NULL);
		pthread_sigmask(SIG_SETMASK, &fixture.saved_mask, NULL);
		fixture.signals_saved = FALSE;
	}
}

START_TEARDOWN(teardown)
{
	restore_signals();
	fixture.auth->authenticator.destroy(&fixture.auth->authenticator);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
	charon->bus->set_sa(charon->bus, NULL);
	charon->eap->create_instance = fixture.factory;
	lib->credmgr->remove_set(lib->credmgr, &fixture.creds->set);
	fixture.creds->destroy(fixture.creds);
	fixture.local->destroy(fixture.local);
	fixture.remote->destroy(fixture.remote);
	fixture.completed->destroy(fixture.completed);
	fixture.my_id->destroy(fixture.my_id);
	fixture.other_id->destroy(fixture.other_id);
	chunk_clear(&fixture.signature_key);
	unlink(fixture.helper);
	unlink(fixture.ready);
	unlink(fixture.returned);
	ck_assert_int_eq(rmdir(fixture.directory), 0);
	free(fixture.directory);
	free(fixture.helper);
	free(fixture.ready);
	free(fixture.returned);
}
END_TEARDOWN

/** The fixed test tokens contain no shell quoting characters. */
static void write_helper(char *output, bool push, int status)
{
	FILE *file;

	file = fopen(fixture.helper, "w");
	ck_assert(file);
	fprintf(file, "#!/bin/sh\n"
			"[ \"$#\" -eq %d ] && [ \"$1\" = --ike-id ] && "
			"[ \"$2\" = 42 ] && [ \"$3\" = --connection ] && "
			"[ \"$4\" = " CONNECTION " ] || exit 99\n", push ? 5 : 4);
	if (push)
	{
		fputs("[ \"$5\" = --push-capable ] || exit 99\n", file);
	}
	fprintf(file, "printf '%%s' '%s'\nexit %d\n", output, status);
	ck_assert_int_eq(fclose(file), 0);
	ck_assert_int_eq(chmod(fixture.helper, 0700), 0);
}

static status_t receive(chunk_t data)
{
	message_t *message;
	status_t status;

	message = message_create(IKEV2, 0);
	message->set_exchange_type(message, IKE_AUTH);
	message->add_payload(message, (payload_t*)eap_payload_create_data(data));
	status = fixture.auth->authenticator.process(&fixture.auth->authenticator,
											message);
	message->destroy(message);
	return status;
}

static message_t *build()
{
	message_t *message;

	message = message_create(IKEV2, 0);
	message->set_exchange_type(message, IKE_AUTH);
	ck_assert_int_eq(fixture.auth->authenticator.build(
			&fixture.auth->authenticator, message), NEED_MORE);
	return message;
}

static void assert_eap(chunk_t expected)
{
	message_t *message;
	eap_payload_t *payload;

	message = build();
	payload = (eap_payload_t*)message->get_payload(message, PLV2_EAP);
	ck_assert(payload);
	ck_assert_chunk_eq(payload->get_data(payload), expected);
	ck_assert(!message->get_payload(message, PLV2_AUTH));
	ck_assert_int_eq(fixture.signatures, 0);
	message->destroy(message);
}

static void identity(uint8_t id)
{
	uint8_t response[] = {EAP_RESPONSE, id, 0, 5 + strlen(PRINCIPAL),
						 EAP_IDENTITY, 'e', 'a', 'p', '-', 'u', 's', 'e', 'r'};

	ck_assert_int_eq(receive(chunk_from_chars(EAP_REQUEST, id, 0, 5,
							 EAP_IDENTITY)), NEED_MORE);
	assert_eap(chunk_from_thing(response));
}

static void prime_mschap()
{
	identity(9);
	ck_assert_int_eq(receive(chunk_from_chars(EAP_REQUEST, 13, 0, 6,
							 EAP_MSCHAPV2, 3)), NEED_MORE);
	assert_eap(chunk_from_chars(EAP_RESPONSE, 13, 0, 6, EAP_MSCHAPV2,
							   fixture.ack_operation));
}

static chunk_t extended_success(int variant)
{
	static uint8_t data[6];
	uint8_t marker[] = {EAP_SUCCESS, 13, 0, variant ? 6 : 5, EAP_GTC,
						variant == 2};

	memcpy(data, marker, sizeof(data));
	return chunk_create(data, variant ? 6 : 5);
}

static void continuation(int variant)
{
	prime_mschap();
	ck_assert_int_eq(receive(extended_success(variant)), NEED_MORE);
	assert_eap(chunk_from_chars(EAP_RESPONSE, 13, 0, 6, EAP_MSCHAPV2, 3));
	ck_assert_int_eq(!!(fixture.conditions & COND_FORTIGATE_MFA_PUSH),
					 variant == 2);
	ck_assert_int_eq(fixture.msk_queries, 1);
}

static void gtc(uint8_t id, bool push)
{
	ck_assert_int_eq(receive(chunk_from_chars(EAP_REQUEST, id, 0, 6,
							 EAP_GTC, '?')), NEED_MORE);
	assert_eap(push ? chunk_from_chars(EAP_RESPONSE, id, 0, 5, EAP_GTC) :
			chunk_from_chars(EAP_RESPONSE, id, 0, 11, EAP_GTC,
							 '1', '2', '3', '4', '5', '6'));
}

static void assert_auth(bool fortigate)
{
	message_t *message;
	auth_payload_t *auth;

	message = build();
	ck_assert(message->get_payload(message, PLV2_AUTH));
	ck_assert(!message->get_payload(message, PLV2_EAP));
	if (fortigate)
	{
		ck_assert_int_eq(fixture.signature_key.len, 0);
	}
	else
	{
		ck_assert_chunk_eq(fixture.signature_key, chunk_from_str(MSK));
	}
	ck_assert(!fixture.verified);
	message->destroy(message);
	message = message_create(IKEV2, 0);
	auth = auth_payload_create();
	auth->set_auth_method(auth, AUTH_PSK);
	auth->set_data(auth, chunk_from_str(SIGNATURE));
	message->add_payload(message, (payload_t*)auth);
	ck_assert_int_eq(fixture.auth->authenticator.process(
			&fixture.auth->authenticator, message), SUCCESS);
	ck_assert(fixture.verified);
	ck_assert_int_eq(fixture.signature_key.len, fortigate ? 0 : strlen(MSK));
	message->destroy(message);
}

static struct {
	uint8_t data[7];
	size_t len;
	bool selected, current;
	status_t expected;
} payloads[] = {
	{{3, 13, 0, 4}, 4, FALSE, TRUE, SUCCESS},
	{{4, 13, 0, 4}, 4, TRUE, TRUE, SUCCESS},
	{{3, 13, 0, 5, 6}, 5, TRUE, TRUE, SUCCESS},
	{{3, 13, 0, 6, 6, 0}, 6, TRUE, TRUE, SUCCESS},
	{{3, 13, 0, 6, 6, 1}, 6, TRUE, TRUE, SUCCESS},
	{{3, 13, 0, 5, 6}, 5, FALSE, TRUE, SUCCESS},
	{{3, 13, 0, 6, 6, 1}, 6, TRUE, FALSE, SUCCESS},
	{{3, 13, 0, 6, 6, 2}, 6, TRUE, TRUE, FAILED},
	{{3, 13, 0, 6, 6, 0x80}, 6, TRUE, TRUE, FAILED},
	{{3, 13, 0, 7, 6, 1, 0}, 7, TRUE, TRUE, FAILED},
	{{4, 13, 0, 5, 6}, 5, TRUE, TRUE, FAILED},
	{{3, 13, 0, 5, 7}, 5, TRUE, TRUE, FAILED},
	{{3, 13, 0, 4, 6}, 5, TRUE, TRUE, FAILED},
	{{3, 13, 0}, 3, TRUE, TRUE, FAILED},
	{{0, 13, 0, 4}, 4, TRUE, TRUE, FAILED},
};

START_TEST(test_payload)
{
	eap_payload_t *payload;

	select_connection(payloads[_i].selected ? CONNECTION : "other");
	if (!payloads[_i].current)
	{
		charon->bus->set_sa(charon->bus, NULL);
	}
	payload = eap_payload_create_data(chunk_create(payloads[_i].data,
											payloads[_i].len));
	ck_assert_int_eq(payload->payload_interface.verify(
			&payload->payload_interface), payloads[_i].expected);
	payload->destroy(payload);
}
END_TEST


START_TEST(test_payload_without_daemon)
{
	daemon_t *saved;
	eap_payload_t *payload;
	status_t status;
	int variant;

	select_connection(NULL);
	charon->bus->set_sa(charon->bus, NULL);
	for (variant = 0; variant < 3; variant++)
	{
		payload = eap_payload_create_data(extended_success(variant));
		saved = charon;
		if (_i)
		{
			charon = NULL;
		}
		status = payload->payload_interface.verify(&payload->payload_interface);
		charon = saved;
		payload->destroy(payload);
		ck_assert_int_eq(status, SUCCESS);
	}
}
END_TEST

START_TEST(test_unselected_continuation)
{
	eap_payload_t *payload;
	chunk_t marker = extended_success(_i);

	select_connection(NULL);
	prime_mschap();
	payload = eap_payload_create_data(marker);
	ck_assert_int_eq(payload->payload_interface.verify(
			&payload->payload_interface), SUCCESS);
	payload->destroy(payload);
	ck_assert_int_eq(receive(marker), FAILED);
	ck_assert_int_eq(fixture.signatures, 0);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
}
END_TEST

START_TEST(test_standard_success)
{
	select_connection(_i ? CONNECTION : NULL);
	prime_mschap();
	ck_assert_int_eq(receive(chunk_from_chars(EAP_SUCCESS, 13, 0, 4)), NEED_MORE);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
	assert_auth(FALSE);
}
END_TEST

START_TEST(test_mfa_flow)
{
	bool push = _i == 2;
	uint8_t final_id = push ? 24 : 23;

	write_helper(push ? "PUSH\n" : "123456\n", push, 0);
	continuation(_i);
	fixture.local->add(fixture.local, AUTH_RULE_EAP_IDENTITY,
					  identification_create_from_string("changed-principal"));
	identity(21);
	identity(22);
	ck_assert_int_eq(fixture.msk_queries, 1);
	ck_assert_int_eq(!!(fixture.conditions & COND_FORTIGATE_MFA_PUSH), push);
	gtc(23, push);
	if (push)
	{
		ck_assert_int_eq(unlink(fixture.helper), 0);
		gtc(24, TRUE); /* A pending push must not invoke the helper again. */
	}
	ck_assert_int_eq(receive(chunk_from_chars(EAP_SUCCESS, final_id, 0, 4)),
					 NEED_MORE);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
	ck_assert_int_eq(fixture.msk_queries, 1);
	assert_auth(TRUE);
}
END_TEST

START_TEST(test_mfa_gates)
{
	chunk_t marker = extended_success(2);

	if (_i == 0)
	{
		select_connection("other");
	}
	if (_i == 9)
	{
		ck_assert(fixture.auth->authenticator.is_mutual(
									&fixture.auth->authenticator));
	}
	if (_i != 1)
	{
		if (_i == 6)
		{
			fixture.ack_operation = 2;
		}
		prime_mschap();
	}
	switch (_i)
	{
		case 2: fixture.msk_status = FAILED; break;
		case 3: fixture.empty_msk = TRUE; break;
		case 4: fixture.mschap_type = EAP_GTC; break;
		case 5: fixture.mschap_vendor = 123; break;
		case 7: marker.ptr[1] = 12; break;
		case 8:
			fixture.completed->add(fixture.completed, AUTH_RULE_AUTH_CLASS,
								  AUTH_CLASS_PUBKEY);
			break;
		case 10: marker.ptr[5] = 2; break;
	}
	ck_assert_int_eq(receive(marker), FAILED);
	ck_assert_int_eq(fixture.signatures, 0);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
}
END_TEST

static struct {
	uint8_t data[12];
	size_t len;
} stages[] = {
	{{3, 23, 0, 4}, 4},
	{{3, 21, 0, 4}, 4},
	{{3, 24, 0, 4}, 4},
	{{1, 21, 0, 6, 26, 3}, 6},
	{{1, 21, 0, 5, 1}, 5},
	{{1, 21, 0, 12, 254, 0, 0, 123, 0, 0, 0, 1}, 12},
	{{1, 21, 0, 12, 254, 0, 0, 0, 0, 0, 0, 1}, 12},
	{{3, 13, 0, 6, 6, 1}, 6},
	{{1, 21, 0, 5, 1}, 5},
	{{1, 21, 0, 5, 1}, 5},
	{{4, 23, 0, 4}, 4},
};

START_TEST(test_mfa_stage)
{
	write_helper("PUSH\n", TRUE, 0);
	continuation(2);
	switch (_i)
	{
		case 1: identity(21); break;
		case 2:
		case 4: gtc(23, TRUE); break;
		case 8: select_connection(NULL); break;
		case 9:
			gtc(23, TRUE);
			ck_assert_int_eq(receive(chunk_from_chars(EAP_SUCCESS, 23, 0, 4)),
							 NEED_MORE);
			break;
	}
	ck_assert_int_eq(receive(chunk_create(stages[_i].data, stages[_i].len)),
					 FAILED);
	ck_assert_int_eq(fixture.signatures, 0);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
}
END_TEST

static struct {
	char *output;
	bool push;
	int status;
	char *path;
	status_t expected;
} helpers[] = {
	{"1234", FALSE, 0, NULL, NEED_MORE},
	{"123456\n", FALSE, 0, NULL, NEED_MORE},
	{"12345678\r\n", TRUE, 0, NULL, NEED_MORE},
	{"PUSH\n", TRUE, 0, NULL, NEED_MORE},
	{"PUSH\n", FALSE, 0, NULL, FAILED},
	{"PUSH", TRUE, 0, NULL, FAILED},
	{"PUSH\r\n", TRUE, 0, NULL, FAILED},
	{"", TRUE, 0, NULL, FAILED},
	{"\n", FALSE, 0, NULL, FAILED},
	{"123", FALSE, 0, NULL, FAILED},
	{"12345x", FALSE, 0, NULL, FAILED},
	{"123456\n", FALSE, 7, NULL, FAILED},
	{"12345678901234567890123456789012", FALSE, 0, NULL, FAILED},
	{"123456\n", FALSE, 0, "relative-helper", FAILED},
	{"123456\n", FALSE, 0, "/nonexistent-fortigate-test-helper", FAILED},
};

START_TEST(test_gtc_helper)
{
	eap_method_t *method;
	eap_payload_t *in, *out = NULL;
	chunk_t expected, token;
	uint8_t header[] = {EAP_RESPONSE, 23, 0, 5, EAP_GTC};

	write_helper(helpers[_i].output, helpers[_i].push, helpers[_i].status);
	_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, helpers[_i].push);
	if (helpers[_i].path)
	{
		lib->settings->set_str(lib->settings, "%s.plugins.eap-gtc.otp_helper",
							  helpers[_i].path, lib->ns);
	}
	method = &eap_gtc_create_peer(fixture.other_id, fixture.my_id)
											 ->eap_method_interface;
	in = eap_payload_create_data(chunk_from_chars(EAP_REQUEST, 23, 0, 6,
												EAP_GTC, '?'));
	ck_assert_int_eq(method->process(method, in, &out), helpers[_i].expected);
	if (helpers[_i].expected == NEED_MORE)
	{
		ck_assert(out);
		token = _i == 3 ? chunk_empty : chunk_from_str(helpers[_i].output);
		while (token.len && (token.ptr[token.len - 1] == '\n' ||
							token.ptr[token.len - 1] == '\r'))
		{
			token.len--;
		}
		header[3] += token.len;
		expected = chunk_cat("cc", chunk_from_thing(header), token);
		ck_assert_chunk_eq(out->get_data(out), expected);
		chunk_free(&expected);
		out->destroy(out);
	}
	else
	{
		ck_assert(!out);
	}
	in->destroy(in);
	method->destroy(method);
	_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, FALSE);
}
END_TEST

START_TEST(test_gtc_scope)
{
	eap_method_t *method;
	eap_payload_t *in, *out = NULL;

	method = &eap_gtc_create_peer(fixture.other_id, fixture.my_id)
											 ->eap_method_interface;
	in = eap_payload_create_data(chunk_from_chars(EAP_REQUEST, 23, 0, 6,
												EAP_GTC, '?'));
	if (_i < 2)
	{
		select_connection(_i ? "other" : NULL);
		ck_assert_int_eq(method->process(method, in, &out), NEED_MORE);
		ck_assert_chunk_eq(out->get_data(out), chunk_from_chars(EAP_RESPONSE,
				23, 0, 20, EAP_GTC, 's', 't', 'a', 't', 'i', 'c', '-',
				'p', 'a', 's', 's', 'w', 'o', 'r', 'd'));
		out->destroy(out);
	}
	else
	{
		write_helper("PUSH\n", TRUE, 0);
		_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, TRUE);
		ck_assert_int_eq(method->process(method, in, &out), NEED_MORE);
		ck_assert_chunk_eq(out->get_data(out),
						   chunk_from_chars(EAP_RESPONSE, 23, 0, 5, EAP_GTC));
		out->destroy(out);
		out = NULL;
		_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, FALSE);
		ck_assert_int_eq(method->process(method, in, &out), FAILED);
		ck_assert(!out);
		select_connection(NULL);
		ck_assert_int_eq(method->process(method, in, &out), FAILED);
		ck_assert(!out); /* A selected method never falls back to a password. */
	}
	in->destroy(in);
	method->destroy(method);
}
END_TEST


/** Execute the probe through the real plugin under charon's signal state. */
START_TEST(test_gtc_helper_signals)
{
	eap_method_t *method;
	eap_payload_t *in, *out = NULL;
	struct sigaction ignore = { .sa_handler = SIG_IGN }, current_pipe;
	sigset_t blocked, before, after;
	struct timespec start, end;
	status_t status = FAILED;
	int blocked_result, ignored_result, mask_result, pipe_result, signal;
	FILE *file;
	int pid = 0, scanned, waited_errno;
	pid_t waited;
	int64_t elapsed;

	ck_assert_int_eq(symlink(TEST_HELPER_PROBE, fixture.helper), 0);
	_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, _i != 0);
	method = &eap_gtc_create_peer(fixture.other_id, fixture.my_id)
											 ->eap_method_interface;
	in = eap_payload_create_data(chunk_from_chars(EAP_REQUEST, 23, 0, 6,
												EAP_GTC, '?'));
	ck_assert_int_eq(sigemptyset(&ignore.sa_mask), 0);
	ck_assert_int_eq(sigemptyset(&blocked), 0);
	ck_assert_int_eq(sigaddset(&blocked, SIGINT), 0);
	ck_assert_int_eq(sigaddset(&blocked, SIGTERM), 0);
	ck_assert_int_eq(sigaddset(&blocked, SIGHUP), 0);
	ck_assert_int_eq(sigaction(SIGPIPE, NULL, &fixture.saved_pipe), 0);
	ck_assert_int_eq(pthread_sigmask(SIG_SETMASK, NULL,
								   &fixture.saved_mask), 0);
	ck_assert_int_eq(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	fixture.signals_saved = TRUE;
	blocked_result = pthread_sigmask(SIG_BLOCK, &blocked, NULL);
	ignored_result = sigaction(SIGPIPE, &ignore, NULL);
	pthread_sigmask(SIG_SETMASK, NULL, &before);
	if (!blocked_result && !ignored_result)
	{
		status = method->process(method, in, &out);
	}
	mask_result = pthread_sigmask(SIG_SETMASK, NULL, &after);
	pipe_result = sigaction(SIGPIPE, NULL, &current_pipe);
	restore_signals();
	ck_assert_int_eq(clock_gettime(CLOCK_MONOTONIC, &end), 0);
	ck_assert_int_eq(blocked_result, 0);
	ck_assert_int_eq(ignored_result, 0);
	ck_assert_int_eq(mask_result, 0);
	ck_assert_int_eq(pipe_result, 0);
	for (signal = 1; signal < NSIG; signal++)
	{
		ck_assert_int_eq(sigismember(&before, signal),
						 sigismember(&after, signal));
	}
	ck_assert(current_pipe.sa_handler == SIG_IGN);
	elapsed = (end.tv_sec - start.tv_sec) * 1000 +
			  (end.tv_nsec - start.tv_nsec) / 1000000;
	ck_assert_msg(elapsed < 2000, "helper took %lld ms", (long long)elapsed);
	if (_i)
	{
		ck_assert_int_eq(status, FAILED);
		ck_assert(!out);
		file = fopen(fixture.ready, "r");
		ck_assert(file);
		scanned = fscanf(file, "%d", &pid);
		fclose(file);
		ck_assert_int_eq(scanned, 1);
		ck_assert(pid > 1);
		ck_assert(access(fixture.returned, F_OK) < 0 && errno == ENOENT);
		waited = waitpid(pid, NULL, WNOHANG);
		waited_errno = errno;
		if (!waited)
		{
			/* Clean up even if a future plugin forgets to reap its helper. */
			kill(pid, SIGKILL);
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
			{
			}
		}
		ck_assert(waited < 0 && waited_errno == ECHILD);
	}
	else
	{
		ck_assert_int_eq(status, NEED_MORE);
		ck_assert(out);
		ck_assert_chunk_eq(out->get_data(out), chunk_from_chars(EAP_RESPONSE,
				23, 0, 11, EAP_GTC, '1', '2', '3', '4', '5', '6'));
		out->destroy(out);
	}
	in->destroy(in);
	method->destroy(method);
	_set_condition(&fixture.sa, COND_FORTIGATE_MFA_PUSH, FALSE);
}
END_TEST

START_TEST(test_identity_unavailable)
{
	continuation(2);
	fixture.missing_identity = TRUE;
	ck_assert_int_eq(receive(chunk_from_chars(EAP_REQUEST, 21, 0, 5,
							 EAP_IDENTITY)), FAILED);
	ck_assert_int_eq(fixture.msk_queries, 1);
	ck_assert(!(fixture.conditions & COND_FORTIGATE_MFA_PUSH));
	ck_assert_int_eq(fixture.signatures, 0);
}
END_TEST

Suite *eap_fortigate_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("eap-fortigate");
	tc = tcase_create("payload");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_payload, 0, countof(payloads));
	tcase_add_loop_test(tc, test_payload_without_daemon, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("authentication");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_standard_success, 0, 2);
	tcase_add_loop_test(tc, test_mfa_flow, 0, 3);
	tcase_add_loop_test(tc, test_mfa_gates, 0, 11);
	tcase_add_loop_test(tc, test_unselected_continuation, 0, 3);
	tcase_add_loop_test(tc, test_mfa_stage, 0, countof(stages));
	tcase_add_test(tc, test_identity_unavailable);
	suite_add_tcase(s, tc);

	tc = tcase_create("GTC helper");
	tcase_set_timeout(tc, 5);
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_gtc_helper, 0, countof(helpers));
	tcase_add_loop_test(tc, test_gtc_scope, 0, 3);
	tcase_add_loop_test(tc, test_gtc_helper_signals, 0, 2);
	suite_add_tcase(s, tc);
	return s;
}

#endif /* __linux__ */
