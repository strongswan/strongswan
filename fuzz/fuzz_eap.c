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
#include <utils/debug.h>
#include <utils/identification.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/keys/shared_key.h>
#include <encoding/payloads/eap_payload.h>
#include <sa/eap/eap_method.h>
#include <plugins/eap_md5/eap_md5.h>
#include <plugins/eap_mschapv2/eap_mschapv2.h>
#include <plugins/eap_aka/eap_aka_peer.h>
#include <plugins/eap_aka/eap_aka_server.h>
#include <plugins/eap_sim/eap_sim_peer.h>
#include <plugins/eap_sim/eap_sim_server.h>
#include <simaka_manager.h>

/* Static EAP identities reused across iterations */
static identification_t *server_id;
static identification_t *peer_id;

/* Persistent credential set holding shared secrets keyed to the identity pair. */
static mem_cred_t *creds;
static chunk_t eap_secret    = chunk_from_chars('f','u','z','z','p','w');
static chunk_t mschap_nthash = chunk_from_chars(
	0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
	0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	linked_list_t *owners;

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_eap");
	libcharon_init();

	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	server_id = identification_create_from_string("server.strongswan.org");
	peer_id   = identification_create_from_string("oss-fuzz@strongswan.org");

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	/* Register a shared EAP secret for (server, peer). */
	owners = linked_list_create();
	owners->insert_last(owners, server_id->clone(server_id));
	owners->insert_last(owners, peer_id->clone(peer_id));
	creds->add_shared_list(creds,
		shared_key_create(SHARED_EAP, chunk_clone(eap_secret)), owners);

	/* Register an NT-hash for MSCHAPv2 server-side. */
	owners = linked_list_create();
	owners->insert_last(owners, server_id->clone(server_id));
	owners->insert_last(owners, peer_id->clone(peer_id));
	creds->add_shared_list(creds,
		shared_key_create(SHARED_NT_HASH, chunk_clone(mschap_nthash)),
		owners);

	/* SIM-manager + AKA-manager registrations */
	lib->set(lib, "sim-manager", simaka_manager_create());
	lib->set(lib, "aka-manager", simaka_manager_create());

	return 0;
}

/* Run a single EAP method against the supplied payload */
static void exercise_method(eap_method_t *peer, eap_method_t *server,
							eap_payload_t *payload)
{
	eap_payload_t *out;
	pen_t vendor;

	if (peer)
	{
		out = NULL;
		peer->process(peer, payload, &out);
		DESTROY_IF(out);
		peer->get_type(peer, &vendor);
		peer->destroy(peer);
	}
	if (server)
	{
		out = NULL;
		server->initiate(server, &out);
		DESTROY_IF(out);

		out = NULL;
		server->process(server, payload, &out);
		DESTROY_IF(out);
		server->get_type(server, &vendor);
		server->destroy(server);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	eap_payload_t *payload;
	chunk_t chunk;
	pen_t vendor;
	uint32_t code, id;

	if (len < 1)
	{
		return 0;
	}

	chunk = chunk_create((u_char*)buf, len);

	/* eap_payload_t */
	payload = eap_payload_create_data(chunk);
	if (!payload)
	{
		return 0;
	}

	code   = payload->get_code(payload);
	id     = payload->get_identifier(payload);
	(void)payload->get_type(payload, &vendor);
	(void)payload->get_data(payload);
	(void)code; (void)id;

	{
		enumerator_t *types;
		eap_type_t t;

		types = payload->get_types(payload);
		if (types)
		{
			while (types->enumerate(types, &t, &vendor))
			{
				/* no-op iteration */
			}
			types->destroy(types);
		}
	}

	/* EAP-MD5 */
	exercise_method(
		(eap_method_t*)eap_md5_create_peer(server_id, peer_id),
		(eap_method_t*)eap_md5_create_server(server_id, peer_id),
		payload);

	/* EAP-MSCHAPv2 */
	exercise_method(
		(eap_method_t*)eap_mschapv2_create_peer(server_id, peer_id),
		(eap_method_t*)eap_mschapv2_create_server(server_id, peer_id),
		payload);

	/* EAP-AKA */
	exercise_method(
		(eap_method_t*)eap_aka_peer_create(server_id, peer_id),
		(eap_method_t*)eap_aka_server_create(server_id, peer_id),
		payload);

	/* EAP-SIM */
	exercise_method(
		(eap_method_t*)eap_sim_peer_create(server_id, peer_id),
		(eap_method_t*)eap_sim_server_create(server_id, peer_id),
		payload);

	payload->destroy(payload);
	return 0;
}
