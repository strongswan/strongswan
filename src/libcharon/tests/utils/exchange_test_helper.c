/*
 * Copyright (C) 2016 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "exchange_test_helper.h"
#include "mock_ipsec.h"

#include <credentials/sets/mem_cred.h>

typedef struct private_exchange_test_helper_t private_exchange_test_helper_t;

/**
 * Private data
 */
struct private_exchange_test_helper_t {

	/**
	 * Public interface
	 */
	exchange_test_helper_t public;

	/**
	 * Config backend
	 */
	backend_t backend;

	/**
	 * Credentials
	 */
	mem_cred_t *creds;
};

/*
 * Described in header
 */
exchange_test_helper_t *exchange_test_helper;

static ike_cfg_t *create_ike_cfg()
{
	ike_cfg_t *ike_cfg;

	ike_cfg = ike_cfg_create(IKEV2, TRUE, FALSE, "127.0.0.1", IKEV2_UDP_PORT,
							 "127.0.0.1", IKEV2_UDP_PORT, FRAGMENTATION_NO, 0);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	return ike_cfg;
}

static child_cfg_t *create_child_cfg(bool initiator)
{
	child_cfg_t *child_cfg;
	child_cfg_create_t child = {
		.mode = MODE_TUNNEL,
	};

	child_cfg = child_cfg_create(initiator ? "init" : "resp", &child);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	child_cfg->add_proposal(child_cfg, proposal_create_default_aead(PROTO_ESP));
	child_cfg->add_traffic_selector(child_cfg, TRUE,
								traffic_selector_create_dynamic(0, 0, 65535));
	child_cfg->add_traffic_selector(child_cfg, FALSE,
								traffic_selector_create_dynamic(0, 0, 65535));
	return child_cfg;
}

static void add_auth_cfg(peer_cfg_t *peer_cfg, bool initiator, bool local)
{
	auth_cfg_t *auth;
	char *id = "init";

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	if (initiator ^ local)
	{
		id = "resp";
	}
	auth->add(auth, AUTH_RULE_IDENTITY, identification_create_from_string(id));
	peer_cfg->add_auth_cfg(peer_cfg, auth, local);
}

static peer_cfg_t *create_peer_cfg(bool initiator)
{
	peer_cfg_t *peer_cfg;
	peer_cfg_create_t peer = {
		.cert_policy = CERT_SEND_IF_ASKED,
		.unique = UNIQUE_REPLACE,
		.keyingtries = 1,
	};

	peer_cfg = peer_cfg_create(initiator ? "init" : "resp", create_ike_cfg(),
							   &peer);
	add_auth_cfg(peer_cfg, initiator, TRUE);
	add_auth_cfg(peer_cfg, initiator, FALSE);
	peer_cfg->add_child_cfg(peer_cfg, create_child_cfg(initiator));
	return peer_cfg;
}

METHOD(backend_t, create_ike_cfg_enumerator, enumerator_t*,
	backend_t *this, host_t *me, host_t *other)
{
	ike_cfg_t *ike_cfg = create_ike_cfg();
	return enumerator_create_single(ike_cfg, (void*)ike_cfg->destroy);
}

METHOD(backend_t, create_peer_cfg_enumerator, enumerator_t*,
	backend_t *this, identification_t *me, identification_t *other)
{
	peer_cfg_t *peer_cfg = create_peer_cfg(FALSE);
	return enumerator_create_single(peer_cfg, (void*)peer_cfg->destroy);
}

METHOD(exchange_test_helper_t, process_message, void,
	private_exchange_test_helper_t *this, ike_sa_t *ike_sa, message_t *message)
{
	if (!message)
	{
		message = this->public.sender->dequeue(this->public.sender);
	}
	charon->bus->set_sa(charon->bus, ike_sa);
	ike_sa->process_message(ike_sa, message);
	charon->bus->set_sa(charon->bus, NULL);
	message->destroy(message);
}

METHOD(exchange_test_helper_t, establish_sa, void,
	private_exchange_test_helper_t *this, ike_sa_t **init, ike_sa_t **resp)
{
	ike_sa_id_t *id_i, *id_r;
	ike_sa_t *sa_i, *sa_r;
	peer_cfg_t *peer_cfg;

	sa_i = *init = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager,
														IKEV2, TRUE);
	id_i = sa_i->get_id(sa_i);

	sa_r = *resp = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager,
														IKEV2, FALSE);
	id_r = sa_r->get_id(sa_r);

	peer_cfg = create_peer_cfg(TRUE);
	sa_i->set_peer_cfg(sa_i, peer_cfg);
	peer_cfg->destroy(peer_cfg);
	call_ikesa(sa_i, initiate, create_child_cfg(TRUE), 0, NULL, NULL);
	/* IKE_SA_INIT --> */
	id_r->set_initiator_spi(id_r, id_i->get_initiator_spi(id_i));
	process_message(this, sa_r, NULL);
	/* <-- IKE_SA_INIT */
	id_i->set_responder_spi(id_i, id_r->get_responder_spi(id_r));
	process_message(this, sa_i, NULL);
	/* IKE_AUTH --> */
	process_message(this, sa_r, NULL);
	/* <-- IKE_AUTH */
	process_message(this, sa_i, NULL);
}

/**
 * Enable logging in charon as requested
 */
static void initialize_logging()
{
	int level = LEVEL_SILENT;
	char *verbosity;

	verbosity = getenv("TESTS_VERBOSITY");
	if (verbosity)
	{
		level = atoi(verbosity);
	}
	lib->settings->set_int(lib->settings, "%s.filelog.stderr.default",
			lib->settings->get_int(lib->settings, "%s.filelog.stderr.default",
								   level, lib->ns), lib->ns);
	lib->settings->set_bool(lib->settings, "%s.filelog.stderr.ike_name", TRUE,
							lib->ns);
	charon->load_loggers(charon, NULL, TRUE);
}

/*
 * Described in header
 */
void exchange_test_helper_init(char *plugins)
{
	private_exchange_test_helper_t *this;

	INIT(this,
		.public = {
			.sender = mock_sender_create(),
			.establish_sa = _establish_sa,
			.process_message = _process_message,
		},
		.backend = {
			.create_ike_cfg_enumerator = _create_ike_cfg_enumerator,
			.create_peer_cfg_enumerator = _create_peer_cfg_enumerator,
			.get_peer_cfg_by_name = (void*)return_null,
		},
		.creds = mem_cred_create(),
	);

	initialize_logging();
	/* the libcharon unit tests only load the libstrongswan plugins, unless
	 * TESTS_PLUGINS is defined */
	charon->initialize(charon, plugins);
	lib->plugins->status(lib->plugins, LEVEL_CTRL);
	/* the original sender is not initialized because there is no socket */
	charon->sender = (sender_t*)this->public.sender;
	/* and there is no kernel plugin loaded
	 * TODO: we'd have more control if we'd implement kernel_interface_t */
	charon->kernel->add_ipsec_interface(charon->kernel, mock_ipsec_create);

	charon->backends->add_backend(charon->backends, &this->backend);
	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	this->creds->add_shared(this->creds,
			shared_key_create(SHARED_IKE, chunk_clone(chunk_from_str("test"))),
			identification_create_from_string("%any"), NULL);

	exchange_test_helper = &this->public;
}

/*
 * Described in header
 */
void exchange_test_helper_deinit()
{
	private_exchange_test_helper_t *this;

	this = (private_exchange_test_helper_t*)exchange_test_helper;

	charon->backends->remove_backend(charon->backends, &this->backend);
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	/* can't let charon do it as it happens too late */
	charon->sender->destroy(charon->sender);
	charon->sender = NULL;
	free(this);
}
