/*
 * Copyright (C) 2010 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include <glib.h>
#include <libosso.h>

#include "maemo_service.h"

#include <daemon.h>
#include <credentials/sets/mem_cred.h>
#include <processing/jobs/callback_job.h>

#define OSSO_STATUS_NAME	"status"
#define OSSO_STATUS_SERVICE	"org.strongswan."OSSO_STATUS_NAME
#define OSSO_STATUS_OBJECT	"/org/strongswan/"OSSO_STATUS_NAME
#define OSSO_STATUS_IFACE	"org.strongswan."OSSO_STATUS_NAME

#define OSSO_CHARON_NAME	"charon"
#define OSSO_CHARON_SERVICE	"org.strongswan."OSSO_CHARON_NAME
#define OSSO_CHARON_OBJECT	"/org/strongswan/"OSSO_CHARON_NAME
#define OSSO_CHARON_IFACE	"org.strongswan."OSSO_CHARON_NAME

typedef struct private_maemo_service_t private_maemo_service_t;

/**
 * private data of maemo service
 */
struct private_maemo_service_t {

	/**
	 * public interface
	 */
	maemo_service_t public;

	/**
	 * credentials
	 */
	mem_cred_t *creds;

	/**
	 * Glib main loop for a thread, handles DBUS calls
	 */
	GMainLoop *loop;

	/**
	 * Context for OSSO
	 */
	osso_context_t *context;

	/**
	 * Name of the current connection
	 */
	gchar *current;

};

static gint change_status(private_maemo_service_t *this, int status)
{
	osso_rpc_t retval;
	gint res;
	res = osso_rpc_run (this->context, OSSO_STATUS_SERVICE, OSSO_STATUS_OBJECT,
						OSSO_STATUS_IFACE, "StatusChanged", &retval,
						DBUS_TYPE_INT32, status,
						DBUS_TYPE_INVALID);
	return res;
}

static gboolean initiate_connection(private_maemo_service_t *this,
									GArray *arguments)
{
	gint i;
	gchar *hostname = NULL, *cacert = NULL, *username = NULL, *password = NULL;
	identification_t *gateway = NULL, *user = NULL;
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;
	auth_cfg_t *auth;
	certificate_t *cert;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = 10800, /* 3h */
			.rekey = 10200, /* 2h50min */
			.jitter = 300 /* 5min */
		}
	};

	if (this->current)
	{
		DBG1(DBG_CFG, "currently connected to '%s', disconnect first",
			 this->current);
		return FALSE;
	}

	if (arguments->len != 5)
	{
		DBG1(DBG_CFG, "wrong number of arguments: %d", arguments->len);
		return FALSE;
	}

	for (i = 0; i < arguments->len; i++)
	{
		osso_rpc_t *arg = &g_array_index(arguments, osso_rpc_t, i);
		if (arg->type != DBUS_TYPE_STRING)
		{
			DBG1(DBG_CFG, "invalid argument [%d]: %d", i, arg->type);
			this->current = (g_free(this->current), NULL);
			return FALSE;
		}
		switch (i)
		{
			case 0: /* name */
				this->current = g_strdup(arg->value.s);
				break;
			case 1: /* hostname */
				hostname = arg->value.s;
				break;
			case 2: /* CA certificate path */
				cacert = arg->value.s;
				break;
			case 3: /* username */
				username = arg->value.s;
				break;
			case 4: /* password */
				password = arg->value.s;
				break;
		}
	}

	DBG1(DBG_CFG, "received initiate for connection '%s'", this->current);

	this->creds->clear(this->creds);

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, cacert, BUILD_END);
	if (cert)
	{
		this->creds->add_cert(this->creds, TRUE, cert);
	}
	else
	{
		DBG1(DBG_CFG, "failed to load CA certificate");
	}
	/* if this is a server cert we could use the cert subject as id */

	gateway = identification_create_from_string(hostname);
	DBG1(DBG_CFG, "using CA certificate, gateway identitiy '%Y'", gateway);

	{
		shared_key_t *shared_key;
		chunk_t secret = chunk_create(password, strlen(password));
		user = identification_create_from_string(username);
		shared_key = shared_key_create(SHARED_EAP, chunk_clone(secret));
		this->creds->add_shared(this->creds, shared_key, user->clone(user),
								NULL);
	}

	ike_cfg = ike_cfg_create(TRUE, FALSE, "0.0.0.0", IKEV2_UDP_PORT,
							 hostname, IKEV2_UDP_PORT);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));

	peer_cfg = peer_cfg_create(this->current, 2, ike_cfg, CERT_SEND_IF_ASKED,
							   UNIQUE_REPLACE, 1, /* keyingtries */
							   36000, 0, /* rekey 10h, reauth none */
							   600, 600, /* jitter, over 10min */
							   TRUE, 0, /* mobike, DPD */
							   host_create_from_string("0.0.0.0", 0) /* virt */,
							   NULL, FALSE, NULL, NULL); /* pool, mediation */

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);
	auth->add(auth, AUTH_RULE_IDENTITY, user);
	peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);
	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
	auth->add(auth, AUTH_RULE_IDENTITY, gateway);
	peer_cfg->add_auth_cfg(peer_cfg, auth, FALSE);

	child_cfg = child_cfg_create(this->current, &lifetime, NULL /* updown */,
								 TRUE, MODE_TUNNEL, ACTION_NONE, ACTION_NONE,
								 FALSE, 0, 0, NULL, NULL);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_from_string(0, TS_IPV4_ADDR_RANGE, "0.0.0.0",
											 0, "255.255.255.255", 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	/* get an additional reference because initiate consumes one */
	child_cfg->get_ref(child_cfg);

	if (charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 controller_cb_empty, NULL) != SUCCESS)
	{
		DBG1(DBG_CFG, "failed to initiate tunnel");
		this->current = (g_free(this->current), NULL);
		return FALSE;
	}
	return TRUE;
}

static void disconnect(private_maemo_service_t *this)
{
	ike_sa_t *ike_sa;
	u_int id;

	if (!this->current)
	{
		return;
	}

	ike_sa = charon->ike_sa_manager->checkout_by_name(charon->ike_sa_manager,
													  this->current, FALSE);
	if (ike_sa)
	{
		id = ike_sa->get_unique_id(ike_sa);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		charon->controller->terminate_ike(charon->controller, id,
										  NULL, NULL);
	}
	this->current = (g_free(this->current), NULL);
}

/**
 * Callback for libosso dbus wrapper
 */
static gint dbus_req_handler(const gchar *interface, const gchar *method,
							 GArray *arguments, private_maemo_service_t *this,
							 osso_rpc_t *retval)
{
	if (streq(method, "Start"))
	{	/* void start (void), dummy function to start charon as root */
		return OSSO_OK;
	}
	else if (streq(method, "Connect"))
	{	/* bool connect (name, host, cert, user, pass) */
		retval->value.b = initiate_connection(this, arguments);
		retval->type = DBUS_TYPE_BOOLEAN;
	}
	else if (streq(method, "Disconnect"))
	{	/* void disconnect (void) */
		disconnect(this);
	}
	else
	{
		return OSSO_ERROR;
	}
	return OSSO_OK;
}

/**
 * Main loop to handle D-BUS messages.
 */
static job_requeue_t run(private_maemo_service_t *this)
{
	this->loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(this->loop);
	return JOB_REQUEUE_NONE;
}

METHOD(maemo_service_t, destroy, void,
	   private_maemo_service_t *this)
{
	if (this->loop)
	{
		if (g_main_loop_is_running(this->loop))
		{
			g_main_loop_quit(this->loop);
		}
		g_main_loop_unref(this->loop);
	}
	if (this->context)
	{
		osso_deinitialize(this->context);
	}
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

/*
 * See header
 */
maemo_service_t *maemo_service_create()
{
	osso_return_t result;
	private_maemo_service_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.creds = mem_cred_create(),
	);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	this->context = osso_initialize(OSSO_CHARON_SERVICE, "0.0.1", TRUE, NULL);
	if (!this->context)
	{
		DBG1(DBG_CFG, "failed to initialize OSSO context");
		destroy(this);
		return NULL;
	}

	result = osso_rpc_set_cb_f(this->context,
							   OSSO_CHARON_SERVICE,
							   OSSO_CHARON_OBJECT,
							   OSSO_CHARON_IFACE,
							   (osso_rpc_cb_f*)dbus_req_handler,
							   this);
	if (result != OSSO_OK)
	{
		DBG1(DBG_CFG, "failed to set D-BUS callback (%d)", result);
		destroy(this);
		return NULL;
	}

	this->loop = NULL;
	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)run, this, NULL, NULL));

	return &this->public;
}

