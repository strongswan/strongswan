/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "ha_sync_socket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <daemon.h>
#include <utils/host.h>
#include <processing/jobs/callback_job.h>

typedef struct private_ha_sync_socket_t private_ha_sync_socket_t;
typedef struct ha_backend_t ha_backend_t;
typedef struct ha_creds_t ha_creds_t;

/**
 * Serves credentials for the HA sync SA
 */
struct ha_creds_t {

	/**
	 * Implements credential_set_t
	 */
	credential_set_t public;

	/**
	 * own identity
	 */
	identification_t *local;

	/**
	 * peer identity
	 */
	identification_t *remote;

	/**
	 * Shared key to serve
	 */
	shared_key_t *key;
};

/**
 * Serves configurations for the HA sync SA
 */
struct ha_backend_t {

	/**
	 * Implements backend_t
	 */
	backend_t public;

	/**
	 * peer config we serve
	 */
	peer_cfg_t *cfg;
};

/**
 * Private data of an ha_sync_socket_t object.
 */
struct private_ha_sync_socket_t {

	/**
	 * Public ha_sync_socket_t interface.
	 */
	ha_sync_socket_t public;

	/**
	 * UDP communication socket fd
	 */
	int fd;

	/**
	 * remote host to receive/send to
	 */
	host_t *remote;

	/**
	 * Reqid of installed trap
	 */
	u_int32_t trap;

	/**
	 * backend for sync SA
	 */
	ha_backend_t backend;

	/**
	 * credential set for sync SA
	 */
	ha_creds_t creds;
};

/**
 * Data to pass to the send_message() callback job
 */
typedef struct {
	ha_sync_message_t *message;
	private_ha_sync_socket_t *this;
} job_data_t;

/**
 * Cleanup job data
 */
static void job_data_destroy(job_data_t *this)
{
	this->message->destroy(this->message);
	free(this);
}

/**
 * Callback to asynchronously send messages
 */
static job_requeue_t send_message(job_data_t *data)
{
	private_ha_sync_socket_t *this;
	chunk_t chunk;

	this = data->this;
	chunk = data->message->get_encoding(data->message);
	if (sendto(this->fd, chunk.ptr, chunk.len, 0,
			   this->remote->get_sockaddr(this->remote),
			   *this->remote->get_sockaddr_len(this->remote)) < chunk.len)
	{
		DBG1(DBG_CFG, "pushing HA sync message failed: %s", strerror(errno));
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of ha_sync_socket_t.push
 */
static void push(private_ha_sync_socket_t *this, ha_sync_message_t *message)
{
	if (this->trap)
	{
		callback_job_t *job;
		job_data_t *data;

		data = malloc_thing(job_data_t);
		data->message = message;
		data->this = this;

		/* we send sync message asynchronously. This is required, as sendto()
		 * is a blocking call if it acquires a policy. Otherwise we could
		 * end up in a deadlock, as we own an IKE_SA. */
		job = callback_job_create((callback_job_cb_t)send_message,
								  data, (void*)job_data_destroy, NULL);
		charon->processor->queue_job(charon->processor, (job_t*)job);
	}
	else
	{
		job_data_t data;

		data.message = message;
		data.this = this;
		send_message(&data);
		message->destroy(message);
	}
}

/**
 * Implementation of ha_sync_socket_t.pull
 */
static ha_sync_message_t *pull(private_ha_sync_socket_t *this)
{
	while (TRUE)
	{
		ha_sync_message_t *message;
		char buf[1024];
		int oldstate;
		ssize_t len;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		len = recvfrom(this->fd, buf, sizeof(buf), 0,
					   this->remote->get_sockaddr(this->remote),
					   this->remote->get_sockaddr_len(this->remote));
		pthread_setcancelstate(oldstate, NULL);
		if (len <= 0)
		{
			if (errno != EINTR)
			{
				DBG1(DBG_CFG, "pulling HA sync message failed: %s",
					 strerror(errno));
				sleep(1);
			}
			continue;
		}
		message = ha_sync_message_parse(chunk_create(buf, len));
		if (message)
		{
			return message;
		}
	}
}

/**
 * Implementation of ha_sync_socket_t.is_sync_sa
 */
static bool is_sync_sa(private_ha_sync_socket_t *this, ike_sa_t *ike_sa)
{
	peer_cfg_t *cfg = this->backend.cfg;

	return cfg && ike_sa->get_ike_cfg(ike_sa) == cfg->get_ike_cfg(cfg);
}

/**
 * Enumerator over HA shared_key
 */
typedef struct {
	/** Implements enumerator_t */
	enumerator_t public;
	/** a single secret we serve */
	shared_key_t *key;
} shared_enum_t;

/**
 * Implementation of shared_enum_t.enumerate
 */
static bool shared_enumerate(shared_enum_t *this, shared_key_t **key,
							 id_match_t *me, id_match_t *other)
{
	if (this->key)
	{
		if (me)
		{
			*me = ID_MATCH_PERFECT;
		}
		if (other)
		{
			*other = ID_MATCH_PERFECT;
		}
		*key = this->key;
		this->key = NULL;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implements ha_creds_t.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(ha_creds_t *this,
							shared_key_type_t type, identification_t *me,
							identification_t *other)
{
	shared_enum_t *enumerator;

	if (type != SHARED_IKE && type != SHARED_ANY)
	{
		return NULL;
	}
	if (me && !me->equals(me, this->local))
	{
		return NULL;
	}
	if (other && !other->equals(other, this->remote))
	{
		return NULL;
	}

	enumerator = malloc_thing(shared_enum_t);
	enumerator->public.enumerate = (void*)shared_enumerate;
	enumerator->public.destroy = (void*)free;
	enumerator->key = this->key;

	return &enumerator->public;
}

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(ha_backend_t *this,
								identification_t *me, identification_t *other)
{
	return enumerator_create_single(this->cfg, NULL);
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(ha_backend_t *this,
											   host_t *me, host_t *other)
{
	return enumerator_create_single(this->cfg->get_ike_cfg(this->cfg), NULL);
}

/**
 * Install configs and a a trap for secured sync
 */
static void setup_sync_tunnel(private_ha_sync_socket_t *this)
{
	char *local, *remote, *secret;
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;
	auth_cfg_t *auth_cfg;
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;

	secret = lib->settings->get_str(lib->settings,
									"charon.plugins.ha_sync.secret", NULL);
	if (!secret)
	{
		DBG1(DBG_CFG, "no HA sync secret defined, using unencrypted sync");
		return;
	}
	local = lib->settings->get_str(lib->settings,
								   "charon.plugins.ha_sync.local", NULL);
	remote = lib->settings->get_str(lib->settings,
								   "charon.plugins.ha_sync.remote", NULL);

	/* setup credentials */
	this->creds.key = shared_key_create(SHARED_IKE,
							chunk_clone(chunk_create(secret, strlen(secret))));
	this->creds.local = identification_create_from_string(local);
	this->creds.remote = identification_create_from_string(remote);
	this->creds.public.create_private_enumerator = (void*)return_null;
	this->creds.public.create_cert_enumerator = (void*)return_null;
	this->creds.public.create_shared_enumerator = (void*)create_shared_enumerator;
	this->creds.public.create_cdp_enumerator = (void*)return_null;
	this->creds.public.cache_cert = (void*)nop;

	charon->credentials->add_set(charon->credentials, &this->creds.public);

	/* create config and backend */
	ike_cfg = ike_cfg_create(FALSE, FALSE, local, remote);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	peer_cfg = peer_cfg_create("ha-sync", 2, ike_cfg, CERT_NEVER_SEND,
						UNIQUE_KEEP, 0, 86400, 0, 7200, 3600, FALSE, 30,
						NULL, NULL, FALSE, NULL, NULL);

	auth_cfg = auth_cfg_create();
	auth_cfg->add(auth_cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	auth_cfg->add(auth_cfg, AUTH_RULE_IDENTITY,
				  identification_create_from_string(local));
	peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, TRUE);

	auth_cfg = auth_cfg_create();
	auth_cfg->add(auth_cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	auth_cfg->add(auth_cfg, AUTH_RULE_IDENTITY,
				  identification_create_from_string(remote));
	peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, FALSE);

	child_cfg = child_cfg_create("ha-sync", 0, 21600, 1200, FALSE, TRUE,
						MODE_TRANSPORT, ACTION_NONE, ACTION_NONE, FALSE);
	ts = traffic_selector_create_dynamic(0, HA_SYNC_PORT, HA_SYNC_PORT);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_dynamic(0, HA_SYNC_PORT, HA_SYNC_PORT);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);

	this->backend.cfg = peer_cfg;
	this->backend.public.create_peer_cfg_enumerator = (void*)create_peer_cfg_enumerator;
	this->backend.public.create_ike_cfg_enumerator = (void*)create_ike_cfg_enumerator;
	this->backend.public.get_peer_cfg_by_name = (void*)return_null;

	charon->backends->add_backend(charon->backends, &this->backend.public);

	/* install an acquiring trap */
	this->trap = charon->traps->install(charon->traps, peer_cfg, child_cfg);
}

/**
 * read local/remote node address from config
 */
static host_t *get_host_config(char *key)
{
	char *value;
	host_t *host;

	value = lib->settings->get_str(lib->settings,
								   "charon.plugins.ha_sync.%s", NULL, key);
	if (!value)
	{
		DBG1(DBG_CFG, "no %s node specified for HA sync", key);
		return NULL;
	}
	host = host_create_from_dns(value, 0, HA_SYNC_PORT);
	if (!host)
	{
		DBG1(DBG_CFG, "%s node '%s' is invalid", key, value);
	}
	return host;
}

/**
 * Open and connect the HA sync socket
 */
static bool open_socket(private_ha_sync_socket_t *this)
{
	host_t *local;

	local = get_host_config("local");
	if (!local)
	{
		return FALSE;
	}

	this->fd = socket(local->get_family(local), SOCK_DGRAM, 0);
	if (!this->fd)
	{
		local->destroy(local);
		DBG1(DBG_CFG, "opening HA sync socket failed: %s", strerror(errno));
		return FALSE;
	}

	if (bind(this->fd, local->get_sockaddr(local),
			 *local->get_sockaddr_len(local)) == -1)
	{
		DBG1(DBG_CFG, "binding HA sync socket failed: %s", strerror(errno));
		close(this->fd);
		local->destroy(local);
		return FALSE;
	}
	local->destroy(local);
	return TRUE;
}

/**
 * Implementation of ha_sync_socket_t.destroy.
 */
static void destroy(private_ha_sync_socket_t *this)
{
	close(this->fd);
	if (this->backend.cfg)
	{
		charon->backends->remove_backend(charon->backends, &this->backend.public);
		this->backend.cfg->destroy(this->backend.cfg);
	}
	if (this->creds.key)
	{
		charon->credentials->remove_set(charon->credentials, &this->creds.public);
		this->creds.key->destroy(this->creds.key);
	}
	DESTROY_IF(this->creds.local);
	DESTROY_IF(this->creds.remote);
	DESTROY_IF(this->remote);
	if (this->trap)
	{
		charon->traps->uninstall(charon->traps, this->trap);
	}
	free(this);
}

/**
 * See header
 */
ha_sync_socket_t *ha_sync_socket_create()
{
	private_ha_sync_socket_t *this = malloc_thing(private_ha_sync_socket_t);

	this->public.push = (void(*)(ha_sync_socket_t*, ha_sync_message_t*))push;
	this->public.pull = (ha_sync_message_t*(*)(ha_sync_socket_t*))pull;
	this->public.is_sync_sa = (bool(*)(ha_sync_socket_t*, ike_sa_t *ike_sa))is_sync_sa;
	this->public.destroy = (void(*)(ha_sync_socket_t*))destroy;

	this->remote = get_host_config("remote");
	if (!this->remote)
	{
		free(this);
		return NULL;
	}
	this->trap = 0;
	this->creds.key = NULL;
	this->creds.local = NULL;
	this->creds.remote = NULL;
	this->backend.cfg = NULL;

	setup_sync_tunnel(this);

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}

	return &this->public;
}

