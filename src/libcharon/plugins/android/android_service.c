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

#include <unistd.h>
#include <cutils/sockets.h>
#include <cutils/properties.h>
#include <signal.h>

#include "android_service.h"

#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

typedef struct private_android_service_t private_android_service_t;

/**
 * private data of Android service
 */
struct private_android_service_t {

	/**
	 * public interface
	 */
	android_service_t public;

	/**
	 * current IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * android credentials
	 */
	android_creds_t *creds;

	/**
	 * android control socket
	 */
	int control;

};

/**
 * Some of the error codes defined in VpnManager.java
 */
typedef enum {
	/** Error code to indicate an error from authentication. */
	VPN_ERROR_AUTH = 51,
	/** Error code to indicate the connection attempt failed. */
	VPN_ERROR_CONNECTION_FAILED = 101,
	/** Error code to indicate an error of remote server hanging up. */
	VPN_ERROR_REMOTE_HUNG_UP = 7,
	/** Error code to indicate an error of losing connectivity. */
	VPN_ERROR_CONNECTION_LOST = 103,
} android_vpn_errors_t;

/**
 * send a status code back to the Android app
 */
static void send_status(private_android_service_t *this, u_char code)
{
	DBG1(DBG_CFG, "status of Android plugin changed: %d", code);
	send(this->control, &code, 1, 0);
}

METHOD(listener_t, ike_updown, bool,
	   private_android_service_t *this, ike_sa_t *ike_sa, bool up)
{
	/* this callback is only registered during initiation, so if the IKE_SA
	 * goes down we assume an authentication error */
	if (this->ike_sa == ike_sa && !up)
	{
		send_status(this, VPN_ERROR_AUTH);
		return FALSE;
	}
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
	   private_android_service_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	   child_sa_state_t state)
{
	/* this callback is only registered during initiation, so we still have
	 * the control socket open */
	if (this->ike_sa == ike_sa && state == CHILD_DESTROYING)
	{
		send_status(this, VPN_ERROR_CONNECTION_FAILED);
		return FALSE;
	}
	return TRUE;
}

/**
 * Callback used to shutdown the daemon
 */
static job_requeue_t shutdown_callback(void *data)
{
	kill(0, SIGTERM);
	return JOB_REQUEUE_NONE;
}

METHOD(listener_t, child_updown, bool,
	   private_android_service_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	   bool up)
{
	if (this->ike_sa == ike_sa)
	{
		if (up)
		{
			/* disable the hooks registered to catch initiation failures */
			this->public.listener.ike_updown = NULL;
			this->public.listener.child_state_change = NULL;
			property_set("vpn.status", "ok");
		}
		else
		{
			callback_job_t *job;
			/* the control socket is closed as soon as vpn.status is set to "ok"
			 * and the daemon proxy then only checks for terminated daemons to
			 * detect lost connections, so... */
			DBG1(DBG_CFG, "connection lost, raising delayed SIGTERM");
			/* to avoid any conflicts we send the SIGTERM not directly from this
			 * callback, but from a different thread. we also delay it to avoid
			 * a race condition during a regular shutdown */
			job = callback_job_create(shutdown_callback, NULL, NULL, NULL);
			lib->scheduler->schedule_job(lib->scheduler, (job_t*)job, 1);
			return FALSE;
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	   private_android_service_t *this, ike_sa_t *old, ike_sa_t *new)
{
	if (this->ike_sa == old)
	{
		this->ike_sa = new;
	}
	return TRUE;
}

/**
 * Read a string argument from the Android control socket
 */
static char *read_argument(int fd, u_char length)
{
	int offset = 0;
	char *data = malloc(length + 1);
	while (offset < length)
	{
		int n = recv(fd, &data[offset], length - offset, 0);
		if (n < 0)
		{
			DBG1(DBG_CFG, "failed to read argument from Android"
				 " control socket: %s", strerror(errno));
			free(data);
			return NULL;
		}
		offset += n;
	}
	data[length] = '\0';
	DBG3(DBG_CFG, "received argument from Android control socket: %s", data);
	return data;
}

/**
 * handle the request received from the Android control socket
 */
static job_requeue_t initiate(private_android_service_t *this)
{
	bool oldstate;
	int fd, i = 0;
	char *hostname = NULL, *cacert = NULL, *username = NULL, *password = NULL;
	identification_t *gateway = NULL, *user = NULL;
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;
	ike_sa_t *ike_sa;
	auth_cfg_t *auth;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = 10800, /* 3h */
			.rekey = 10200, /* 2h50min */
			.jitter = 300 /* 5min */
		}
	};

	fd = accept(this->control, NULL, 0);
	if (fd < 0)
	{
		DBG1(DBG_CFG, "accept on Android control socket failed: %s",
			 strerror(errno));
		return JOB_REQUEUE_NONE;
	}
	/* the original control socket is not used anymore */
	close(this->control);
	this->control = fd;

	while (TRUE)
	{
		u_char length;
		if (recv(fd, &length, 1, 0) != 1)
		{
			DBG1(DBG_CFG, "failed to read from Android control socket: %s",
				 strerror(errno));
			return JOB_REQUEUE_NONE;
		}

		if (length == 0xFF)
		{	/* last argument */
			break;
		}
		else
		{
			switch (i++)
			{
				case 0: /* gateway */
					hostname = read_argument(fd, length);
					break;
				case 1: /* CA certificate name */
					cacert = read_argument(fd, length);
					break;
				case 2: /* username */
					username = read_argument(fd, length);
					break;
				case 3: /* password */
					password = read_argument(fd, length);
					break;
			}
		}
	}

	if (cacert)
	{
		if (!this->creds->add_certificate(this->creds, cacert))
		{
			DBG1(DBG_CFG, "failed to load CA certificate");
		}
		/* if this is a server cert we could use the cert subject as id
		 * but we have to test first if that possible to configure */
	}

	gateway = identification_create_from_string(hostname);
	DBG1(DBG_CFG, "using CA certificate, gateway identitiy '%Y'", gateway);

	if (username)
	{
		user = identification_create_from_string(username);
		this->creds->set_username_password(this->creds, user, password);
	}

	ike_cfg = ike_cfg_create(TRUE, FALSE, "0.0.0.0", FALSE,
							 charon->socket->get_port(charon->socket, FALSE),
							 hostname, FALSE, IKEV2_UDP_PORT);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));

	peer_cfg = peer_cfg_create("android", IKEV2, ike_cfg, CERT_SEND_IF_ASKED,
							   UNIQUE_REPLACE, 1, /* keyingtries */
							   36000, 0, /* rekey 10h, reauth none */
							   600, 600, /* jitter, over 10min */
							   TRUE, FALSE, /* mobike, aggressive */
							   0, 0, /* DPD delay, timeout */
							   FALSE, NULL, NULL); /* mediation */
	peer_cfg->add_virtual_ip(peer_cfg,  host_create_from_string("0.0.0.0", 0));

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);
	auth->add(auth, AUTH_RULE_IDENTITY, user);
	peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);
	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
	auth->add(auth, AUTH_RULE_IDENTITY, gateway);
	peer_cfg->add_auth_cfg(peer_cfg, auth, FALSE);

	child_cfg = child_cfg_create("android", &lifetime, NULL, TRUE, MODE_TUNNEL,
								 ACTION_NONE, ACTION_NONE, ACTION_NONE, FALSE,
								 0, 0, NULL, NULL, 0);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_from_string(0, TS_IPV4_ADDR_RANGE, "0.0.0.0",
											 0, "255.255.255.255", 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);

	/* get us an IKE_SA */
	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
														peer_cfg);
	if (!ike_sa)
	{
		peer_cfg->destroy(peer_cfg);
		send_status(this, VPN_ERROR_CONNECTION_FAILED);
		return JOB_REQUEUE_NONE;
	}

	if (!ike_sa->get_peer_cfg(ike_sa))
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	peer_cfg->destroy(peer_cfg);

	/* store the IKE_SA so we can track its progress */
	this->ike_sa = ike_sa;

	/* confirm that we received the request */
	send_status(this, i);

	/* get an additional reference because initiate consumes one */
	child_cfg->get_ref(child_cfg);
	if (ike_sa->initiate(ike_sa, child_cfg, 0, NULL, NULL) != SUCCESS)
	{
		DBG1(DBG_CFG, "failed to initiate tunnel");
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													ike_sa);
		send_status(this, VPN_ERROR_CONNECTION_FAILED);
		return JOB_REQUEUE_NONE;
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return JOB_REQUEUE_NONE;
}

METHOD(android_service_t, destroy, void,
	   private_android_service_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->public.listener);
	close(this->control);
	free(this);
}

/**
 * See header
 */
android_service_t *android_service_create(android_creds_t *creds)
{
	private_android_service_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
				.child_state_change = _child_state_change,
				.child_updown = _child_updown,
				.ike_rekey = _ike_rekey,
			},
			.destroy = _destroy,
		},
		.creds = creds,
	);

	this->control = android_get_control_socket("charon");
	if (this->control == -1)
	{
		DBG1(DBG_CFG, "failed to get Android control socket");
		free(this);
		return NULL;
	}

	if (listen(this->control, 1) < 0)
	{
		DBG1(DBG_CFG, "failed to listen on Android control socket: %s",
			 strerror(errno));
		close(this->control);
		free(this);
		return NULL;
	}

	charon->bus->add_listener(charon->bus, &this->public.listener);
	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)initiate, this,
									NULL, NULL));

	return &this->public;
}

