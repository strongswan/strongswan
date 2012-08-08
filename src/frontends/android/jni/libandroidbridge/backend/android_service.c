/*
 * Copyright (C) 2010-2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

#include "android_service.h"
#include "../charonservice.h"
#include "../vpnservice_builder.h"

#include <daemon.h>
#include <library.h>
#include <processing/jobs/callback_job.h>
#include <threading/rwlock.h>

typedef struct private_android_service_t private_android_service_t;

#define TUN_DEFAULT_MTU 1400

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
	 * local ipv4 address
	 */
	char *local_address;

	/**
	 * gateway
	 */
	char *gateway;

	/**
	 * username
	 */
	char *username;

	/**
	 * lock to safely access the TUN device fd
	 */
	rwlock_t *lock;

	/**
	 * TUN device file descriptor
	 */
	int tunfd;

};

/**
 * Setup a new TUN device for the supplied SAs.
 * Additional information such as DNS servers are gathered in appropriate
 * listeners asynchronously.  To be sure every required bit of information is
 * available this should be called after the CHILD_SA has been established.
 */
static bool setup_tun_device(private_android_service_t *this,
							 ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	vpnservice_builder_t *builder;
	int tunfd;

	DBG1(DBG_DMN, "setting up TUN device for CHILD_SA %s{%u}",
		 child_sa->get_name(child_sa), child_sa->get_reqid(child_sa));

	builder = charonservice->get_vpnservice_builder(charonservice);
	if (!builder->set_mtu(builder, TUN_DEFAULT_MTU))
	{
		return FALSE;
	}

	tunfd = builder->establish(builder);
	if (tunfd == -1)
	{
		return FALSE;
	}

	this->lock->write_lock(this->lock);
	this->tunfd = tunfd;
	this->lock->unlock(this->lock);

	DBG1(DBG_DMN, "successfully created TUN device");
	return TRUE;
}

/**
 * Close the current tun device
 */
static void close_tun_device(private_android_service_t *this)
{
	int tunfd;

	this->lock->write_lock(this->lock);
	if (this->tunfd < 0)
	{	/* already closed (or never created) */
		this->lock->unlock(this->lock);
		return;
	}
	tunfd = this->tunfd;
	this->tunfd = -1;
	this->lock->unlock(this->lock);
	close(tunfd);
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
			this->public.listener.ike_state_change = NULL;
			if (!setup_tun_device(this, ike_sa, child_sa))
			{
				DBG1(DBG_DMN, "failed to setup TUN device");
				charonservice->update_status(charonservice,
											 CHARONSERVICE_GENERIC_ERROR);
				return FALSE;

			}
			charonservice->update_status(charonservice,
										 CHARONSERVICE_CHILD_STATE_UP);
		}
		else
		{
			close_tun_device(this);
			charonservice->update_status(charonservice,
										 CHARONSERVICE_CHILD_STATE_DOWN);
			return FALSE;
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_android_service_t *this, ike_sa_t *ike_sa, bool up)
{
	/* this callback is only registered during initiation, so if the IKE_SA
	 * goes down we assume an authentication error */
	if (this->ike_sa == ike_sa && !up)
	{
		charonservice->update_status(charonservice,
									 CHARONSERVICE_AUTH_ERROR);
		return FALSE;
	}
	return TRUE;
}

METHOD(listener_t, ike_state_change, bool,
	private_android_service_t *this, ike_sa_t *ike_sa, ike_sa_state_t state)
{
	/* this call back is only registered during initiation */
	if (this->ike_sa == ike_sa && state == IKE_DESTROYING)
	{
		charonservice->update_status(charonservice,
									 CHARONSERVICE_UNREACHABLE_ERROR);
		return FALSE;
	}
	return TRUE;
}

METHOD(listener_t, alert, bool,
	private_android_service_t *this, ike_sa_t *ike_sa, alert_t alert,
	va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		switch (alert)
		{
			case ALERT_PEER_ADDR_FAILED:
				charonservice->update_status(charonservice,
											 CHARONSERVICE_LOOKUP_ERROR);
				break;
			case ALERT_PEER_AUTH_FAILED:
				charonservice->update_status(charonservice,
											 CHARONSERVICE_PEER_AUTH_ERROR);
				break;
			default:
				break;
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

static job_requeue_t initiate(private_android_service_t *this)
{
	identification_t *gateway, *user;
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

	ike_cfg = ike_cfg_create(TRUE, TRUE, this->local_address, FALSE,
							 charon->socket->get_port(charon->socket, FALSE),
							 this->gateway, FALSE, IKEV2_UDP_PORT);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));

	peer_cfg = peer_cfg_create("android", IKEV2, ike_cfg, CERT_SEND_IF_ASKED,
							   UNIQUE_REPLACE, 1, /* keyingtries */
							   36000, 0, /* rekey 10h, reauth none */
							   600, 600, /* jitter, over 10min */
							   TRUE, FALSE, /* mobike, aggressive */
							   0, 0, /* DPD delay, timeout */
							   host_create_from_string("0.0.0.0", 0) /* virt */,
							   NULL, FALSE, NULL, NULL); /* pool, mediation */


	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);
	user = identification_create_from_string(this->username);
	auth->add(auth, AUTH_RULE_IDENTITY, user);
	peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);
	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
	gateway = identification_create_from_string(this->gateway);
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
		charonservice->update_status(charonservice,
									 CHARONSERVICE_GENERIC_ERROR);
		return JOB_REQUEUE_NONE;
	}
	if (!ike_sa->get_peer_cfg(ike_sa))
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	peer_cfg->destroy(peer_cfg);

	/* store the IKE_SA so we can track its progress */
	this->ike_sa = ike_sa;

	/* get an additional reference because initiate consumes one */
	child_cfg->get_ref(child_cfg);
	if (ike_sa->initiate(ike_sa, child_cfg, 0, NULL, NULL) != SUCCESS)
	{
		DBG1(DBG_CFG, "failed to initiate tunnel");
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
			ike_sa);
		return JOB_REQUEUE_NONE;
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return JOB_REQUEUE_NONE;
}

METHOD(android_service_t, destroy, void,
	private_android_service_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->public.listener);
	/* make sure the tun device is actually closed */
	close_tun_device(this);
	this->lock->destroy(this->lock);
	free(this->local_address);
	free(this->username);
	free(this->gateway);
	free(this);
}

/**
 * See header
 */
android_service_t *android_service_create(char *local_address, char *gateway,
										  char *username)
{
	private_android_service_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_rekey = _ike_rekey,
				.ike_updown = _ike_updown,
				.ike_state_change = _ike_state_change,
				.child_updown = _child_updown,
				.alert = _alert,
			},
			.destroy = _destroy,
		},
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.local_address = local_address,
		.username = username,
		.gateway = gateway,
		.tunfd = -1,
	);

	charon->bus->add_listener(charon->bus, &this->public.listener);

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)initiate, this,
									NULL, NULL));
	return &this->public;
}
