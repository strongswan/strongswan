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

#include <errno.h>
#include <unistd.h>

#include "android_service.h"
#include "../charonservice.h"
#include "../vpnservice_builder.h"

#include <daemon.h>
#include <library.h>
#include <ipsec.h>
#include <processing/jobs/callback_job.h>
#include <threading/rwlock.h>
#include <threading/thread.h>

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
	 * credential set
	 */
	android_creds_t *creds;

	/**
	 * current IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * the type of VPN
	 */
	char *type;

	/**
	 * gateway
	 */
	char *gateway;

	/**
	 * username
	 */
	char *username;

	/**
	 * password
	 */
	char *password;

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
 * Outbound callback
 */
static void send_esp(void *data, esp_packet_t *packet)
{
	charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
}

/**
 * Inbound callback
 */
static void deliver_plain(private_android_service_t *this,
						  ip_packet_t *packet)
{
	chunk_t encoding;
	ssize_t len;

	encoding = packet->get_encoding(packet);

	this->lock->read_lock(this->lock);
	if (this->tunfd < 0)
	{	/* the TUN device is already closed */
		this->lock->unlock(this->lock);
		packet->destroy(packet);
		return;
	}
	len = write(this->tunfd, encoding.ptr, encoding.len);
	this->lock->unlock(this->lock);

	if (len < 0 || len != encoding.len)
	{
		DBG1(DBG_DMN, "failed to write packet to TUN device: %s",
			 strerror(errno));
	}
	packet->destroy(packet);
}

/**
 * Receiver callback
 */
static void receiver_esp_cb(void *data, packet_t *packet)
{
	esp_packet_t *esp_packet;

	esp_packet = esp_packet_create_from_packet(packet);
	ipsec->processor->queue_inbound(ipsec->processor, esp_packet);
}

/**
 * Job handling outbound plaintext packets
 */
static job_requeue_t handle_plain(private_android_service_t *this)
{
	ip_packet_t *packet;
	chunk_t raw;
	fd_set set;
	ssize_t len;
	int tunfd;
	bool old;
	timeval_t tv = {
		/* check every second if tunfd is still valid */
		.tv_sec = 1,
	};

	FD_ZERO(&set);

	this->lock->read_lock(this->lock);
	if (this->tunfd < 0)
	{	/* the TUN device is already closed */
		this->lock->unlock(this->lock);
		return JOB_REQUEUE_NONE;
	}
	tunfd = this->tunfd;
	FD_SET(tunfd, &set);
	this->lock->unlock(this->lock);

	old = thread_cancelability(TRUE);
	len = select(tunfd + 1, &set, NULL, NULL, &tv);
	thread_cancelability(old);

	if (len < 0)
	{
		DBG1(DBG_DMN, "select on TUN device failed: %s", strerror(errno));
		return JOB_REQUEUE_NONE;
	}
	else if (len == 0)
	{	/* timeout, check again right away */
		return JOB_REQUEUE_DIRECT;
	}

	raw = chunk_alloc(TUN_DEFAULT_MTU);
	len = read(tunfd, raw.ptr, raw.len);
	if (len < 0)
	{
		DBG1(DBG_DMN, "reading from TUN device failed: %s", strerror(errno));
		chunk_free(&raw);
		return JOB_REQUEUE_FAIR;
	}
	raw.len = len;

	packet = ip_packet_create(raw);
	if (packet)
	{
		ipsec->processor->queue_outbound(ipsec->processor, packet);
	}
	else
	{
		DBG1(DBG_DMN, "invalid IP packet read from TUN device");
	}
	return JOB_REQUEUE_DIRECT;
}

/**
 * Add a route to the TUN device builder
 */
static bool add_route(vpnservice_builder_t *builder, host_t *net,
					  u_int8_t prefix)
{
	/* if route is 0.0.0.0/0, split it into two routes 0.0.0.0/1 and
	 * 128.0.0.0/1 because otherwise it would conflict with the current default
	 * route */
	if (net->is_anyaddr(net) && prefix == 0)
	{
		bool success;

		success = add_route(builder, net, 1);
		net = host_create_from_string("128.0.0.0", 0);
		success = success && add_route(builder, net, 1);
		net->destroy(net);
		return success;
	}
	return builder->add_route(builder, net, prefix);
}

/**
 * Generate and set routes from installed IPsec policies
 */
static bool add_routes(vpnservice_builder_t *builder, child_sa_t *child_sa)
{
	traffic_selector_t *src_ts, *dst_ts;
	enumerator_t *enumerator;
	bool success = TRUE;

	enumerator = child_sa->create_policy_enumerator(child_sa);
	while (success && enumerator->enumerate(enumerator, &src_ts, &dst_ts))
	{
		host_t *net;
		u_int8_t prefix;

		dst_ts->to_subnet(dst_ts, &net, &prefix);
		success = add_route(builder, net, prefix);
		net->destroy(net);
	}
	enumerator->destroy(enumerator);
	return success;
}

/**
 * Setup a new TUN device for the supplied SAs, also queues a job that
 * reads packets from this device.
 * Additional information such as DNS servers are gathered in appropriate
 * listeners asynchronously.  To be sure every required bit of information is
 * available this should be called after the CHILD_SA has been established.
 */
static bool setup_tun_device(private_android_service_t *this,
							 ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	vpnservice_builder_t *builder;
	enumerator_t *enumerator;
	bool vip_found = FALSE, already_registered = FALSE;
	host_t *vip;
	int tunfd;

	DBG1(DBG_DMN, "setting up TUN device for CHILD_SA %s{%u}",
		 child_sa->get_name(child_sa), child_sa->get_reqid(child_sa));

	builder = charonservice->get_vpnservice_builder(charonservice);

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	while (enumerator->enumerate(enumerator, &vip))
	{
		if (!vip->is_anyaddr(vip))
		{
			if (!builder->add_address(builder, vip))
			{
				break;
			}
			vip_found = TRUE;
		}
	}
	enumerator->destroy(enumerator);

	if (!vip_found)
	{
		DBG1(DBG_DMN, "setting up TUN device failed, no virtual IP found");
		return FALSE;
	}
	if (!add_routes(builder, child_sa) ||
		!builder->set_mtu(builder, TUN_DEFAULT_MTU))
	{
		return FALSE;
	}

	tunfd = builder->establish(builder);
	if (tunfd == -1)
	{
		return FALSE;
	}

	this->lock->write_lock(this->lock);
	if (this->tunfd > 0)
	{	/* close previously opened TUN device */
		close(this->tunfd);
		already_registered = true;
	}
	this->tunfd = tunfd;
	this->lock->unlock(this->lock);

	DBG1(DBG_DMN, "successfully created TUN device");

	if (!already_registered)
	{
		charon->receiver->add_esp_cb(charon->receiver,
								(receiver_esp_cb_t)receiver_esp_cb, NULL);
		ipsec->processor->register_inbound(ipsec->processor,
									  (ipsec_inbound_cb_t)deliver_plain, this);
		ipsec->processor->register_outbound(ipsec->processor,
									   (ipsec_outbound_cb_t)send_esp, NULL);

		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, (callback_job_cancel_t)return_false));
	}
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

	ipsec->processor->unregister_outbound(ipsec->processor,
										 (ipsec_outbound_cb_t)send_esp);
	ipsec->processor->unregister_inbound(ipsec->processor,
										(ipsec_inbound_cb_t)deliver_plain);
	charon->receiver->del_esp_cb(charon->receiver,
								(receiver_esp_cb_t)receiver_esp_cb);
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
			if (ike_sa->has_condition(ike_sa, COND_REAUTHENTICATING))
			{	/* we ignore this during reauthentication */
				return TRUE;
			}
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
			case ALERT_PEER_INIT_UNREACHABLE:
				this->lock->read_lock(this->lock);
				if (this->tunfd < 0)
				{	/* only handle this if we are not reestablishing the SA */
					charonservice->update_status(charonservice,
											CHARONSERVICE_UNREACHABLE_ERROR);
				}
				this->lock->unlock(this->lock);
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

METHOD(listener_t, ike_reestablish, bool,
	private_android_service_t *this, ike_sa_t *old, ike_sa_t *new)
{
	if (this->ike_sa == old)
	{
		this->ike_sa = new;
		/* re-register hook to detect initiation failures */
		this->public.listener.ike_updown = _ike_updown;
		/* the TUN device will be closed when the new CHILD_SA is established */
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

	ike_cfg = ike_cfg_create(IKEV2, TRUE, TRUE, "0.0.0.0", FALSE,
							 charon->socket->get_port(charon->socket, FALSE),
							 this->gateway, FALSE, IKEV2_UDP_PORT,
							 FRAGMENTATION_NO);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));

	peer_cfg = peer_cfg_create("android", ike_cfg, CERT_SEND_IF_ASKED,
							   UNIQUE_REPLACE, 0, /* keyingtries */
							   36000, 0, /* rekey 10h, reauth none */
							   600, 600, /* jitter, over 10min */
							   TRUE, FALSE, /* mobike, aggressive */
							   0, 0, /* DPD delay, timeout */
							   FALSE, NULL, NULL); /* mediation */
	peer_cfg->add_virtual_ip(peer_cfg, host_create_from_string("0.0.0.0", 0));

	/* local auth config */
	if (streq("ikev2-eap", this->type))
	{
		auth = auth_cfg_create();
		auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);
		user = identification_create_from_string(this->username);
		auth->add(auth, AUTH_RULE_IDENTITY, user);

		this->creds->add_username_password(this->creds, this->username,
										   this->password);
		memwipe(this->password, strlen(this->password));
		peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);
	}
	else if (streq("ikev2-cert", this->type))
	{
		certificate_t *cert;
		identification_t *id;

		cert = this->creds->load_user_certificate(this->creds);
		if (!cert)
		{
			peer_cfg->destroy(peer_cfg);
			charonservice->update_status(charonservice,
										 CHARONSERVICE_GENERIC_ERROR);
			return JOB_REQUEUE_NONE;

		}
		auth = auth_cfg_create();
		auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
		auth->add(auth, AUTH_RULE_SUBJECT_CERT, cert);
		id = cert->get_subject(cert);
		auth->add(auth, AUTH_RULE_IDENTITY, id->clone(id));
		peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);
	}

	/* remote auth config */
	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
	gateway = identification_create_from_string(this->gateway);
	auth->add(auth, AUTH_RULE_IDENTITY, gateway);
	auth->add(auth, AUTH_RULE_IDENTITY_LOOSE, TRUE);
	peer_cfg->add_auth_cfg(peer_cfg, auth, FALSE);

	child_cfg = child_cfg_create("android", &lifetime, NULL, TRUE, MODE_TUNNEL,
								 ACTION_NONE, ACTION_RESTART, ACTION_RESTART,
								 FALSE, 0, 0, NULL, NULL, 0);
	/* create an ESP proposal with the algorithms currently supported by
	 * libipsec, no PFS for now */
	child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
							"aes128-aes192-aes256-sha1-sha256-sha384-sha512"));
	ts = traffic_selector_create_from_string(0, TS_IPV4_ADDR_RANGE, "0.0.0.0",
											 0, "255.255.255.255", 65535);
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
	free(this->type);
	free(this->gateway);
	free(this->username);
	if (this->password)
	{
		memwipe(this->password, strlen(this->password));
		free(this->password);
	}
	free(this);
}

/**
 * See header
 */
android_service_t *android_service_create(android_creds_t *creds, char *type,
										  char *gateway, char *username,
										  char *password)
{
	private_android_service_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_rekey = _ike_rekey,
				.ike_reestablish = _ike_reestablish,
				.ike_updown = _ike_updown,
				.child_updown = _child_updown,
				.alert = _alert,
			},
			.destroy = _destroy,
		},
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.username = username,
		.password = password,
		.gateway = gateway,
		.creds = creds,
		.type = type,
		.tunfd = -1,
	);

	charon->bus->add_listener(charon->bus, &this->public.listener);

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)initiate, this,
									NULL, NULL));
	return &this->public;
}
