/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "eap_radius_dae.h"

#include "radius_message.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

#define RADIUS_DAE_PORT 3799

typedef struct private_eap_radius_dae_t private_eap_radius_dae_t;

/**
 * Private data of an eap_radius_dae_t object.
 */
struct private_eap_radius_dae_t {

	/**
	 * Public eap_radius_dae_t interface.
	 */
	eap_radius_dae_t public;

	/**
	 * RADIUS session state
	 */
	eap_radius_accounting_t *accounting;

	/**
	 * Socket to listen on authorization extension port
	 */
	int fd;

	/**
	 * Listen job
	 */
	callback_job_t *job;

	/**
	 * RADIUS shared secret for DAE exchanges
	 */
	chunk_t secret;

	/**
	 * MD5 hasher
	 */
	hasher_t *hasher;

	/**
	 * HMAC MD5 signer, with secret set
	 */
	signer_t *signer;
};

/**
 * Receive RADIUS DAE requests
 */
static job_requeue_t receive(private_eap_radius_dae_t *this)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	radius_message_t *request;
	char buf[2048];
	ssize_t len;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	len = recvfrom(this->fd, buf, sizeof(buf), 0,
				   (struct sockaddr*)&addr, &addr_len);
	thread_cancelability(oldstate);

	if (len > 0)
	{
		request = radius_message_parse(chunk_create(buf, len));
		if (request)
		{
			if (request->verify(request, NULL, this->secret,
								this->hasher, this->signer))
			{
				switch (request->get_code(request))
				{
					case RMC_DISCONNECT_REQUEST:
						/* TODO */
					case RMC_COA_REQUEST:
						/* TODO */
					default:
						DBG1(DBG_CFG, "ignoring unsupported RADIUS DAE %N "
							 "message", radius_message_code_names,
							 request->get_code(request));
					break;
				}
			}
			request->destroy(request);
		}
		else
		{
			DBG1(DBG_NET, "ignoring invalid RADIUS DAE request");
		}
	}
	else
	{
		DBG1(DBG_NET, "receving RADIUS DAE request failed: %s", strerror(errno));
	}
	return JOB_REQUEUE_DIRECT;
}

/**
 * Open DAE socket
 */
static bool open_socket(private_eap_radius_dae_t *this)
{
	host_t *host;

	this->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (this->fd == -1)
	{
		DBG1(DBG_CFG, "unable to open RADIUS DAE socket: %s", strerror(errno));
		return FALSE;
	}

	host = host_create_from_string(
				lib->settings->get_str(lib->settings,
					"charon.plugins.eap-radius.dae.listen", "0.0.0.0"),
				lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.dae.port", RADIUS_DAE_PORT));
	if (!host)
	{
		DBG1(DBG_CFG, "invalid RADIUS DAE listen address");
		return FALSE;
	}

	if (bind(this->fd, host->get_sockaddr(host),
			 *host->get_sockaddr_len(host)) == -1)
	{
		DBG1(DBG_CFG, "unable to bind RADIUS DAE socket: %s", strerror(errno));
		host->destroy(host);
		return FALSE;
	}
	host->destroy(host);
	return TRUE;
}

METHOD(eap_radius_dae_t, destroy, void,
	private_eap_radius_dae_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	if (this->fd != -1)
	{
		close(this->fd);
	}
	DESTROY_IF(this->signer);
	DESTROY_IF(this->hasher);
	free(this);
}

/**
 * See header
 */
eap_radius_dae_t *eap_radius_dae_create(eap_radius_accounting_t *accounting)
{
	private_eap_radius_dae_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.accounting = accounting,
		.fd = -1,
		.secret = {
			.ptr = lib->settings->get_str(lib->settings,
							"charon.plugins.eap-radius.dae.secret", NULL),
		},
		.hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5),
		.signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_MD5_128),
	);

	if (!this->hasher || !this->signer)
	{
		destroy(this);
		return NULL;
	}
	if (!this->secret.ptr)
	{
		DBG1(DBG_CFG, "missing RADIUS DAE secret, disabled");
		destroy(this);
		return NULL;
	}
	this->secret.len = strlen(this->secret.ptr);
	this->signer->set_key(this->signer, this->secret);

	if (!open_socket(this))
	{
		destroy(this);
		return NULL;
	}

	this->job = callback_job_create_with_prio((callback_job_cb_t)receive,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->job);

	return &this->public;
}
