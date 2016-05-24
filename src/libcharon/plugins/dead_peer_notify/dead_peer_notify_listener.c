/* vim: set ts=4 sw=4 noexpandtab: */
/*
 * Copyright (C) 2015 Pavel Balaev.
 * Copyright (C) 2015 InfoTeCS JSC.
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

#include "dead_peer_notify_listener.h"

#include <daemon.h>

typedef struct private_dead_peer_notify_listener_t private_dead_peer_notify_listener_t;

/**
 * Private data of an dead_peer_notify_listener_t object.
 */
struct private_dead_peer_notify_listener_t {

	/**
	 * Public dead_peer_notify_listener_t interface.
	 */
	dead_peer_notify_listener_t public;

	/**
	 * Send email interface.
	 */
	dead_peer_notify_mail_t *mail;

	/**
	 * Execute external command interface.
	 */
	dead_peer_notify_exec_t *script;
};

METHOD(listener_t, alert, bool,
	private_dead_peer_notify_listener_t *this, ike_sa_t *ike_sa,
	alert_t alert, va_list args)
{
	host_t *host;
	peer_cfg_t *peer_cfg;
	char host_str[64];

	memset(host_str, 0, sizeof(host_str));

	if (alert == ALERT_RETRANSMIT_SEND_TIMEOUT)
	{
		if (ike_sa)
		{
			peer_cfg = ike_sa->get_peer_cfg(ike_sa);
			host = ike_sa->get_other_host(ike_sa);

			if (!host->is_anyaddr(host))
			{
				snprintf(host_str, sizeof(host_str), "%#H", host);
			}
			else
			{
				snprintf(host_str, sizeof(host_str), "unknown");
			}

			if (peer_cfg)
			{
				this->mail->send_mail(this->mail, peer_cfg->get_name(peer_cfg), host_str);
				this->script->run(this->script, peer_cfg->get_name(peer_cfg), host_str);
			}
		}
	}

	return TRUE;
}

METHOD(dead_peer_notify_listener_t, destroy, void,
	private_dead_peer_notify_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
dead_peer_notify_listener_t *dead_peer_notify_listener_create(dead_peer_notify_mail_t *m,
															  dead_peer_notify_exec_t *s)
{
	private_dead_peer_notify_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.alert = _alert,
			},
			.destroy = _destroy,
		},
		.mail = m,
		.script = s,
	);

	return &this->public;
}
