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

#include "dead_peer_notify_plugin.h"
#include "dead_peer_notify_listener.h"
#include "dead_peer_notify_mail.h"

#include <daemon.h>

typedef struct private_dead_peer_notify_plugin_t private_dead_peer_notify_plugin_t;

/**
 * private data of dead_peer_notify plugin
 */
struct private_dead_peer_notify_plugin_t {

	/**
	 * Implements plugin interface
	 */
	dead_peer_notify_plugin_t public;

	/**
	 * Listener catching error alerts
	 */
	dead_peer_notify_listener_t *listener;

	/**
	 * Email send instance
	 */
	dead_peer_notify_mail_t *mail;

	/**
	 * External command instance
	 */
	dead_peer_notify_exec_t *script;
};

METHOD(plugin_t, get_name, char*,
	private_dead_peer_notify_plugin_t *this)
{
	return "dead-peer-notify";
}

/**
 * Register listener
 */
static bool plugin_cb(private_dead_peer_notify_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_dead_peer_notify_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "dead-peer-notify"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_dead_peer_notify_plugin_t *this)
{
	this->listener->destroy(this->listener);
	this->mail->destroy(this->mail);
	this->script->destroy(this->script);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *dead_peer_notify_plugin_create()
{
	private_dead_peer_notify_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.mail = dead_peer_notify_mail_create(),
		.script = dead_peer_notify_exec_create(),
	);

	this->listener = dead_peer_notify_listener_create(this->mail, this->script);

	return &this->public.plugin;
}
