/*
 * Copyright (C) 2008 Martin Willi
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

#include "ha_sync_plugin.h"
#include "ha_sync_ike.h"
#include "ha_sync_child.h"
#include "ha_sync_socket.h"
#include "ha_sync_tunnel.h"
#include "ha_sync_dispatcher.h"
#include "ha_sync_segments.h"
#include "ha_sync_ctl.h"

#include <daemon.h>
#include <config/child_cfg.h>

typedef struct private_ha_sync_plugin_t private_ha_sync_plugin_t;

/**
 * private data of ha_sync plugin
 */
struct private_ha_sync_plugin_t {

	/**
	 * implements plugin interface
	 */
	ha_sync_plugin_t public;

	/**
	 * Communication socket
	 */
	ha_sync_socket_t *socket;

	/**
	 * Tunnel securing sync messages.
	 */
	ha_sync_tunnel_t *tunnel;

	/**
	 * IKE_SA synchronization
	 */
	ha_sync_ike_t *ike;

	/**
	 * CHILD_SA synchronization
	 */
	ha_sync_child_t *child;

	/**
	 * Dispatcher to process incoming messages
	 */
	ha_sync_dispatcher_t *dispatcher;

	/**
	 * Active/Passive segment management
	 */
	ha_sync_segments_t *segments;

	/**
	 * Interface to control segments at kernel level
	 */
	ha_sync_kernel_t *kernel;

	/**
	 * Segment control interface via FIFO
	 */
	ha_sync_ctl_t *ctl;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_ha_sync_plugin_t *this)
{
	DESTROY_IF(this->ctl);
	charon->bus->remove_listener(charon->bus, &this->ike->listener);
	charon->bus->remove_listener(charon->bus, &this->child->listener);
	this->ike->destroy(this->ike);
	this->child->destroy(this->child);
	this->dispatcher->destroy(this->dispatcher);
	this->segments->destroy(this->segments);
	this->kernel->destroy(this->kernel);
	this->socket->destroy(this->socket);
	DESTROY_IF(this->tunnel);
	free(this);
}

/**
 * Convert segment string to mask
 */
static segment_mask_t parse_active(char *active)
{
	enumerator_t *enumerator;
	u_int segment;
	segment_mask_t mask = 0;

	enumerator = enumerator_create_token(active, ",", " ");
	while (enumerator->enumerate(enumerator, &active))
	{
		segment = atoi(active);
		if (segment > 0 && segment < SEGMENTS_MAX)
		{
			mask |= SEGMENTS_BIT(segment);
		}
	}
	enumerator->destroy(enumerator);

	return mask;
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_ha_sync_plugin_t *this;
	char *local, *remote, *secret, *external, *internal;
	segment_mask_t active;
	u_int count;
	bool fifo;

	local = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.local", NULL);
	remote = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.remote", NULL);
	external = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.external", NULL);
	internal = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.internal", NULL);
	secret = lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.secret", NULL);
	fifo = lib->settings->get_bool(lib->settings,
								"charon.plugins.ha_sync.fifo_interface", FALSE);
	count = min(SEGMENTS_MAX, lib->settings->get_int(lib->settings,
								"charon.plugins.ha_sync.segment_count", 1));
	active = parse_active(lib->settings->get_str(lib->settings,
								"charon.plugins.ha_sync.active_segments", "1"));
	if (!local || !remote)
	{
		DBG1(DBG_CFG, "HA sync config misses local/remote address");
		return NULL;
	}
	if (!external || !internal)
	{
		DBG1(DBG_CFG, "HA sync config misses external/internal virtual address");
		return NULL;
	}

	this = malloc_thing(private_ha_sync_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	this->tunnel = NULL;
	this->ctl = NULL;

	this->socket = ha_sync_socket_create(local, remote);
	if (!this->socket)
	{
		free(this);
		return NULL;
	}
	this->kernel = ha_sync_kernel_create(count, active, external, internal);
	if (!this->kernel)
	{
		this->socket->destroy(this->socket);
		free(this);
		return NULL;
	}

	this->segments = ha_sync_segments_create(this->socket, this->kernel,
											 count, active);
	if (secret)
	{
		this->tunnel = ha_sync_tunnel_create(secret, local, remote);
	}
	if (fifo)
	{
		this->ctl = ha_sync_ctl_create(this->segments);
	}
	this->dispatcher = ha_sync_dispatcher_create(this->socket, this->segments);
	this->ike = ha_sync_ike_create(this->socket, this->tunnel);
	this->child = ha_sync_child_create(this->socket, this->tunnel);
	charon->bus->add_listener(charon->bus, &this->ike->listener);
	charon->bus->add_listener(charon->bus, &this->child->listener);

	return &this->public.plugin;
}

