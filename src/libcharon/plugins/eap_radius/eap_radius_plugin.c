/*
 * Copyright (C) 2009 Martin Willi
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

#include "eap_radius_plugin.h"

#include "eap_radius.h"
#include "radius_client.h"
#include "radius_server.h"

#include <daemon.h>
#include <threading/rwlock.h>

/**
 * Default RADIUS server port, when not configured
 */
#define RADIUS_PORT 1812

typedef struct private_eap_radius_plugin_t private_eap_radius_plugin_t;

/**
 * Private data of an eap_radius_plugin_t object.
 */
struct private_eap_radius_plugin_t {

	/**
	 * Public radius_plugin_t interface.
	 */
	eap_radius_plugin_t public;

	/**
	 * List of RADIUS servers
	 */
	linked_list_t *servers;

	/**
	 * Lock for server list
	 */
	rwlock_t *lock;
};

/**
 * Instance of the EAP plugin
 */
static private_eap_radius_plugin_t *instance = NULL;

/**
 * Load RADIUS servers from configuration
 */
static void load_servers(private_eap_radius_plugin_t *this)
{
	enumerator_t *enumerator;
	radius_server_t *server;
	char *nas_identifier, *secret, *address, *section;
	int port, sockets, preference;

	address = lib->settings->get_str(lib->settings,
					"charon.plugins.eap-radius.server", NULL);
	if (address)
	{	/* legacy configuration */
		secret = lib->settings->get_str(lib->settings,
					"charon.plugins.eap-radius.secret", NULL);
		if (!secret)
		{
			DBG1(DBG_CFG, "no RADUIS secret defined");
			return;
		}
		nas_identifier = lib->settings->get_str(lib->settings,
					"charon.plugins.eap-radius.nas_identifier", "strongSwan");
		port = lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.port", RADIUS_PORT);
		sockets = lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.sockets", 1);
		server = radius_server_create(address, address, port, nas_identifier,
									  secret, sockets, 0);
		if (!server)
		{
			DBG1(DBG_CFG, "no RADUIS server defined");
			return;
		}
		this->servers->insert_last(this->servers, server);
		return;
	}

	enumerator = lib->settings->create_section_enumerator(lib->settings,
										"charon.plugins.eap-radius.servers");
	while (enumerator->enumerate(enumerator, &section))
	{
		address = lib->settings->get_str(lib->settings,
			"charon.plugins.eap-radius.servers.%s.address", NULL, section);
		if (!address)
		{
			DBG1(DBG_CFG, "RADIUS server '%s' misses address, skipped", section);
			continue;
		}
		secret = lib->settings->get_str(lib->settings,
			"charon.plugins.eap-radius.servers.%s.secret", NULL, section);
		if (!secret)
		{
			DBG1(DBG_CFG, "RADIUS server '%s' misses secret, skipped", section);
			continue;
		}
		nas_identifier = lib->settings->get_str(lib->settings,
			"charon.plugins.eap-radius.servers.%s.nas_identifier",
			"strongSwan", section);
		port = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.port", RADIUS_PORT, section);
		sockets = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.sockets", 1, section);
		preference = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.preference", 0, section);
		server = radius_server_create(section, address, port, nas_identifier,
									  secret, sockets, preference);
		if (!server)
		{
			DBG1(DBG_CFG, "loading RADIUS server '%s' failed, skipped", section);
			continue;
		}
		this->servers->insert_last(this->servers, server);
	}
	enumerator->destroy(enumerator);

	DBG1(DBG_CFG, "loaded %d RADIUS server configuration%s",
		 this->servers->get_count(this->servers),
		 this->servers->get_count(this->servers) == 1 ? "" : "s");
}

METHOD(plugin_t, get_name, char*,
	private_eap_radius_plugin_t *this)
{
	return "eap-radius";
}

METHOD(plugin_t, reload, bool,
	private_eap_radius_plugin_t *this)
{
	this->lock->write_lock(this->lock);
	this->servers->destroy_offset(this->servers,
								  offsetof(radius_server_t, destroy));
	this->servers = linked_list_create();
	load_servers(this);
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_eap_radius_plugin_t *this)
{
	charon->eap->remove_method(charon->eap, (eap_constructor_t)eap_radius_create);
	this->servers->destroy_offset(this->servers,
								  offsetof(radius_server_t, destroy));
	this->lock->destroy(this->lock);
	free(this);
	instance = NULL;
}

/*
 * see header file
 */
plugin_t *eap_radius_plugin_create()
{
	private_eap_radius_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.servers = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	load_servers(this);

	charon->eap->add_method(charon->eap, EAP_RADIUS, 0,
							EAP_SERVER, (eap_constructor_t)eap_radius_create);

	instance = this;

	return &this->public.plugin;
}

/**
 * See header
 */
enumerator_t *eap_radius_create_server_enumerator()
{
	if (instance)
	{
		instance->lock->read_lock(instance->lock);
		return enumerator_create_cleaner(
					instance->servers->create_enumerator(instance->servers),
					(void*)instance->lock->unlock, instance->lock);
	}
	return enumerator_create_empty();
}

