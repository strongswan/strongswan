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
#include "eap_radius_accounting.h"
#include "eap_radius_dae.h"
#include "eap_radius_forward.h"
#include "radius_client.h"
#include "radius_server.h"

#include <daemon.h>
#include <threading/rwlock.h>

/**
 * Default RADIUS server port for authentication
 */
#define AUTH_PORT 1812

/**
 * Default RADIUS server port for accounting
 */
#define ACCT_PORT 1813

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

	/**
	 * RADIUS sessions for accounting
	 */
	eap_radius_accounting_t *accounting;

	/**
	 * Dynamic authorization extensions
	 */
	eap_radius_dae_t *dae;

	/**
	 * RADIUS <-> IKE attribute forwarding
	 */
	eap_radius_forward_t *forward;
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
	int auth_port, acct_port, sockets, preference;

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
		auth_port = lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.port", AUTH_PORT);
		sockets = lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.sockets", 1);
		server = radius_server_create(address, address, auth_port, ACCT_PORT,
									  nas_identifier, secret, sockets, 0);
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
		auth_port = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.auth_port",
				lib->settings->get_int(lib->settings,
					"charon.plugins.eap-radius.servers.%s.port",
					AUTH_PORT, section),
			section);
		acct_port = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.acct_port", ACCT_PORT, section);
		sockets = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.sockets", 1, section);
		preference = lib->settings->get_int(lib->settings,
			"charon.plugins.eap-radius.servers.%s.preference", 0, section);
		server = radius_server_create(section, address, auth_port, acct_port,
								nas_identifier, secret, sockets, preference);
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

METHOD(plugin_t, get_features, int,
	eap_radius_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(eap_method_register, eap_radius_create),
			PLUGIN_PROVIDE(EAP_SERVER, EAP_RADIUS),
				PLUGIN_DEPENDS(HASHER, HASH_MD5),
				PLUGIN_DEPENDS(SIGNER, AUTH_HMAC_MD5_128),
				PLUGIN_DEPENDS(RNG, RNG_WEAK),
	};
	*features = f;
	return countof(f);
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
	if (this->forward)
	{
		charon->bus->remove_listener(charon->bus, &this->forward->listener);
		this->forward->destroy(this->forward);
	}
	DESTROY_IF(this->dae);
	this->servers->destroy_offset(this->servers,
								  offsetof(radius_server_t, destroy));
	this->lock->destroy(this->lock);
	charon->bus->remove_listener(charon->bus, &this->accounting->listener);
	this->accounting->destroy(this->accounting);
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
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.servers = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.accounting = eap_radius_accounting_create(),
		.forward = eap_radius_forward_create(),
	);

	load_servers(this);
	instance = this;

	if (lib->settings->get_bool(lib->settings,
						"charon.plugins.eap-radius.accounting", FALSE))
	{
		charon->bus->add_listener(charon->bus, &this->accounting->listener);
	}
	if (lib->settings->get_bool(lib->settings,
						"charon.plugins.eap-radius.dae.enable", FALSE))
	{
		this->dae = eap_radius_dae_create(this->accounting);
	}
	if (this->forward)
	{
		charon->bus->add_listener(charon->bus, &this->forward->listener);
	}

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

