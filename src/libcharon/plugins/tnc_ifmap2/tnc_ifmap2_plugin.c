/*
 * Copyright (C) 2011-2013 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_ifmap2_plugin.h"
#include "tnc_ifmap2_listener.h"

#include <daemon.h>
 
typedef struct private_tnc_ifmap2_plugin_t private_tnc_ifmap2_plugin_t;

/**
 * private data of tnc_ifmap2 plugin
 */
struct private_tnc_ifmap2_plugin_t {

	/**
	 * implements plugin interface
	 */
	tnc_ifmap2_plugin_t public;

	/**
	 * Listener interface, listens to CHILD_SA state changes
	 */
	tnc_ifmap2_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
	private_tnc_ifmap2_plugin_t *this)
{
	return "tnc-ifmap2";
}

/**
 * Register tnc_ifmap2 plugin features
 */
static bool register_tnc_ifmap2(private_tnc_ifmap2_plugin_t *this,
								plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		this->listener = tnc_ifmap2_listener_create(FALSE);
		if (!this->listener)
		{
			return FALSE;
		}
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		if (this->listener)
		{
			charon->bus->remove_listener(charon->bus, &this->listener->listener);
			this->listener->destroy(this->listener);
		}
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	tnc_ifmap2_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)register_tnc_ifmap2, NULL),
			PLUGIN_PROVIDE(CUSTOM, "tnc-ifmap-2.1"),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_X509),
				PLUGIN_SDEPEND(PRIVKEY, KEY_RSA),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_tnc_ifmap2_plugin_t *this)
{
	if (this->listener)
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
		this->listener->destroy(this->listener);
	}

	this->listener = tnc_ifmap2_listener_create(TRUE);
	if (!this->listener)
	{
		return FALSE;
	}
	charon->bus->add_listener(charon->bus, &this->listener->listener);

	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_tnc_ifmap2_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_ifmap2_plugin_create()
{
	private_tnc_ifmap2_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

