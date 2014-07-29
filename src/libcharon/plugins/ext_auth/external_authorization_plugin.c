/*
Copyright (c) 2014 Vyronas Tsingaras (vtsingaras@it.auth.gr)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


#include "external_authorization_plugin.h"

#include "external_authorization_listener.h"

#include <daemon.h>

typedef struct private_external_authorization_plugin_t private_external_authorization_plugin_t;

/**
 * private data of external_authorization plugin
 */
struct private_external_authorization_plugin_t {

	/**
	 * implements plugin interface
	 */
	external_authorization_plugin_t public;

	/**
	 * Listener verifying peers during authorization
	 */
	external_authorization_listener_t *listener;

	/**
	 * Path to authorization program
	 */
	char *path;
};

METHOD(plugin_t, get_name, char*,
	private_external_authorization_plugin_t *this)
{
	return "external_authorization";
}

/**
 * Register listener
 */
static bool plugin_cb(private_external_authorization_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{	
	if (reg)
	{
		/* check if path is empty string or NULL */
		if(this->path == NULL || !strcmp(this->path, ""))
		{
			charon->bus->add_listener(charon->bus, &this->listener->listener);
		}
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_external_authorization_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "external_authorization"),
	};
	*features = f;
	return countof(f);
}

/**
 * Plugin constructor
 */
plugin_t *external_authorization_plugin_create()
{
	private_external_authorization_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
			},
		},
		.path = lib->settings->get_str(lib->settings, "%s.plugins.external-authorization.path", "", lib->ns),
		.listener = external_authorization_listener_create(this->path),
	);

	return &this->public.plugin;
}
