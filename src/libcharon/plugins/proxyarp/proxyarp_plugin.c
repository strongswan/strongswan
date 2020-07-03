/*
 * Copyright (C) 2008 Martin Willi
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

/*
 * Copyright (C) 2020 Dan James
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Based on strongswan/src/libcharon/plugins/updown for the plugin structure,
 * and PPPd (https://opensource.apple.com/source/ppp/ppp-862) for the
 * interface scanning and route table updates.
 */

#include "proxyarp_plugin.h"
#include "proxyarp_listener.h"

#include <daemon.h>

typedef struct private_proxyarp_plugin_t private_proxyarp_plugin_t;

/**
 * private data of proxyarp plugin
 */
struct private_proxyarp_plugin_t {
	/**
	 * implements plugin interface
	 */
	proxyarp_plugin_t public;

	/**
	 * Listener interface, listens to CHILD_SA state changes
	 */
	proxyarp_listener_t *listener;
};

METHOD(plugin_t, get_name, char*, private_proxyarp_plugin_t *this)
{
	return "proxyarp";
}

/**
 * Register listener
 */
static bool plugin_cb(private_proxyarp_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg) {
		this->listener = proxyarp_listener_create();
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	} else {
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
		this->listener->destroy(this->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int, private_proxyarp_plugin_t *this,
	   plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
			PLUGIN_CALLBACK((plugin_feature_callback_t) plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "proxyarp")
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void, private_proxyarp_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *proxyarp_plugin_create()
{
	private_proxyarp_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy
			}
		}
	);

	return &this->public.plugin;
}
