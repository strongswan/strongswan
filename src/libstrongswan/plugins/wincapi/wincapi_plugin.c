/*
 * Copyright (C) 2018 Robert de la Rey, Francois ten Krooden
 * Copyright (C) 2018 Nanoteq (Pty) Ltd.
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

#include "wincapi_plugin.h"

#include <library.h>
#include <processing/jobs/callback_job.h>
#include <credentials/credential_manager.h>
#include <utils/chunk.h>

#include "wincapi_private_key.h"

typedef struct private_wincapi_plugin_t private_wincapi_plugin_t;


/**
 * private data of wincapi_plugin
 */
struct private_wincapi_plugin_t
{
	/**
	 * public functions
	 */
	wincapi_plugin_t public;
};


METHOD(plugin_t, get_name, char*,
		private_wincapi_plugin_t *this)
{
	return "wincapi";
}


METHOD(plugin_t, get_features, int,
		private_wincapi_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] =
			{
				PLUGIN_REGISTER(PRIVKEY, wincapi_private_key_get, TRUE),
				PLUGIN_PROVIDE(PRIVKEY, KEY_ANY),
		};
	*features = f;
	return countof(f);
}


METHOD(plugin_t, destroy, void,
		private_wincapi_plugin_t *this)
{
	free(this);
}


plugin_t *wincapi_plugin_create()
{
	private_wincapi_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
