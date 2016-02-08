/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>
 *
 * Copyright (C) 2013 Tobias Brunner
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

/*
 * Copyright (C) 2015 Thom Troy
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

#include "quota_plugin.h"

#include <daemon.h>
#include <threading/rwlock.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/delete_ike_sa_job.h>

#include "quota_accounting.h"
#include "quota_invoke.h"

typedef struct private_quota_plugin_t private_quota_plugin_t;

/**
 * Private data of an quota_plugin_t object.
 */
struct private_quota_plugin_t {

	/**
	 * Public quota_plugin_t interface.
	 */
	quota_plugin_t public;

	/**
	 * Lock for configs list
	 */
	rwlock_t *lock;

	/**
	 * quota sessions for accounting
	 */
	quota_accounting_t *accounting;
};

/**
 * Instance of the quota plugin
 */
static private_quota_plugin_t *instance = NULL;

/**
 * Load quota settings from configuration
 */
static void load_config(private_quota_plugin_t *this)
{
	char *script;
	bool acct;

	script = lib->settings->get_str(lib->settings, "%s.plugins.quota.script", NULL, lib->ns);
	acct = lib->settings->get_bool(lib->settings, "%s.plugins.quota.accounting", NULL, lib->ns);

	if (!script)
	{
		DBG1(DBG_CFG, "no script for quota plugin defined, disabled");
		return;
	}

	DBG1(DBG_CFG, "loaded quota plugin. accounting %s. script: %s", acct ? "enabled" : "disabled", script);
}

METHOD(plugin_t, get_name, char*,
	private_quota_plugin_t *this)
{
	return "quota";
}

/**
 * Register listener
 */
static bool plugin_cb(private_quota_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		load_config(this);
		this->accounting = quota_accounting_create();
	}
	else
	{
		this->accounting->destroy(this->accounting);

	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
		private_quota_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "quota"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
		private_quota_plugin_t *this)
{
	this->lock->write_lock(this->lock);
	load_config(this);
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(plugin_t, destroy, void,
		private_quota_plugin_t *this)
{
	this->lock->destroy(this->lock);
	free(this);
	instance = NULL;
}

/*
 * see header file
 */
plugin_t *quota_plugin_create()
{
	private_quota_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);
	instance = this;

	return &this->public.plugin;
}
