/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <glib.h>
#include <libosso.h>

#include "maemo_plugin.h"

#include <daemon.h>
#include <processing/jobs/callback_job.h>

#define OSSO_CHARON_NAME	"charon"
#define OSSO_CHARON_SERVICE	"org.strongswan."OSSO_CHARON_NAME
#define OSSO_CHARON_OBJECT	"/org/strongswan/"OSSO_CHARON_NAME
#define OSSO_CHARON_IFACE	"org.strongswan."OSSO_CHARON_NAME

typedef struct private_maemo_plugin_t private_maemo_plugin_t;

/**
 * private data of maemo plugin
 */
struct private_maemo_plugin_t {

	/**
	 * implements plugin interface
	 */
	maemo_plugin_t public;

	/**
	 * Glib main loop for a thread, handles DBUS calls
	 */
	GMainLoop *loop;

	/**
	 * Context for OSSO
	 */
	osso_context_t *context;

};

/**
 * Callback for libosso dbus wrapper
 */
static gint dbus_req_handler(const gchar *interface, const gchar *method,
							 GArray *arguments, private_maemo_plugin_t *this,
							 osso_rpc_t *retval)
{
	return OSSO_OK;
}

/**
 * Main loop to handle D-BUS messages.
 */
static job_requeue_t run(private_maemo_plugin_t *this)
{
	this->loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(this->loop);
	return JOB_REQUEUE_NONE;
}

METHOD(plugin_t, destroy, void,
	   private_maemo_plugin_t *this)
{
	if (this->loop)
	{
		if (g_main_loop_is_running(this->loop))
		{
			g_main_loop_quit(this->loop);
		}
		g_main_loop_unref(this->loop);
	}
	if (this->context)
	{
		osso_deinitialize(this->context);
	}
	free(this);
}

/*
 * See header
 */
plugin_t *maemo_plugin_create()
{
	osso_return_t result;
	private_maemo_plugin_t *this;

	INIT(this,
		.public.plugin = {
			.destroy = _destroy,
		},
	);

	this->context = osso_initialize(OSSO_CHARON_SERVICE, "0.0.1", TRUE, NULL);
	if (!this->context)
	{
		DBG1(DBG_CFG, "failed to initialize OSSO context");
		destroy(this);
		return NULL;
	}

	result = osso_rpc_set_cb_f(this->context,
							   OSSO_CHARON_SERVICE,
							   OSSO_CHARON_OBJECT,
							   OSSO_CHARON_IFACE,
							   (osso_rpc_cb_f*)dbus_req_handler,
							   this);
	if (result != OSSO_OK)
	{
		DBG1(DBG_CFG, "failed to set D-BUS callback (%d)", result);
		destroy(this);
		return NULL;
	}

	this->loop = NULL;
	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)run, this, NULL, NULL));

	return &this->public.plugin;
}

