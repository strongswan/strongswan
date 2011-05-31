/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "nm_plugin.h"
#include "nm_service.h"
#include "nm_creds.h"
#include "nm_handler.h"

#include <hydra.h>
#include <daemon.h>
#include <processing/jobs/callback_job.h>

#define CAP_DAC_OVERRIDE 1

typedef struct private_nm_plugin_t private_nm_plugin_t;

/**
 * private data of nm plugin
 */
struct private_nm_plugin_t {

	/**
	 * implements plugin interface
	 */
	nm_plugin_t public;

	/**
	 * NetworkManager service (VPNPlugin)
	 */
	NMStrongswanPlugin *plugin;

	/**
	 * Glib main loop for a thread, handles DBUS calls
	 */
	GMainLoop *loop;

	/**
	 * credential set registered at the daemon
	 */
	nm_creds_t *creds;

	/**
	 * attribute handler regeisterd at the daemon
	 */
	nm_handler_t *handler;
};

/**
 * NM plugin processing routine, creates and handles NMVPNPlugin
 */
static job_requeue_t run(private_nm_plugin_t *this)
{
	this->loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(this->loop);
	return JOB_REQUEUE_NONE;
}

METHOD(plugin_t, get_name, char*,
	private_nm_plugin_t *this)
{
	return "nm";
}

METHOD(plugin_t, destroy, void,
	private_nm_plugin_t *this)
{
	if (this->loop)
	{
		if (g_main_loop_is_running(this->loop))
		{
			g_main_loop_quit(this->loop);
		}
		g_main_loop_unref(this->loop);
	}
	if (this->plugin)
	{
		g_object_unref(this->plugin);
	}
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	hydra->attributes->remove_handler(hydra->attributes, &this->handler->handler);
	this->creds->destroy(this->creds);
	this->handler->destroy(this->handler);
	free(this);
}

/*
 * see header file
 */
plugin_t *nm_plugin_create()
{
	private_nm_plugin_t *this;

	g_type_init ();
	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.creds = nm_creds_create(),
		.handler = nm_handler_create(),
	);
	this->plugin = nm_strongswan_plugin_new(this->creds, this->handler);

	hydra->attributes->add_handler(hydra->attributes, &this->handler->handler);
	lib->credmgr->add_set(lib->credmgr, &this->creds->set);
	if (!this->plugin)
	{
		DBG1(DBG_CFG, "DBUS binding failed");
		destroy(this);
		return NULL;
	}

	/* bypass file permissions to read from users ssh-agent */
	charon->keep_cap(charon, CAP_DAC_OVERRIDE);

	lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio((callback_job_cb_t)run,
										this, NULL, NULL, JOB_PRIO_CRITICAL));

	return &this->public.plugin;
}

