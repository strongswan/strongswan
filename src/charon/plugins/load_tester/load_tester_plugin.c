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
 *
 * $Id$
 */

#include "load_tester_plugin.h"
#include "load_tester_config.h"
#include "load_tester_creds.h"
#include "load_tester_ipsec.h"
#include "load_tester_listener.h"
#include "load_tester_diffie_hellman.h"

#include <unistd.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>
#include <utils/mutex.h>

typedef struct private_load_tester_plugin_t private_load_tester_plugin_t;

/**
 * private data of load_tester plugin
 */
struct private_load_tester_plugin_t {

	/**
	 * implements plugin interface
	 */
	load_tester_plugin_t public;
	
	/**
	 * load_tester configuration backend
	 */
	load_tester_config_t *config;
	
	/**
	 * load_tester credential set implementation
	 */
	load_tester_creds_t *creds;
	
	/**
	 * event handler, listens on bus
	 */
	load_tester_listener_t *listener;
	
	/**
	 * number of iterations per thread
	 */
	int iterations;
	
	/**
	 * number desired initiator threads
	 */
	int initiators;
	
	/**
	 * currenly running initiators
	 */
	int running;
	
	/**
	 * delay between initiations, in ms
	 */
	int delay;
	
	/**
	 * mutex to lock running field
	 */
	mutex_t *mutex;
	
	/**
	 * condvar to wait for initiators
	 */
	condvar_t *condvar;
};

/**
 * Begin the load test
 */
static job_requeue_t do_load_test(private_load_tester_plugin_t *this)
{
	int i, s = 0, ms = 0;
	
	this->mutex->lock(this->mutex);
	if (!this->running)
	{
		this->running = this->initiators;
	}
	this->mutex->unlock(this->mutex);
	if (this->delay)
	{
		s = this->delay / 1000;
		ms = this->delay % 1000;
	}
	
	for (i = 0; this->iterations == 0 || i < this->iterations; i++)
	{
		peer_cfg_t *peer_cfg;
		child_cfg_t *child_cfg = NULL;
		enumerator_t *enumerator;
	
		peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
														  "load-test");
		if (!peer_cfg)
		{
			break;
		}
		enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		if (!enumerator->enumerate(enumerator, &child_cfg))
		{
			enumerator->destroy(enumerator);
			break;
		}
		enumerator->destroy(enumerator);
		
		charon->controller->initiate(charon->controller,
					peer_cfg, child_cfg->get_ref(child_cfg),
					NULL, NULL);
		if (s)
		{
			sleep(s);
		}
		if (ms)
		{
			usleep(ms * 1000);
		}
	}
	this->mutex->lock(this->mutex);
	this->running--;
	this->mutex->unlock(this->mutex);
	this->condvar->signal(this->condvar);
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_load_tester_plugin_t *this)
{
	this->iterations = -1;
	this->mutex->lock(this->mutex);
	while (this->running)
	{
		this->condvar->wait(this->condvar, this->mutex);
	}
	this->mutex->unlock(this->mutex);
	charon->kernel_interface->remove_ipsec_interface(charon->kernel_interface,
						(kernel_ipsec_constructor_t)load_tester_ipsec_create);
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	charon->credentials->remove_set(charon->credentials, &this->creds->credential_set);
	charon->bus->remove_listener(charon->bus, &this->listener->listener);
	this->config->destroy(this->config);
	this->creds->destroy(this->creds);
	this->listener->destroy(this->listener);
	lib->crypto->remove_dh(lib->crypto,
						(dh_constructor_t)load_tester_diffie_hellman_create);
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_load_tester_plugin_t *this;
	u_int i, shutdown_on = 0;
	
	if (!lib->settings->get_bool(lib->settings,
								 "charon.plugins.load_tester.enable", FALSE))
	{
		DBG1(DBG_CFG, "disabling load-tester plugin, not configured");
		return NULL;
	}
	
	this = malloc_thing(private_load_tester_plugin_t);
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_dh(lib->crypto, MODP_NULL, 
						(dh_constructor_t)load_tester_diffie_hellman_create);
	
	this->delay = lib->settings->get_int(lib->settings,
					"charon.plugins.load_tester.delay", 0);
	this->iterations = lib->settings->get_int(lib->settings,
					"charon.plugins.load_tester.iterations", 1);
	this->initiators = lib->settings->get_int(lib->settings,
					"charon.plugins.load_tester.initiators", 0);
	if (lib->settings->get_bool(lib->settings,
					"charon.plugins.load_tester.shutdown_when_complete", 0))
	{
		shutdown_on = this->iterations * this->initiators;
	}
	
	this->mutex = mutex_create(MUTEX_DEFAULT);
	this->condvar = condvar_create(CONDVAR_DEFAULT);
	this->config = load_tester_config_create();
	this->creds = load_tester_creds_create();
	this->listener = load_tester_listener_create(shutdown_on);
	charon->backends->add_backend(charon->backends, &this->config->backend);
	charon->credentials->add_set(charon->credentials, &this->creds->credential_set);
	charon->bus->add_listener(charon->bus, &this->listener->listener);
	
	if (lib->settings->get_bool(lib->settings,
					"charon.plugins.load_tester.fake_kernel", FALSE))
	{
		charon->kernel_interface->add_ipsec_interface(charon->kernel_interface, 
						(kernel_ipsec_constructor_t)load_tester_ipsec_create);
	}
	this->running = 0;
	for (i = 0; i < this->initiators; i++)
	{
		charon->processor->queue_job(charon->processor, 
					(job_t*)callback_job_create((callback_job_cb_t)do_load_test,
												this, NULL, NULL));
	}
	return &this->public.plugin;
}

