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

#include <daemon.h>
#include <processing/jobs/callback_job.h>

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
};

/**
 * Begin the load test
 */
static job_requeue_t do_load_test(private_load_tester_plugin_t *this)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg = NULL;;
	enumerator_t *enumerator;
	int iterations, i;
	
	iterations = lib->settings->get_int(lib->settings,
							"charon.plugins.load_tester.iterations", 0);
	
	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  "load-test");
	if (peer_cfg)
	{
		enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		if (enumerator->enumerate(enumerator, &child_cfg))
		{
			child_cfg->get_ref(child_cfg);
		}
		enumerator->destroy(enumerator);
		
		if (child_cfg)
		{
			for (i = 0; i < iterations; i++)
			{
				charon->controller->initiate(charon->controller,
					peer_cfg->get_ref(peer_cfg), child_cfg->get_ref(child_cfg),
					NULL, NULL);
			}
			child_cfg->destroy(child_cfg);
		}
		peer_cfg->destroy(peer_cfg);
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_load_tester_plugin_t *this)
{
	charon->kernel_interface->remove_ipsec_interface(charon->kernel_interface,
						(kernel_ipsec_constructor_t)load_tester_ipsec_create);
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	charon->credentials->remove_set(charon->credentials, &this->creds->credential_set);
	this->config->destroy(this->config);
	this->creds->destroy(this->creds);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	int initiators;
	private_load_tester_plugin_t *this = malloc_thing(private_load_tester_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->config = load_tester_config_create();
	this->creds = load_tester_creds_create();
	charon->backends->add_backend(charon->backends, &this->config->backend);
	charon->credentials->add_set(charon->credentials, &this->creds->credential_set);
	
	if (lib->settings->get_bool(lib->settings,
								"charon.plugins.load_tester.fake_kernel", FALSE))
	{
		charon->kernel_interface->add_ipsec_interface(charon->kernel_interface, 
						(kernel_ipsec_constructor_t)load_tester_ipsec_create);
	}
	initiators = lib->settings->get_int(lib->settings,
						"charon.plugins.load_tester.initiators", 1);
	while (initiators-- > 0)
	{
		charon->processor->queue_job(charon->processor, 
					(job_t*)callback_job_create((callback_job_cb_t)do_load_test,
												this, NULL, NULL));
	}
	return &this->public.plugin;
}

