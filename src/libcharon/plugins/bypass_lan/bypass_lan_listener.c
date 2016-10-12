/*
 * Copyright (C) 2016 Tobias Brunner
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

#include "bypass_lan_listener.h"

#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>

#include <daemon.h>

typedef struct private_bypass_lan_listener_t private_bypass_lan_listener_t;

/**
 * Private data
 */
struct private_bypass_lan_listener_t {

	/**
	 * Public interface.
	 */
	bypass_lan_listener_t public;

	/**
	 * Currently installed bypass policies, bypass_policy_t*
	 */
	hashtable_t *policies;

	/**
	 * Mutex to access list of policies
	 */
	mutex_t *mutex;
};

/**
 * Data for bypass policies
 */
typedef struct {
	private_bypass_lan_listener_t *listener;
	host_t *net;
	uint8_t mask;
	char *iface;
	child_cfg_t *cfg;
} bypass_policy_t;

/**
 * Destroy a bypass policy
 */
static void bypass_policy_destroy(bypass_policy_t *this)
{
	traffic_selector_t *ts;

	if (this->cfg)
	{
		ts = traffic_selector_create_from_subnet(this->net->clone(this->net),
												 this->mask, 0, 0, 65535);
		DBG1(DBG_IKE, "uninstalling bypass policy for %R", ts);
		charon->shunts->uninstall(charon->shunts,
								  this->cfg->get_name(this->cfg));
		this->cfg->destroy(this->cfg);
		ts->destroy(ts);
	}
	this->net->destroy(this->net);
	free(this->iface);
	free(this);
}

/**
 * Hash a bypass policy
 */
static u_int policy_hash(bypass_policy_t *policy)
{
	return chunk_hash_inc(policy->net->get_address(policy->net),
						  chunk_hash(chunk_from_thing(policy->mask)));
}

/**
 * Compare bypass policy
 */
static bool policy_equals(bypass_policy_t *a, bypass_policy_t *b)
{
	return a->mask == b->mask && a->net->equals(a->net, b->net);
}

/**
 * Job updating bypass policies
 */
static job_requeue_t update_bypass(private_bypass_lan_listener_t *this)
{
	enumerator_t *enumerator;
	hashtable_t *seen;
	bypass_policy_t *found, *lookup;
	host_t *net;
	uint8_t mask;
	char *iface;

	seen = hashtable_create((hashtable_hash_t)policy_hash,
							(hashtable_equals_t)policy_equals, 4);

	this->mutex->lock(this->mutex);

	enumerator = charon->kernel->create_local_subnet_enumerator(charon->kernel);
	while (enumerator->enumerate(enumerator, &net, &mask, &iface))
	{
		INIT(lookup,
			.net = net->clone(net),
			.mask = mask,
			.iface = strdupnull(iface),
		);
		seen->put(seen, lookup, lookup);

		found = this->policies->get(this->policies, lookup);
		if (!found)
		{
			child_cfg_create_t child = {
				.mode = MODE_PASS,
				.interface = iface,
			};
			child_cfg_t *cfg;
			traffic_selector_t *ts;
			char name[128];

			ts = traffic_selector_create_from_subnet(net->clone(net), mask,
													 0, 0, 65535);
			snprintf(name, sizeof(name), "Bypass LAN %R [%s]", ts, iface ?: "");

			cfg = child_cfg_create(name, &child);
			cfg->add_traffic_selector(cfg, FALSE, ts->clone(ts));
			cfg->add_traffic_selector(cfg, TRUE, ts);
			charon->shunts->install(charon->shunts, cfg);
			DBG1(DBG_IKE, "installed bypass policy for %R", ts);

			INIT(found,
				.net = net->clone(net),
				.mask = mask,
				.iface = strdupnull(iface),
				.cfg = cfg,
			);
			this->policies->put(this->policies, found, found);
		}
	}
	enumerator->destroy(enumerator);

	enumerator = this->policies->create_enumerator(this->policies);
	while (enumerator->enumerate(enumerator, NULL, &lookup))
	{
		if (!seen->get(seen, lookup))
		{
			this->policies->remove_at(this->policies, enumerator);
			bypass_policy_destroy(lookup);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	seen->destroy_function(seen, (void*)bypass_policy_destroy);
	return JOB_REQUEUE_NONE;
}

METHOD(kernel_listener_t, roam, bool,
	private_bypass_lan_listener_t *this, bool address)
{
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)update_bypass, this,
									NULL, (callback_job_cancel_t)return_false));
	return TRUE;
}

METHOD(bypass_lan_listener_t, destroy, void,
	private_bypass_lan_listener_t *this)
{
	enumerator_t *enumerator;
	bypass_policy_t *policy;

	enumerator = this->policies->create_enumerator(this->policies);
	while (enumerator->enumerate(enumerator, NULL, &policy))
	{
		bypass_policy_destroy(policy);
	}
	enumerator->destroy(enumerator);
	this->policies->destroy(this->policies);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * See header
 */
bypass_lan_listener_t *bypass_lan_listener_create()
{
	private_bypass_lan_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.roam = _roam,
			},
			.destroy = _destroy,
		},
		.policies = hashtable_create((hashtable_hash_t)policy_hash,
									 (hashtable_equals_t)policy_equals, 4),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	/* FIXME: schedule this? */
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)update_bypass, this,
									NULL, (callback_job_cancel_t)return_false));
	return &this->public;
}
