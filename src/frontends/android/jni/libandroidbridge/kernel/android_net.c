/*
 * Copyright (C) 2012-2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.  *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "android_net.h"

#include "../charonservice.h"
#include <hydra.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

typedef struct private_android_net_t private_android_net_t;

struct private_android_net_t {

	/**
	 * Public kernel interface
	 */
	android_net_t public;

	/**
	 * Reference to NetworkManager object
	 */
	network_manager_t *network_manager;

	/**
	 * earliest time of the next roam event
	 */
	timeval_t next_roam;

	/**
	 * mutex to check and update roam event time
	 */
	mutex_t *mutex;
};

/**
 * callback function that raises the delayed roam event
 */
static job_requeue_t roam_event()
{
	/* this will fail if no connection is up */
	charonservice->bypass_socket(charonservice, -1, 0);
	hydra->kernel_interface->roam(hydra->kernel_interface, TRUE);
	return JOB_REQUEUE_NONE;
}

/**
 * Listen for connectivity change events and queue a roam event
 */
static void connectivity_cb(private_android_net_t *this,
							bool disconnected)
{
	timeval_t now;
	job_t *job;

	time_monotonic(&now);
	this->mutex->lock(this->mutex);
	if (!timercmp(&now, &this->next_roam, >))
	{
		this->mutex->unlock(this->mutex);
		return;
	}
	timeval_add_ms(&now, ROAM_DELAY);
	this->next_roam = now;
	this->mutex->unlock(this->mutex);

	job = (job_t*)callback_job_create((callback_job_cb_t)roam_event, NULL,
									   NULL, NULL);
	lib->scheduler->schedule_job_ms(lib->scheduler, job, ROAM_DELAY);
}

METHOD(android_net_t, destroy, void,
	private_android_net_t *this)
{
	this->network_manager->remove_connectivity_cb(this->network_manager,
												 (void*)connectivity_cb);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
android_net_t *android_net_create()
{
	private_android_net_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.network_manager = charonservice->get_network_manager(charonservice),
	);
	timerclear(&this->next_roam);

	this->network_manager->add_connectivity_cb(this->network_manager,
											  (void*)connectivity_cb, this);
	return &this->public;
};
