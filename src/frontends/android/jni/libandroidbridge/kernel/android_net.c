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
#include <utils/debug.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

typedef struct private_kernel_android_net_t private_kernel_android_net_t;

struct private_kernel_android_net_t {

	/**
	 * Public kernel interface
	 */
	kernel_android_net_t public;

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
static void connectivity_cb(private_kernel_android_net_t *this,
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

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_android_net_t *this, host_t *dest, host_t *src)
{
	return this->network_manager->get_local_address(this->network_manager,
											dest->get_family(dest) == AF_INET);
}

METHOD(kernel_net_t, get_interface, bool,
	private_kernel_android_net_t *this, host_t *host, char **name)
{
	return this->network_manager->get_interface(this->network_manager, host,
												name);
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_android_net_t *this, host_t *virtual_ip, int prefix,
	char *iface)
{
	/* we get the IP from the IKE_SA once the CHILD_SA is established */
	return SUCCESS;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_android_net_t *this)
{
	this->network_manager->remove_connectivity_cb(this->network_manager,
												 (void*)connectivity_cb);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_android_net_t *kernel_android_net_create()
{
	private_kernel_android_net_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_source_addr = _get_source_addr,
				.get_nexthop = (void*)return_null,
				.get_interface = _get_interface,
				.create_address_enumerator = (void*)enumerator_create_empty,
				.add_ip = _add_ip,
				.del_ip = (void*)return_failed,
				.add_route = (void*)return_failed,
				.del_route = (void*)return_failed,
				.destroy = _destroy,
			},
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.network_manager = charonservice->get_network_manager(charonservice),
	);
	timerclear(&this->next_roam);

	this->network_manager->add_connectivity_cb(this->network_manager,
											  (void*)connectivity_cb, this);
	return &this->public;
};
