/*
 * Copyright (C) 2012-2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "android_net.h"

#include "../android_jni.h"
#include "../charonservice.h"
#include <daemon.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>

/** delay before firing roam events (ms) */
#define ROAM_DELAY 500
#define ROAM_DELAY_RECHECK 1000

typedef struct private_android_net_t private_android_net_t;

struct private_android_net_t {

	/**
	 * Public kernel interface
	 */
	kernel_net_t public;

	/**
	 * Reference to NetworkManager object
	 */
	network_manager_t *network_manager;

	/**
	 * Earliest time of the next roam event
	 */
	timeval_t next_roam;

	/**
	 * Whether a roam event job is currently scheduled
	 */
	bool roam_scheduled;

	/**
	 * Mutex to check and update roam event time, and other private members
	 */
	mutex_t *mutex;

	/**
	 * List of virtual IPs
	 */
	linked_list_t *vips;

	/**
	 * Whether the device is currently connected
	 */
	bool connected;
};

/**
 * callback function that raises the delayed roam event
 */
CALLBACK(roam_event, job_requeue_t,
	private_android_net_t *this)
{
	timeval_t now, diff;

	time_monotonic(&now);
	this->mutex->lock(this->mutex);
	if (timercmp(&now, &this->next_roam, <))
	{
		/* another event got triggered in the meantime, reschedule */
		timersub(&this->next_roam, &now, &diff);
		this->mutex->unlock(this->mutex);
		return JOB_RESCHEDULE_MS(diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}
	this->roam_scheduled = FALSE;
	this->mutex->unlock(this->mutex);

	/* this will fail if no connection is up */
	charonservice->bypass_socket(charonservice, -1, FALSE);
	charon->kernel->roam(charon->kernel, TRUE);
	return JOB_REQUEUE_NONE;
}

/**
 * Schedule a roam event after the given delay in ms. The mutex must be locked
 * when calling this, it is unlocked automatically.
 */
static void schedule_roam_unlock(private_android_net_t *this, u_int delay)
{
	timeval_t now, next, diff;
	job_t *job;
	u_int schedule = 0;

	time_monotonic(&now);
	next = now;
	timeval_add_ms(&next, delay);
	if (timercmp(&next, &this->next_roam, >))
	{	/* only ever increase the target time */
		this->next_roam = next;
	}
	if (!this->roam_scheduled)
	{
		timersub(&this->next_roam, &now, &diff);
		schedule = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		this->roam_scheduled = schedule > 0;
	}
	this->mutex->unlock(this->mutex);

	if (schedule)
	{
		job = (job_t*)callback_job_create(roam_event, this, NULL, NULL);
		lib->scheduler->schedule_job_ms(lib->scheduler, job, schedule);
	}
}

/**
 * Listen for connectivity change events and queue a roam event
 */
static void connectivity_cb(private_android_net_t *this,
							bool disconnected)
{
	this->mutex->lock(this->mutex);
	this->connected = !disconnected;
	schedule_roam_unlock(this, ROAM_DELAY);
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_android_net_t *this, host_t *dst, host_t *src)
{
	union {
		struct sockaddr sockaddr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr = {};
	socklen_t addrlen = *dst->get_sockaddr_len(dst);
	host_t *host = NULL;
	int skt;

	skt = socket(dst->get_family(dst), SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0)
	{
		DBG1(DBG_KNL, "failed to create socket to lookup src addresses: %s",
			 strerror(errno));
		return NULL;
	}
	charonservice->bypass_socket(charonservice, skt, FALSE);

	if (connect(skt, dst->get_sockaddr(dst), addrlen) < 0)
	{
		/* don't report an error if we are not connected (ENETUNREACH) */
		if (errno != ENETUNREACH)
		{
			DBG1(DBG_KNL, "failed to connect socket: %s", strerror(errno));
		}
		else
		{
			this->mutex->lock(this->mutex);
			if (this->connected)
			{
				/* we were not able to find a source address but reportedly are
				 * connected, trigger a recheck in case an IP address appears
				 * delayed but the callback is not triggered again */
				schedule_roam_unlock(this, ROAM_DELAY_RECHECK);
			}
			else
			{
				this->mutex->unlock(this->mutex);
			}
		}
	}
	else if (getsockname(skt, &addr.sockaddr, &addrlen) < 0)
	{
		DBG1(DBG_KNL, "failed to determine src address: %s", strerror(errno));
	}
	else
	{
		host = host_create_from_sockaddr((sockaddr_t*)&addr);
	}
	close(skt);
	return host;
}

CALLBACK(vip_equals, bool,
	host_t *vip, va_list args)
{
	host_t *host;

	VA_ARGS_VGET(args, host);
	return host->ip_equals(host, vip);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_android_net_t *this, host_t *dest, int prefix, host_t *src,
	char **iface)
{
	return NULL;
}

METHOD(kernel_net_t, get_interface, bool,
	private_android_net_t *this, host_t *host, char **name)
{
	if (name)
	{	/* the actual name does not matter in our case */
		*name = strdup("strongswan");
	}
	return TRUE;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_android_net_t *this, kernel_address_type_t which)
{
	/* return virtual IPs if requested, nothing otherwise */
	if (which & ADDR_TYPE_VIRTUAL)
	{
		this->mutex->lock(this->mutex);
		return enumerator_create_cleaner(
					this->vips->create_enumerator(this->vips),
					(void*)this->mutex->unlock, this->mutex);
	}
	return enumerator_create_empty();
}

METHOD(kernel_net_t, add_ip, status_t,
	private_android_net_t *this, host_t *virtual_ip, int prefix, char *iface)
{
	this->mutex->lock(this->mutex);
	this->vips->insert_last(this->vips, virtual_ip->clone(virtual_ip));
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_android_net_t *this, host_t *virtual_ip, int prefix, bool wait)
{
	host_t *vip;

	this->mutex->lock(this->mutex);
	if (this->vips->find_first(this->vips, vip_equals, (void**)&vip,
							   virtual_ip))
	{
		this->vips->remove(this->vips, vip, NULL);
		vip->destroy(vip);
	}
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(kernel_net_t, add_route, status_t,
	private_android_net_t *this, chunk_t dst_net, uint8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name, bool pass)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_route, status_t,
	private_android_net_t *this, chunk_t dst_net, uint8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name, bool pass)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, destroy, void,
	private_android_net_t *this)
{
	this->network_manager->remove_connectivity_cb(this->network_manager,
												 (void*)connectivity_cb);
	this->mutex->destroy(this->mutex);
	this->vips->destroy(this->vips);
	free(this);
}

kernel_net_t *kernel_android_net_create()
{
	private_android_net_t *this;

	INIT(this,
		.public = {
			.get_source_addr = _get_source_addr,
			.get_nexthop = _get_nexthop,
			.get_interface = _get_interface,
			.create_address_enumerator = _create_address_enumerator,
			.add_ip = _add_ip,
			.del_ip = _del_ip,
			.add_route = _add_route,
			.del_route = _del_route,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.vips = linked_list_create(),
		.network_manager = charonservice->get_network_manager(charonservice),
	);
	timerclear(&this->next_roam);

	this->mutex->lock(this->mutex);
	this->network_manager->add_connectivity_cb(
						this->network_manager, (void*)connectivity_cb, this);
	this->connected = this->network_manager->is_connected(this->network_manager);
	this->mutex->unlock(this->mutex);
	return &this->public;
}
