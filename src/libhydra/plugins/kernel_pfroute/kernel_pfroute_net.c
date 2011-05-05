/*
 * Copyright (C) 2009 Tobias Brunner
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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/route.h>
#include <unistd.h>
#include <errno.h>

#include "kernel_pfroute_net.h"

#include <hydra.h>
#include <debug.h>
#include <utils/host.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>

#ifndef HAVE_STRUCT_SOCKADDR_SA_LEN
#error Cannot compile this plugin on systems where 'struct sockaddr' has no sa_len member.
#endif

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

/** buffer size for PF_ROUTE messages */
#define PFROUTE_BUFFER_SIZE 4096

typedef struct addr_entry_t addr_entry_t;

/**
 * IP address in an inface_entry_t
 */
struct addr_entry_t {

	/** The ip address */
	host_t *ip;

	/** virtual IP managed by us */
	bool virtual;

	/** Number of times this IP is used, if virtual */
	u_int refcount;
};

/**
 * destroy a addr_entry_t object
 */
static void addr_entry_destroy(addr_entry_t *this)
{
	this->ip->destroy(this->ip);
	free(this);
}

typedef struct iface_entry_t iface_entry_t;

/**
 * A network interface on this system, containing addr_entry_t's
 */
struct iface_entry_t {

	/** interface index */
	int ifindex;

	/** name of the interface */
	char ifname[IFNAMSIZ];

	/** interface flags, as in netdevice(7) SIOCGIFFLAGS */
	u_int flags;

	/** list of addresses as host_t */
	linked_list_t *addrs;
};

/**
 * destroy an interface entry
 */
static void iface_entry_destroy(iface_entry_t *this)
{
	this->addrs->destroy_function(this->addrs, (void*)addr_entry_destroy);
	free(this);
}


typedef struct private_kernel_pfroute_net_t private_kernel_pfroute_net_t;

/**
 * Private variables and functions of kernel_pfroute class.
 */
struct private_kernel_pfroute_net_t
{
	/**
	 * Public part of the kernel_pfroute_t object.
	 */
	kernel_pfroute_net_t public;

	/**
	 * mutex to lock access to various lists
	 */
	mutex_t *mutex;

	/**
	 * Cached list of interfaces and their addresses (iface_entry_t)
	 */
	linked_list_t *ifaces;

	/**
	 * job receiving PF_ROUTE events
	 */
	callback_job_t *job;

	/**
	 * mutex to lock access to the PF_ROUTE socket
	 */
	mutex_t *mutex_pfroute;

	/**
	 * PF_ROUTE socket to communicate with the kernel
	 */
	int socket;

	/**
	 * PF_ROUTE socket to receive events
	 */
	int socket_events;

	/**
	 * sequence number for messages sent to the kernel
	 */
	int seq;

	/**
	 * time of last roam event
	 */
	timeval_t last_roam;
};

/**
 * callback function that raises the delayed roam event
 */
static job_requeue_t roam_event(uintptr_t address)
{
	hydra->kernel_interface->roam(hydra->kernel_interface, address != 0);
	return JOB_REQUEUE_NONE;
}

/**
 * fire a roaming event. we delay it for a bit and fire only one event
 * for multiple calls. otherwise we would create too many events.
 */
static void fire_roam_event(private_kernel_pfroute_net_t *this, bool address)
{
	timeval_t now;
	job_t *job;

	time_monotonic(&now);
	if (timercmp(&now, &this->last_roam, >))
	{
		now.tv_usec += ROAM_DELAY * 1000;
		while (now.tv_usec > 1000000)
		{
			now.tv_sec++;
			now.tv_usec -= 1000000;
		}
		this->last_roam = now;

		job = (job_t*)callback_job_create((callback_job_cb_t)roam_event,
										  (void*)(uintptr_t)(address ? 1 : 0),
										  NULL, NULL);
		lib->scheduler->schedule_job_ms(lib->scheduler, job, ROAM_DELAY);
	}
}

/**
 * Process an RTM_*ADDR message from the kernel
 */
static void process_addr(private_kernel_pfroute_net_t *this,
						 struct rt_msghdr *msg)
{
	struct ifa_msghdr *ifa = (struct ifa_msghdr*)msg;
	sockaddr_t *sockaddr = (sockaddr_t*)(ifa + 1);
	host_t *host = NULL;
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	bool found = FALSE, changed = FALSE, roam = FALSE;
	int i;

	for (i = 1; i < (1 << RTAX_MAX); i <<= 1)
	{
		if (ifa->ifam_addrs & i)
		{
			if (RTA_IFA & i)
			{
				host = host_create_from_sockaddr(sockaddr);
				break;
			}
			sockaddr = (sockaddr_t*)((char*)sockaddr + sockaddr->sa_len);
		}
	}

	if (!host)
	{
		return;
	}

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (iface->ifindex == ifa->ifam_index)
		{
			addrs = iface->addrs->create_enumerator(iface->addrs);
			while (addrs->enumerate(addrs, &addr))
			{
				if (host->ip_equals(host, addr->ip))
				{
					found = TRUE;
					if (ifa->ifam_type == RTM_DELADDR)
					{
						iface->addrs->remove_at(iface->addrs, addrs);
						if (!addr->virtual)
						{
							changed = TRUE;
							DBG1(DBG_KNL, "%H disappeared from %s",
								 host, iface->ifname);
						}
						addr_entry_destroy(addr);
					}
					else if (ifa->ifam_type == RTM_NEWADDR && addr->virtual)
					{
						addr->refcount = 1;
					}
				}
			}
			addrs->destroy(addrs);

			if (!found && ifa->ifam_type == RTM_NEWADDR)
			{
				changed = TRUE;
				addr = malloc_thing(addr_entry_t);
				addr->ip = host->clone(host);
				addr->virtual = FALSE;
				addr->refcount = 1;
				iface->addrs->insert_last(iface->addrs, addr);
				DBG1(DBG_KNL, "%H appeared on %s", host, iface->ifname);
			}

			if (changed && (iface->flags & IFF_UP))
			{
				roam = TRUE;
			}
			break;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);
	host->destroy(host);

	if (roam)
	{
		fire_roam_event(this, TRUE);
	}
}

/**
 * Process an RTM_IFINFO message from the kernel
 */
static void process_link(private_kernel_pfroute_net_t *this,
						 struct rt_msghdr *hdr)
{
	struct if_msghdr *msg = (struct if_msghdr*)hdr;
	enumerator_t *enumerator;
	iface_entry_t *iface;
	bool roam = FALSE;

	if (msg->ifm_flags & IFF_LOOPBACK)
	{	/* ignore loopback interfaces */
		return;
	}

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &iface))
	{
		if (iface->ifindex == msg->ifm_index)
		{
			if (!(iface->flags & IFF_UP) && (msg->ifm_flags & IFF_UP))
			{
				roam = TRUE;
				DBG1(DBG_KNL, "interface %s activated", iface->ifname);
			}
			else if ((iface->flags & IFF_UP) && !(msg->ifm_flags & IFF_UP))
			{
				roam = TRUE;
				DBG1(DBG_KNL, "interface %s deactivated", iface->ifname);
			}
			iface->flags = msg->ifm_flags;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (roam)
	{
		fire_roam_event(this, TRUE);
	}
}

/**
 * Process an RTM_*ROUTE message from the kernel
 */
static void process_route(private_kernel_pfroute_net_t *this,
						  struct rt_msghdr *msg)
{

}

/**
 * Receives events from kernel
 */
static job_requeue_t receive_events(private_kernel_pfroute_net_t *this)
{
	unsigned char buf[PFROUTE_BUFFER_SIZE];
	struct rt_msghdr *msg = (struct rt_msghdr*)buf;
	int len;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	len = recvfrom(this->socket_events, buf, sizeof(buf), 0, NULL, 0);
	thread_cancelability(oldstate);

	if (len < 0)
	{
		switch (errno)
		{
			case EINTR:
				/* interrupted, try again */
				return JOB_REQUEUE_DIRECT;
			case EAGAIN:
				/* no data ready, select again */
				return JOB_REQUEUE_DIRECT;
			default:
				DBG1(DBG_KNL, "unable to receive from PF_ROUTE event socket");
				sleep(1);
				return JOB_REQUEUE_FAIR;
		}
	}

	if (len < sizeof(msg->rtm_msglen) || len < msg->rtm_msglen ||
		msg->rtm_version != RTM_VERSION)
	{
		DBG2(DBG_KNL, "received corrupted PF_ROUTE message");
		return JOB_REQUEUE_DIRECT;
	}

	switch (msg->rtm_type)
	{
		case RTM_NEWADDR:
		case RTM_DELADDR:
			process_addr(this, msg);
			break;
		case RTM_IFINFO:
		/*case RTM_IFANNOUNCE <- what about this*/
			process_link(this, msg);
			break;
		case RTM_ADD:
		case RTM_DELETE:
			process_route(this, msg);
		default:
			break;
	}

	return JOB_REQUEUE_DIRECT;
}


/** enumerator over addresses */
typedef struct {
	private_kernel_pfroute_net_t* this;
	/** whether to enumerate down interfaces */
	bool include_down_ifaces;
	/** whether to enumerate virtual ip addresses */
	bool include_virtual_ips;
} address_enumerator_t;

/**
 * cleanup function for address enumerator
 */
static void address_enumerator_destroy(address_enumerator_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter for addresses
 */
static bool filter_addresses(address_enumerator_t *data,
							 addr_entry_t** in, host_t** out)
{
	host_t *ip;
	if (!data->include_virtual_ips && (*in)->virtual)
	{   /* skip virtual interfaces added by us */
		return FALSE;
	}
	ip = (*in)->ip;
	if (ip->get_family(ip) == AF_INET6)
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ip->get_sockaddr(ip);
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
		{   /* skip addresses with a unusable scope */
			return FALSE;
		}
	}
	*out = ip;
	return TRUE;
}

/**
 * enumerator constructor for interfaces
 */
static enumerator_t *create_iface_enumerator(iface_entry_t *iface,
											 address_enumerator_t *data)
{
	return enumerator_create_filter(iface->addrs->create_enumerator(iface->addrs),
									(void*)filter_addresses, data, NULL);
}

/**
 * filter for interfaces
 */
static bool filter_interfaces(address_enumerator_t *data, iface_entry_t** in,
							  iface_entry_t** out)
{
	if (!data->include_down_ifaces && !((*in)->flags & IFF_UP))
	{   /* skip interfaces not up */
		return FALSE;
	}
	*out = *in;
	return TRUE;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_pfroute_net_t *this,
	bool include_down_ifaces, bool include_virtual_ips)
{
	address_enumerator_t *data = malloc_thing(address_enumerator_t);
	data->this = this;
	data->include_down_ifaces = include_down_ifaces;
	data->include_virtual_ips = include_virtual_ips;

	this->mutex->lock(this->mutex);
	return enumerator_create_nested(
				enumerator_create_filter(
					this->ifaces->create_enumerator(this->ifaces),
					(void*)filter_interfaces, data, NULL),
				(void*)create_iface_enumerator, data,
				(void*)address_enumerator_destroy);
}

METHOD(kernel_net_t, get_interface_name, char*,
	private_kernel_pfroute_net_t *this, host_t* ip)
{
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	char *name = NULL;

	DBG2(DBG_KNL, "getting interface name for %H", ip);

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, &addr))
		{
			if (ip->ip_equals(ip, addr->ip))
			{
				name = strdup(iface->ifname);
				break;
			}
		}
		addrs->destroy(addrs);
		if (name)
		{
			break;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);

	if (name)
	{
		DBG2(DBG_KNL, "%H is on interface %s", ip, name);
	}
	else
	{
		DBG2(DBG_KNL, "%H is not a local address", ip);
	}
	return name;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_pfroute_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_pfroute_net_t *this, host_t *dest)
{
	return NULL;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_pfroute_net_t *this, host_t *virtual_ip, host_t *iface_ip)
{
	return FAILED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_pfroute_net_t *this, host_t *virtual_ip)
{
	return FAILED;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_pfroute_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return FAILED;
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_pfroute_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return FAILED;
}

/**
 * Initialize a list of local addresses.
 */
static status_t init_address_list(private_kernel_pfroute_net_t *this)
{
	struct ifaddrs *ifap, *ifa;
	iface_entry_t *iface, *current;
	addr_entry_t *addr;
	enumerator_t *ifaces, *addrs;

	DBG1(DBG_KNL, "listening on interfaces:");

	if (getifaddrs(&ifap) < 0)
	{
		DBG1(DBG_KNL, "  failed to get interfaces!");
		return FAILED;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
		{
			continue;
		}
		switch(ifa->ifa_addr->sa_family)
		{
			case AF_LINK:
			case AF_INET:
			case AF_INET6:
			{
				if (ifa->ifa_flags & IFF_LOOPBACK)
				{	/* ignore loopback interfaces */
					continue;
				}

				iface = NULL;
				ifaces = this->ifaces->create_enumerator(this->ifaces);
				while (ifaces->enumerate(ifaces, &current))
				{
					if (streq(current->ifname, ifa->ifa_name))
					{
						iface = current;
						break;
					}
				}
				ifaces->destroy(ifaces);

				if (!iface)
				{
					iface = malloc_thing(iface_entry_t);
					memcpy(iface->ifname, ifa->ifa_name, IFNAMSIZ);
					iface->ifindex = if_nametoindex(ifa->ifa_name);
					iface->flags = ifa->ifa_flags;
					iface->addrs = linked_list_create();
					this->ifaces->insert_last(this->ifaces, iface);
				}

				if (ifa->ifa_addr->sa_family != AF_LINK)
				{
					addr = malloc_thing(addr_entry_t);
					addr->ip = host_create_from_sockaddr(ifa->ifa_addr);
					addr->virtual = FALSE;
					addr->refcount = 1;
					iface->addrs->insert_last(iface->addrs, addr);
				}
			}
		}
	}
	freeifaddrs(ifap);

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (iface->flags & IFF_UP)
		{
			DBG1(DBG_KNL, "  %s", iface->ifname);
			addrs = iface->addrs->create_enumerator(iface->addrs);
			while (addrs->enumerate(addrs, (void**)&addr))
			{
				DBG1(DBG_KNL, "    %H", addr->ip);
			}
			addrs->destroy(addrs);
		}
	}
	ifaces->destroy(ifaces);

	return SUCCESS;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_pfroute_net_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	if (this->socket > 0)
	{
		close(this->socket);
	}
	if (this->socket_events)
	{
		close(this->socket_events);
	}
	this->ifaces->destroy_function(this->ifaces, (void*)iface_entry_destroy);
	this->mutex->destroy(this->mutex);
	this->mutex_pfroute->destroy(this->mutex_pfroute);
	free(this);
}

/*
 * Described in header.
 */
kernel_pfroute_net_t *kernel_pfroute_net_create()
{
	private_kernel_pfroute_net_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_interface = _get_interface_name,
				.create_address_enumerator = _create_address_enumerator,
				.get_source_addr = _get_source_addr,
				.get_nexthop = _get_nexthop,
				.add_ip = _add_ip,
				.del_ip = _del_ip,
				.add_route = _add_route,
				.del_route = _del_route,
				.destroy = _destroy,
			},
		},
		.ifaces = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.mutex_pfroute = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	/* create a PF_ROUTE socket to communicate with the kernel */
	this->socket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (this->socket < 0)
	{
		DBG1(DBG_KNL, "unable to create PF_ROUTE socket");
		destroy(this);
		return NULL;
	}

	/* create a PF_ROUTE socket to receive events */
	this->socket_events = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (this->socket_events < 0)
	{
		DBG1(DBG_KNL, "unable to create PF_ROUTE event socket");
		destroy(this);
		return NULL;
	}

	this->job = callback_job_create_with_prio((callback_job_cb_t)receive_events,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->job);

	if (init_address_list(this) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get interface list");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
