/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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
 * Copyright (C) 2010 secunet Security Networks AG
 * Copyright (C) 2010 Thomas Egerer
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

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include "kernel_netlink_net.h"
#include "kernel_netlink_shared.h"

#include <hydra.h>
#include <debug.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

typedef struct addr_entry_t addr_entry_t;

/**
 * IP address in an inface_entry_t
 */
struct addr_entry_t {

	/** The ip address */
	host_t *ip;

	/** virtual IP managed by us */
	bool virtual;

	/** scope of the address */
	u_char scope;

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

typedef struct private_kernel_netlink_net_t private_kernel_netlink_net_t;

/**
 * Private variables and functions of kernel_netlink_net class.
 */
struct private_kernel_netlink_net_t {
	/**
	 * Public part of the kernel_netlink_net_t object.
	 */
	kernel_netlink_net_t public;

	/**
	 * mutex to lock access to various lists
	 */
	mutex_t *mutex;

	/**
	 * condition variable to signal virtual IP add/removal
	 */
	condvar_t *condvar;

	/**
	 * Cached list of interfaces and its addresses (iface_entry_t)
	 */
	linked_list_t *ifaces;

	/**
	 * job receiving netlink events
	 */
	callback_job_t *job;

	/**
	 * netlink rt socket (routing)
	 */
	netlink_socket_t *socket;

	/**
	 * Netlink rt socket to receive address change events
	 */
	int socket_events;

	/**
	 * time of the last roam event
	 */
	timeval_t last_roam;

	/**
	 * routing table to install routes
	 */
	int routing_table;

	/**
	 * priority of used routing table
	 */
	int routing_table_prio;

	/**
	 * whether to react to RTM_NEWROUTE or RTM_DELROUTE events
	 */
	bool process_route;

	/**
	 * whether to actually install virtual IPs
	 */
	bool install_virtual_ip;

	/**
	 * list with routing tables to be excluded from route lookup
	 */
	linked_list_t *rt_exclude;
};

/**
 * get the refcount of a virtual ip
 */
static int get_vip_refcount(private_kernel_netlink_net_t *this, host_t* ip)
{
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	int refcount = 0;

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, (void**)&addr))
		{
			if (addr->virtual && (iface->flags & IFF_UP) &&
				ip->ip_equals(ip, addr->ip))
			{
				refcount = addr->refcount;
				break;
			}
		}
		addrs->destroy(addrs);
		if (refcount)
		{
			break;
		}
	}
	ifaces->destroy(ifaces);

	return refcount;
}

/**
 * get the first non-virtual ip address on the given interface.
 * returned host is a clone, has to be freed by caller.
 */
static host_t *get_interface_address(private_kernel_netlink_net_t *this,
									 int ifindex, int family)
{
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	host_t *ip = NULL;

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (iface->ifindex == ifindex)
		{
			addrs = iface->addrs->create_enumerator(iface->addrs);
			while (addrs->enumerate(addrs, &addr))
			{
				if (!addr->virtual && addr->ip->get_family(addr->ip) == family)
				{
					ip = addr->ip->clone(addr->ip);
					break;
				}
			}
			addrs->destroy(addrs);
			break;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);
	return ip;
}

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
static void fire_roam_event(private_kernel_netlink_net_t *this, bool address)
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
 * process RTM_NEWLINK/RTM_DELLINK from kernel
 */
static void process_link(private_kernel_netlink_net_t *this,
						 struct nlmsghdr *hdr, bool event)
{
	struct ifinfomsg* msg = (struct ifinfomsg*)(NLMSG_DATA(hdr));
	struct rtattr *rta = IFLA_RTA(msg);
	size_t rtasize = IFLA_PAYLOAD (hdr);
	enumerator_t *enumerator;
	iface_entry_t *current, *entry = NULL;
	char *name = NULL;
	bool update = FALSE;

	while(RTA_OK(rta, rtasize))
	{
		switch (rta->rta_type)
		{
			case IFLA_IFNAME:
				name = RTA_DATA(rta);
				break;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	if (!name)
	{
		name = "(unknown)";
	}

	this->mutex->lock(this->mutex);
	switch (hdr->nlmsg_type)
	{
		case RTM_NEWLINK:
		{
			if (msg->ifi_flags & IFF_LOOPBACK)
			{	/* ignore loopback interfaces */
				break;
			}
			enumerator = this->ifaces->create_enumerator(this->ifaces);
			while (enumerator->enumerate(enumerator, &current))
			{
				if (current->ifindex == msg->ifi_index)
				{
					entry = current;
					break;
				}
			}
			enumerator->destroy(enumerator);
			if (!entry)
			{
				entry = malloc_thing(iface_entry_t);
				entry->ifindex = msg->ifi_index;
				entry->flags = 0;
				entry->addrs = linked_list_create();
				this->ifaces->insert_last(this->ifaces, entry);
			}
			strncpy(entry->ifname, name, IFNAMSIZ);
			entry->ifname[IFNAMSIZ-1] = '\0';
			if (event)
			{
				if (!(entry->flags & IFF_UP) && (msg->ifi_flags & IFF_UP))
				{
					update = TRUE;
					DBG1(DBG_KNL, "interface %s activated", name);
				}
				if ((entry->flags & IFF_UP) && !(msg->ifi_flags & IFF_UP))
				{
					update = TRUE;
					DBG1(DBG_KNL, "interface %s deactivated", name);
				}
			}
			entry->flags = msg->ifi_flags;
			break;
		}
		case RTM_DELLINK:
		{
			enumerator = this->ifaces->create_enumerator(this->ifaces);
			while (enumerator->enumerate(enumerator, &current))
			{
				if (current->ifindex == msg->ifi_index)
				{
					if (event)
					{
						update = TRUE;
						DBG1(DBG_KNL, "interface %s deleted", current->ifname);
					}
					this->ifaces->remove_at(this->ifaces, enumerator);
					iface_entry_destroy(current);
					break;
				}
			}
			enumerator->destroy(enumerator);
			break;
		}
	}
	this->mutex->unlock(this->mutex);

	/* send an update to all IKE_SAs */
	if (update && event)
	{
		fire_roam_event(this, TRUE);
	}
}

/**
 * process RTM_NEWADDR/RTM_DELADDR from kernel
 */
static void process_addr(private_kernel_netlink_net_t *this,
						 struct nlmsghdr *hdr, bool event)
{
	struct ifaddrmsg* msg = (struct ifaddrmsg*)(NLMSG_DATA(hdr));
	struct rtattr *rta = IFA_RTA(msg);
	size_t rtasize = IFA_PAYLOAD (hdr);
	host_t *host = NULL;
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	chunk_t local = chunk_empty, address = chunk_empty;
	bool update = FALSE, found = FALSE, changed = FALSE;

	while(RTA_OK(rta, rtasize))
	{
		switch (rta->rta_type)
		{
			case IFA_LOCAL:
				local.ptr = RTA_DATA(rta);
				local.len = RTA_PAYLOAD(rta);
				break;
			case IFA_ADDRESS:
				address.ptr = RTA_DATA(rta);
				address.len = RTA_PAYLOAD(rta);
				break;
		}
		rta = RTA_NEXT(rta, rtasize);
	}

	/* For PPP interfaces, we need the IFA_LOCAL address,
	 * IFA_ADDRESS is the peers address. But IFA_LOCAL is
	 * not included in all cases (IPv6?), so fallback to IFA_ADDRESS. */
	if (local.ptr)
	{
		host = host_create_from_chunk(msg->ifa_family, local, 0);
	}
	else if (address.ptr)
	{
		host = host_create_from_chunk(msg->ifa_family, address, 0);
	}

	if (host == NULL)
	{	/* bad family? */
		return;
	}

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (iface->ifindex == msg->ifa_index)
		{
			addrs = iface->addrs->create_enumerator(iface->addrs);
			while (addrs->enumerate(addrs, &addr))
			{
				if (host->ip_equals(host, addr->ip))
				{
					found = TRUE;
					if (hdr->nlmsg_type == RTM_DELADDR)
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
					else if (hdr->nlmsg_type == RTM_NEWADDR && addr->virtual)
					{
						addr->refcount = 1;
					}
				}
			}
			addrs->destroy(addrs);

			if (hdr->nlmsg_type == RTM_NEWADDR)
			{
				if (!found)
				{
					found = TRUE;
					changed = TRUE;
					addr = malloc_thing(addr_entry_t);
					addr->ip = host->clone(host);
					addr->virtual = FALSE;
					addr->refcount = 1;
					addr->scope = msg->ifa_scope;

					iface->addrs->insert_last(iface->addrs, addr);
					if (event)
					{
						DBG1(DBG_KNL, "%H appeared on %s", host, iface->ifname);
					}
				}
			}
			if (found && (iface->flags & IFF_UP))
			{
				update = TRUE;
			}
			break;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);
	host->destroy(host);

	/* send an update to all IKE_SAs */
	if (update && event && changed)
	{
		fire_roam_event(this, TRUE);
	}
}

/**
 * process RTM_NEWROUTE and RTM_DELROUTE from kernel
 */
static void process_route(private_kernel_netlink_net_t *this, struct nlmsghdr *hdr)
{
	struct rtmsg* msg = (struct rtmsg*)(NLMSG_DATA(hdr));
	struct rtattr *rta = RTM_RTA(msg);
	size_t rtasize = RTM_PAYLOAD(hdr);
	u_int32_t rta_oif = 0;
	host_t *host = NULL;

	/* ignore routes added by us or in the local routing table (local addrs) */
	if (msg->rtm_table && (msg->rtm_table == this->routing_table ||
						   msg->rtm_table == RT_TABLE_LOCAL))
	{
		return;
	}

	while (RTA_OK(rta, rtasize))
	{
		switch (rta->rta_type)
		{
			case RTA_PREFSRC:
				DESTROY_IF(host);
				host = host_create_from_chunk(msg->rtm_family,
							chunk_create(RTA_DATA(rta), RTA_PAYLOAD(rta)), 0);
				break;
			case RTA_OIF:
				if (RTA_PAYLOAD(rta) == sizeof(rta_oif))
				{
					rta_oif = *(u_int32_t*)RTA_DATA(rta);
				}
				break;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	if (!host && rta_oif)
	{
		host = get_interface_address(this, rta_oif, msg->rtm_family);
	}
	if (host)
	{
		this->mutex->lock(this->mutex);
		if (!get_vip_refcount(this, host))
		{	/* ignore routes added for virtual IPs */
			fire_roam_event(this, FALSE);
		}
		this->mutex->unlock(this->mutex);
		host->destroy(host);
	}
}

/**
 * Receives events from kernel
 */
static job_requeue_t receive_events(private_kernel_netlink_net_t *this)
{
	char response[1024];
	struct nlmsghdr *hdr = (struct nlmsghdr*)response;
	struct sockaddr_nl addr;
	socklen_t addr_len = sizeof(addr);
	int len;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	len = recvfrom(this->socket_events, response, sizeof(response), 0,
				   (struct sockaddr*)&addr, &addr_len);
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
				DBG1(DBG_KNL, "unable to receive from rt event socket");
				sleep(1);
				return JOB_REQUEUE_FAIR;
		}
	}

	if (addr.nl_pid != 0)
	{	/* not from kernel. not interested, try another one */
		return JOB_REQUEUE_DIRECT;
	}

	while (NLMSG_OK(hdr, len))
	{
		/* looks good so far, dispatch netlink message */
		switch (hdr->nlmsg_type)
		{
			case RTM_NEWADDR:
			case RTM_DELADDR:
				process_addr(this, hdr, TRUE);
				this->condvar->broadcast(this->condvar);
				break;
			case RTM_NEWLINK:
			case RTM_DELLINK:
				process_link(this, hdr, TRUE);
				this->condvar->broadcast(this->condvar);
				break;
			case RTM_NEWROUTE:
			case RTM_DELROUTE:
				if (this->process_route)
				{
					process_route(this, hdr);
				}
				break;
			default:
				break;
		}
		hdr = NLMSG_NEXT(hdr, len);
	}
	return JOB_REQUEUE_DIRECT;
}

/** enumerator over addresses */
typedef struct {
	private_kernel_netlink_net_t* this;
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
	if (!data->include_virtual_ips && (*in)->virtual)
	{	/* skip virtual interfaces added by us */
		return FALSE;
	}
	if ((*in)->scope >= RT_SCOPE_LINK)
	{	/* skip addresses with a unusable scope */
		return FALSE;
	}
	*out = (*in)->ip;
	return TRUE;
}

/**
 * enumerator constructor for interfaces
 */
static enumerator_t *create_iface_enumerator(iface_entry_t *iface,
											 address_enumerator_t *data)
{
	return enumerator_create_filter(
				iface->addrs->create_enumerator(iface->addrs),
				(void*)filter_addresses, data, NULL);
}

/**
 * filter for interfaces
 */
static bool filter_interfaces(address_enumerator_t *data, iface_entry_t** in,
							  iface_entry_t** out)
{
	if (!data->include_down_ifaces && !((*in)->flags & IFF_UP))
	{	/* skip interfaces not up */
		return FALSE;
	}
	*out = *in;
	return TRUE;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_netlink_net_t *this,
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
	private_kernel_netlink_net_t *this, host_t* ip)
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

/**
 * get the index of an interface by name
 */
static int get_interface_index(private_kernel_netlink_net_t *this, char* name)
{
	enumerator_t *ifaces;
	iface_entry_t *iface;
	int ifindex = 0;

	DBG2(DBG_KNL, "getting iface index for %s", name);

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (streq(name, iface->ifname))
		{
			ifindex = iface->ifindex;
			break;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);

	if (ifindex == 0)
	{
		DBG1(DBG_KNL, "unable to get interface index for %s", name);
	}
	return ifindex;
}

/**
 * Check if an interface with a given index is up
 */
static bool is_interface_up(private_kernel_netlink_net_t *this, int index)
{
	enumerator_t *ifaces;
	iface_entry_t *iface;
	/* default to TRUE for interface we do not monitor (e.g. lo) */
	bool up = TRUE;

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (iface->ifindex == index)
		{
			up = iface->flags & IFF_UP;
			break;
		}
	}
	ifaces->destroy(ifaces);
	return up;
}

/**
 * check if an address (chunk) addr is in subnet (net with net_len net bits)
 */
static bool addr_in_subnet(chunk_t addr, chunk_t net, int net_len)
{
	static const u_char mask[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
	int byte = 0;

	if (net_len == 0)
	{	/* any address matches a /0 network */
		return TRUE;
	}
	if (addr.len != net.len || net_len > 8 * net.len )
	{
		return FALSE;
	}
	/* scan through all bytes in network order */
	while (net_len > 0)
	{
		if (net_len < 8)
		{
			return (mask[net_len] & addr.ptr[byte]) == (mask[net_len] & net.ptr[byte]);
		}
		else
		{
			if (addr.ptr[byte] != net.ptr[byte])
			{
				return FALSE;
			}
			byte++;
			net_len -= 8;
		}
	}
	return TRUE;
}

/**
 * Get a route: If "nexthop", the nexthop is returned. source addr otherwise.
 */
static host_t *get_route(private_kernel_netlink_net_t *this, host_t *dest,
						 bool nexthop, host_t *candidate)
{
	netlink_buf_t request;
	struct nlmsghdr *hdr, *out, *current;
	struct rtmsg *msg;
	chunk_t chunk;
	size_t len;
	int best = -1;
	enumerator_t *enumerator;
	host_t *src = NULL, *gtw = NULL;

	DBG2(DBG_KNL, "getting address to reach %H", dest);

	memset(&request, 0, sizeof(request));

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	if (dest->get_family(dest) == AF_INET)
	{
		/* We dump all addresses for IPv4, as we want to ignore IPsec specific
		 * routes installed by us. But the kernel does not return source
		 * addresses in a IPv6 dump, so fall back to get() for v6 routes. */
		hdr->nlmsg_flags |= NLM_F_ROOT | NLM_F_DUMP;
	}
	hdr->nlmsg_type = RTM_GETROUTE;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_family = dest->get_family(dest);
	if (candidate)
	{
		chunk = candidate->get_address(candidate);
		netlink_add_attribute(hdr, RTA_PREFSRC, chunk, sizeof(request));
	}
	chunk = dest->get_address(dest);
	netlink_add_attribute(hdr, RTA_DST, chunk, sizeof(request));

	if (this->socket->send(this->socket, hdr, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "getting address to %H failed", dest);
		return NULL;
	}
	this->mutex->lock(this->mutex);

	for (current = out; NLMSG_OK(current, len);
		 current = NLMSG_NEXT(current, len))
	{
		switch (current->nlmsg_type)
		{
			case NLMSG_DONE:
				break;
			case RTM_NEWROUTE:
			{
				struct rtattr *rta;
				size_t rtasize;
				chunk_t rta_gtw, rta_src, rta_dst;
				u_int32_t rta_oif = 0, rta_table;
				host_t *new_src, *new_gtw;
				bool cont = FALSE;
				uintptr_t table;

				rta_gtw = rta_src = rta_dst = chunk_empty;
				msg = (struct rtmsg*)(NLMSG_DATA(current));
				rta = RTM_RTA(msg);
				rtasize = RTM_PAYLOAD(current);
				rta_table = msg->rtm_table;
				while (RTA_OK(rta, rtasize))
				{
					switch (rta->rta_type)
					{
						case RTA_PREFSRC:
							rta_src = chunk_create(RTA_DATA(rta), RTA_PAYLOAD(rta));
							break;
						case RTA_GATEWAY:
							rta_gtw = chunk_create(RTA_DATA(rta), RTA_PAYLOAD(rta));
							break;
						case RTA_DST:
							rta_dst = chunk_create(RTA_DATA(rta), RTA_PAYLOAD(rta));
							break;
						case RTA_OIF:
							if (RTA_PAYLOAD(rta) == sizeof(rta_oif))
							{
								rta_oif = *(u_int32_t*)RTA_DATA(rta);
							}
							break;
#ifdef HAVE_RTA_TABLE
						case RTA_TABLE:
							if (RTA_PAYLOAD(rta) == sizeof(rta_table))
							{
								rta_table = *(u_int32_t*)RTA_DATA(rta);
							}
							break;
#endif /* HAVE_RTA_TABLE*/
					}
					rta = RTA_NEXT(rta, rtasize);
				}
				if (msg->rtm_dst_len <= best)
				{	/* not better than a previous one */
					continue;
				}
				enumerator = this->rt_exclude->create_enumerator(this->rt_exclude);
				while (enumerator->enumerate(enumerator, &table))
				{
					if (table == rta_table)
					{
						cont = TRUE;
						break;
					}
				}
				enumerator->destroy(enumerator);
				if (cont)
				{
					continue;
				}
				if (this->routing_table != 0 &&
					rta_table == this->routing_table)
				{	/* route is from our own ipsec routing table */
					continue;
				}
				if (rta_oif && !is_interface_up(this, rta_oif))
				{	/* interface is down */
					continue;
				}
				if (!addr_in_subnet(chunk, rta_dst, msg->rtm_dst_len))
				{	/* route destination does not contain dest */
					continue;
				}

				if (nexthop)
				{
					/* nexthop lookup, return gateway if any */
					DESTROY_IF(gtw);
					gtw = host_create_from_chunk(msg->rtm_family, rta_gtw, 0);
					best = msg->rtm_dst_len;
					continue;
				}
				if (rta_src.ptr)
				{	/* got a source address */
					new_src = host_create_from_chunk(msg->rtm_family, rta_src, 0);
					if (new_src)
					{
						if (get_vip_refcount(this, new_src))
						{	/* skip source address if it is installed by us */
							new_src->destroy(new_src);
						}
						else
						{
							DESTROY_IF(src);
							src = new_src;
							best = msg->rtm_dst_len;
						}
					}
					continue;
				}
				if (rta_oif)
				{	/* no src or gtw, but an interface. Get address from it. */
					new_src = get_interface_address(this, rta_oif,
													msg->rtm_family);
					if (new_src)
					{
						DESTROY_IF(src);
						src = new_src;
						best = msg->rtm_dst_len;
					}
					continue;
				}
				if (rta_gtw.ptr)
				{	/* no source, but a gateway. Lookup source to reach gtw. */
					new_gtw = host_create_from_chunk(msg->rtm_family, rta_gtw, 0);
					new_src = get_route(this, new_gtw, FALSE, candidate);
					new_gtw->destroy(new_gtw);
					if (new_src)
					{
						DESTROY_IF(src);
						src = new_src;
						best = msg->rtm_dst_len;
					}
					continue;
				}
				continue;
			}
			default:
				continue;
		}
		break;
	}
	free(out);
	this->mutex->unlock(this->mutex);

	if (nexthop)
	{
		if (gtw)
		{
			return gtw;
		}
		return dest->clone(dest);
	}
	return src;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_netlink_net_t *this, host_t *dest, host_t *src)
{
	return get_route(this, dest, FALSE, src);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_netlink_net_t *this, host_t *dest)
{
	return get_route(this, dest, TRUE, NULL);
}

/**
 * Manages the creation and deletion of ip addresses on an interface.
 * By setting the appropriate nlmsg_type, the ip will be set or unset.
 */
static status_t manage_ipaddr(private_kernel_netlink_net_t *this, int nlmsg_type,
							  int flags, int if_index, host_t *ip)
{
	netlink_buf_t request;
	struct nlmsghdr *hdr;
	struct ifaddrmsg *msg;
	chunk_t chunk;

	memset(&request, 0, sizeof(request));

	chunk = ip->get_address(ip);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	hdr->nlmsg_type = nlmsg_type;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

	msg = (struct ifaddrmsg*)NLMSG_DATA(hdr);
	msg->ifa_family = ip->get_family(ip);
	msg->ifa_flags = 0;
	msg->ifa_prefixlen = 8 * chunk.len;
	msg->ifa_scope = RT_SCOPE_UNIVERSE;
	msg->ifa_index = if_index;

	netlink_add_attribute(hdr, IFA_LOCAL, chunk, sizeof(request));

	return this->socket->send_ack(this->socket, hdr);
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_netlink_net_t *this, host_t *virtual_ip, host_t *iface_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	enumerator_t *addrs, *ifaces;
	int ifindex;

	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	DBG2(DBG_KNL, "adding virtual IP %H", virtual_ip);

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		bool iface_found = FALSE;

		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, &addr))
		{
			if (iface_ip->ip_equals(iface_ip, addr->ip))
			{
				iface_found = TRUE;
			}
			else if (virtual_ip->ip_equals(virtual_ip, addr->ip))
			{
				addr->refcount++;
				DBG2(DBG_KNL, "virtual IP %H already installed on %s",
					 virtual_ip, iface->ifname);
				addrs->destroy(addrs);
				ifaces->destroy(ifaces);
				this->mutex->unlock(this->mutex);
				return SUCCESS;
			}
		}
		addrs->destroy(addrs);

		if (iface_found)
		{
			ifindex = iface->ifindex;
			addr = malloc_thing(addr_entry_t);
			addr->ip = virtual_ip->clone(virtual_ip);
			addr->refcount = 0;
			addr->virtual = TRUE;
			addr->scope = RT_SCOPE_UNIVERSE;
			iface->addrs->insert_last(iface->addrs, addr);

			if (manage_ipaddr(this, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL,
							  ifindex, virtual_ip) == SUCCESS)
			{
				while (get_vip_refcount(this, virtual_ip) == 0)
				{	/* wait until address appears */
					this->condvar->wait(this->condvar, this->mutex);
				}
				ifaces->destroy(ifaces);
				this->mutex->unlock(this->mutex);
				return SUCCESS;
			}
			ifaces->destroy(ifaces);
			this->mutex->unlock(this->mutex);
			DBG1(DBG_KNL, "adding virtual IP %H failed", virtual_ip);
			return FAILED;
		}
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);

	DBG1(DBG_KNL, "interface address %H not found, unable to install"
		 "virtual IP %H", iface_ip, virtual_ip);
	return FAILED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_netlink_net_t *this, host_t *virtual_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	enumerator_t *addrs, *ifaces;
	status_t status;
	int ifindex;

	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	DBG2(DBG_KNL, "deleting virtual IP %H", virtual_ip);

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, &addr))
		{
			if (virtual_ip->ip_equals(virtual_ip, addr->ip))
			{
				ifindex = iface->ifindex;
				if (addr->refcount == 1)
				{
					status = manage_ipaddr(this, RTM_DELADDR, 0,
										   ifindex, virtual_ip);
					if (status == SUCCESS)
					{	/* wait until the address is really gone */
						while (get_vip_refcount(this, virtual_ip) > 0)
						{
							this->condvar->wait(this->condvar, this->mutex);
						}
					}
					addrs->destroy(addrs);
					ifaces->destroy(ifaces);
					this->mutex->unlock(this->mutex);
					return status;
				}
				else
				{
					addr->refcount--;
				}
				DBG2(DBG_KNL, "virtual IP %H used by other SAs, not deleting",
					 virtual_ip);
				addrs->destroy(addrs);
				ifaces->destroy(ifaces);
				this->mutex->unlock(this->mutex);
				return SUCCESS;
			}
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);

	DBG2(DBG_KNL, "virtual IP %H not cached, unable to delete", virtual_ip);
	return FAILED;
}

/**
 * Manages source routes in the routing table.
 * By setting the appropriate nlmsg_type, the route gets added or removed.
 */
static status_t manage_srcroute(private_kernel_netlink_net_t *this, int nlmsg_type,
								int flags, chunk_t dst_net, u_int8_t prefixlen,
								host_t *gateway, host_t *src_ip, char *if_name)
{
	netlink_buf_t request;
	struct nlmsghdr *hdr;
	struct rtmsg *msg;
	int ifindex;
	chunk_t chunk;

	/* if route is 0.0.0.0/0, we can't install it, as it would
	 * overwrite the default route. Instead, we add two routes:
	 * 0.0.0.0/1 and 128.0.0.0/1 */
	if (this->routing_table == 0 && prefixlen == 0)
	{
		chunk_t half_net;
		u_int8_t half_prefixlen;
		status_t status;

		half_net = chunk_alloca(dst_net.len);
		memset(half_net.ptr, 0, half_net.len);
		half_prefixlen = 1;

		status = manage_srcroute(this, nlmsg_type, flags, half_net, half_prefixlen,
					gateway, src_ip, if_name);
		half_net.ptr[0] |= 0x80;
		status = manage_srcroute(this, nlmsg_type, flags, half_net, half_prefixlen,
					gateway, src_ip, if_name);
		return status;
	}

	memset(&request, 0, sizeof(request));

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	hdr->nlmsg_type = nlmsg_type;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_family = src_ip->get_family(src_ip);
	msg->rtm_dst_len = prefixlen;
	msg->rtm_table = this->routing_table;
	msg->rtm_protocol = RTPROT_STATIC;
	msg->rtm_type = RTN_UNICAST;
	msg->rtm_scope = RT_SCOPE_UNIVERSE;

	netlink_add_attribute(hdr, RTA_DST, dst_net, sizeof(request));
	chunk = src_ip->get_address(src_ip);
	netlink_add_attribute(hdr, RTA_PREFSRC, chunk, sizeof(request));
	if (gateway && gateway->get_family(gateway) == src_ip->get_family(src_ip))
	{
		chunk = gateway->get_address(gateway);
		netlink_add_attribute(hdr, RTA_GATEWAY, chunk, sizeof(request));
	}
	ifindex = get_interface_index(this, if_name);
	chunk.ptr = (char*)&ifindex;
	chunk.len = sizeof(ifindex);
	netlink_add_attribute(hdr, RTA_OIF, chunk, sizeof(request));

	return this->socket->send_ack(this->socket, hdr);
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_netlink_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_srcroute(this, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
				dst_net, prefixlen, gateway, src_ip, if_name);
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_netlink_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_srcroute(this, RTM_DELROUTE, 0, dst_net, prefixlen,
				gateway, src_ip, if_name);
}

/**
 * Initialize a list of local addresses.
 */
static status_t init_address_list(private_kernel_netlink_net_t *this)
{
	netlink_buf_t request;
	struct nlmsghdr *out, *current, *in;
	struct rtgenmsg *msg;
	size_t len;
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;

	DBG1(DBG_KNL, "listening on interfaces:");

	memset(&request, 0, sizeof(request));

	in = (struct nlmsghdr*)&request;
	in->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	in->nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
	msg = (struct rtgenmsg*)NLMSG_DATA(in);
	msg->rtgen_family = AF_UNSPEC;

	/* get all links */
	in->nlmsg_type = RTM_GETLINK;
	if (this->socket->send(this->socket, in, &out, &len) != SUCCESS)
	{
		return FAILED;
	}
	current = out;
	while (NLMSG_OK(current, len))
	{
		switch (current->nlmsg_type)
		{
			case NLMSG_DONE:
				break;
			case RTM_NEWLINK:
				process_link(this, current, FALSE);
				/* fall through */
			default:
				current = NLMSG_NEXT(current, len);
				continue;
		}
		break;
	}
	free(out);

	/* get all interface addresses */
	in->nlmsg_type = RTM_GETADDR;
	if (this->socket->send(this->socket, in, &out, &len) != SUCCESS)
	{
		return FAILED;
	}
	current = out;
	while (NLMSG_OK(current, len))
	{
		switch (current->nlmsg_type)
		{
			case NLMSG_DONE:
				break;
			case RTM_NEWADDR:
				process_addr(this, current, FALSE);
				/* fall through */
			default:
				current = NLMSG_NEXT(current, len);
				continue;
		}
		break;
	}
	free(out);

	this->mutex->lock(this->mutex);
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
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

/**
 * create or delete a rule to use our routing table
 */
static status_t manage_rule(private_kernel_netlink_net_t *this, int nlmsg_type,
							int family, u_int32_t table, u_int32_t prio)
{
	netlink_buf_t request;
	struct nlmsghdr *hdr;
	struct rtmsg *msg;
	chunk_t chunk;

	memset(&request, 0, sizeof(request));
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = nlmsg_type;
	if (nlmsg_type == RTM_NEWRULE)
	{
		hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	}
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_table = table;
	msg->rtm_family = family;
	msg->rtm_protocol = RTPROT_BOOT;
	msg->rtm_scope = RT_SCOPE_UNIVERSE;
	msg->rtm_type = RTN_UNICAST;

	chunk = chunk_from_thing(prio);
	netlink_add_attribute(hdr, RTA_PRIORITY, chunk, sizeof(request));

	return this->socket->send_ack(this->socket, hdr);
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_netlink_net_t *this)
{
	if (this->routing_table)
	{
		manage_rule(this, RTM_DELRULE, AF_INET, this->routing_table,
					this->routing_table_prio);
		manage_rule(this, RTM_DELRULE, AF_INET6, this->routing_table,
					this->routing_table_prio);
	}
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	if (this->socket_events > 0)
	{
		close(this->socket_events);
	}
	DESTROY_IF(this->socket);
	this->ifaces->destroy_function(this->ifaces, (void*)iface_entry_destroy);
	this->rt_exclude->destroy(this->rt_exclude);
	this->condvar->destroy(this->condvar);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_netlink_net_t *kernel_netlink_net_create()
{
	private_kernel_netlink_net_t *this;
	struct sockaddr_nl addr;
	enumerator_t *enumerator;
	char *exclude;

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
		.socket = netlink_socket_create(NETLINK_ROUTE),
		.rt_exclude = linked_list_create(),
		.ifaces = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.routing_table = lib->settings->get_int(lib->settings,
				"%s.routing_table", ROUTING_TABLE, hydra->daemon),
		.routing_table_prio = lib->settings->get_int(lib->settings,
				"%s.routing_table_prio", ROUTING_TABLE_PRIO, hydra->daemon),
		.process_route = lib->settings->get_bool(lib->settings,
				"%s.process_route", TRUE, hydra->daemon),
		.install_virtual_ip = lib->settings->get_bool(lib->settings,
				"%s.install_virtual_ip", TRUE, hydra->daemon),
	);
	timerclear(&this->last_roam);

	exclude = lib->settings->get_str(lib->settings,
					"%s.ignore_routing_tables", NULL, hydra->daemon);
	if (exclude)
	{
		char *token;
		uintptr_t table;

		enumerator = enumerator_create_token(exclude, " ", " ");
		while (enumerator->enumerate(enumerator, &token))
		{
			errno = 0;
			table = strtoul(token, NULL, 10);

			if (errno == 0)
			{
				this->rt_exclude->insert_last(this->rt_exclude, (void*)table);
			}
		}
		enumerator->destroy(enumerator);
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	/* create and bind RT socket for events (address/interface/route changes) */
	this->socket_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->socket_events < 0)
	{
		DBG1(DBG_KNL, "unable to create RT event socket");
		destroy(this);
		return NULL;
	}
	addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
					 RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK;
	if (bind(this->socket_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		DBG1(DBG_KNL, "unable to bind RT event socket");
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

	if (this->routing_table)
	{
		if (manage_rule(this, RTM_NEWRULE, AF_INET, this->routing_table,
						this->routing_table_prio) != SUCCESS)
		{
			DBG1(DBG_KNL, "unable to create IPv4 routing table rule");
		}
		if (manage_rule(this, RTM_NEWRULE, AF_INET6, this->routing_table,
						this->routing_table_prio) != SUCCESS)
		{
			DBG1(DBG_KNL, "unable to create IPv6 routing table rule");
		}
	}

	return &this->public;
}
