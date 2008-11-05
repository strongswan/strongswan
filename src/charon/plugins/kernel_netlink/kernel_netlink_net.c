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
 *
 * $Id$
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include "kernel_netlink_net.h"
#include "kernel_netlink_shared.h"

#include <daemon.h>
#include <utils/mutex.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/roam_job.h>

/** delay before firing roam jobs (ms) */
#define ROAM_DELAY 100

/** routing table for routes installed by us */
#ifndef IPSEC_ROUTING_TABLE
#define IPSEC_ROUTING_TABLE 100
#endif
#ifndef IPSEC_ROUTING_TABLE_PRIO
#define IPSEC_ROUTING_TABLE_PRIO 100
#endif

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
	 * time of the last roam_job
	 */
	struct timeval last_roam;
	
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

};

/**
 * get the refcount of a virtual ip
 */
static int get_vip_refcount(private_kernel_netlink_net_t *this, host_t* ip)
{
	iterator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	int refcount = 0;
	
	ifaces = this->ifaces->create_iterator(this->ifaces, TRUE);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
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
 * start a roaming job. We delay it for a second and fire only one job
 * for multiple events. Otherwise we would create two many jobs.
 */
static void fire_roam_job(private_kernel_netlink_net_t *this, bool address)
{
	struct timeval now;
		
	if (gettimeofday(&now, NULL) == 0)
	{
		if (timercmp(&now, &this->last_roam, >))
		{
			now.tv_usec += ROAM_DELAY * 1000;
			while (now.tv_usec > 1000000)
			{
				now.tv_sec++;
				now.tv_usec -= 1000000;
			}
			this->last_roam = now;
			charon->scheduler->schedule_job(charon->scheduler,
					(job_t*)roam_job_create(address), ROAM_DELAY);
		}
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
			memcpy(entry->ifname, name, IFNAMSIZ);
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
					/* we do not remove it, as an address may be added to a 
					 * "down" interface and we wan't to know that. */
					current->flags = msg->ifi_flags;
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
		fire_roam_job(this, TRUE);
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
		fire_roam_job(this, TRUE);
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
	host_t *host = NULL;
	
	/* ignore routes added by us */
	if (msg->rtm_table && msg->rtm_table == this->routing_table)
	{
		return;
	}
	
	while (RTA_OK(rta, rtasize))
	{
		switch (rta->rta_type)
		{
			case RTA_PREFSRC:
				host = host_create_from_chunk(msg->rtm_family,
							chunk_create(RTA_DATA(rta), RTA_PAYLOAD(rta)), 0);
				break;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	if (host)
	{
		this->mutex->lock(this->mutex);
		if (!get_vip_refcount(this, host))
		{	/* ignore routes added for virtual IPs */
			fire_roam_job(this, FALSE);
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
	int len, oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);	
	len = recvfrom(this->socket_events, response, sizeof(response), 0,
				   (struct sockaddr*)&addr, &addr_len);
	pthread_setcancelstate(oldstate, NULL);
	
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
static bool filter_addresses(address_enumerator_t *data, addr_entry_t** in, host_t** out)
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
static enumerator_t *create_iface_enumerator(iface_entry_t *iface, address_enumerator_t *data)
{
	return enumerator_create_filter(iface->addrs->create_enumerator(iface->addrs),
				(void*)filter_addresses, data, NULL);
}

/**
 * filter for interfaces
 */
static bool filter_interfaces(address_enumerator_t *data, iface_entry_t** in, iface_entry_t** out)
{
	if (!data->include_down_ifaces && !((*in)->flags & IFF_UP))
	{	/* skip interfaces not up */
		return FALSE;
	}
	*out = *in;
	return TRUE;
}

/**
 * implementation of kernel_net_t.create_address_enumerator
 */
static enumerator_t *create_address_enumerator(private_kernel_netlink_net_t *this,
		bool include_down_ifaces, bool include_virtual_ips)
{
	address_enumerator_t *data = malloc_thing(address_enumerator_t);
	data->this = this;
	data->include_down_ifaces = include_down_ifaces;
	data->include_virtual_ips = include_virtual_ips;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(
				enumerator_create_filter(this->ifaces->create_enumerator(this->ifaces),
							(void*)filter_interfaces, data, NULL),
				(void*)create_iface_enumerator, data, (void*)address_enumerator_destroy);
}

/**
 * implementation of kernel_net_t.get_interface_name
 */
static char *get_interface_name(private_kernel_netlink_net_t *this, host_t* ip)
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
 * check if an address (chunk) addr is in subnet (net with net_len net bits)
 */
static bool addr_in_subnet(chunk_t addr, chunk_t net, int net_len)
{
	static const u_char mask[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
	int byte = 0;

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
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr, *out, *current;
	struct rtmsg *msg;
	chunk_t chunk;
	size_t len;
	int best = -1;
	host_t *src = NULL, *gtw = NULL;
	
	DBG2(DBG_KNL, "getting address to reach %H", dest);
	
	memset(&request, 0, sizeof(request));

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ROOT;
	hdr->nlmsg_type = RTM_GETROUTE;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_family = dest->get_family(dest);
	
	chunk = dest->get_address(dest);
	netlink_add_attribute(hdr, RTA_DST, chunk, sizeof(request));
	if (candidate)
	{
		chunk = candidate->get_address(candidate);
		netlink_add_attribute(hdr, RTA_PREFSRC, chunk, sizeof(request));
	}
	
	if (this->socket->send(this->socket, hdr, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "getting address to %H failed", dest);
		return NULL;
	}
	this->mutex->lock(this->mutex);
	current = out;
	while (NLMSG_OK(current, len))
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
				u_int32_t rta_oif = 0;
				
				rta_gtw = rta_src = rta_dst = chunk_empty;
				msg = (struct rtmsg*)(NLMSG_DATA(current));
				rta = RTM_RTA(msg);
				rtasize = RTM_PAYLOAD(current);
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
					}
					rta = RTA_NEXT(rta, rtasize);
				}
				
				/* apply the route if:
				 * - it is not from our own ipsec routing table
				 * - is better than a previous one
				 * - is the default route or
				 * - its destination net contains our destination
				 */
				if ((this->routing_table == 0 ||msg->rtm_table != this->routing_table)
					&&  msg->rtm_dst_len > best
					&& (msg->rtm_dst_len == 0 || /* default route */
					(rta_dst.ptr && addr_in_subnet(chunk, rta_dst, msg->rtm_dst_len))))
				{
					enumerator_t *ifaces, *addrs;
					iface_entry_t *iface;
					addr_entry_t *addr;
					
					best = msg->rtm_dst_len;
					if (nexthop)
					{
						DESTROY_IF(gtw);
						gtw = host_create_from_chunk(msg->rtm_family, rta_gtw, 0);
					}
					else if (rta_src.ptr)
					{
						DESTROY_IF(src);
						src = host_create_from_chunk(msg->rtm_family, rta_src, 0);
						if (get_vip_refcount(this, src))
						{	/* skip source address if it is installed by us */
							DESTROY_IF(src);
							src = NULL;
							current = NLMSG_NEXT(current, len);
							continue;
						}
					}
					else
					{
						/* no source addr, get one from the interfaces */
						ifaces = this->ifaces->create_enumerator(this->ifaces);
						while (ifaces->enumerate(ifaces, &iface))
						{
							if (iface->ifindex == rta_oif)
							{
								addrs = iface->addrs->create_enumerator(iface->addrs);
								while (addrs->enumerate(addrs, &addr))
								{
									chunk_t ip = addr->ip->get_address(addr->ip);
									if ((msg->rtm_dst_len == 0 && 
										 addr->ip->get_family(addr->ip) ==
										 	dest->get_family(dest)) ||
										addr_in_subnet(ip, rta_dst, msg->rtm_dst_len))
									{
										DESTROY_IF(src);
										src = addr->ip->clone(addr->ip);
										break;
									}
								}
								addrs->destroy(addrs);
							}
						}
						ifaces->destroy(ifaces);
					}
				}
				/* FALL through */
			}
			default:
				current = NLMSG_NEXT(current, len);
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

/**
 * Implementation of kernel_net_t.get_source_addr.
 */
static host_t* get_source_addr(private_kernel_netlink_net_t *this,
							   host_t *dest, host_t *src)
{
	return get_route(this, dest, FALSE, src);
}

/**
 * Implementation of kernel_net_t.get_nexthop.
 */
static host_t* get_nexthop(private_kernel_netlink_net_t *this, host_t *dest)
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
	unsigned char request[NETLINK_BUFFER_SIZE];
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

/**
 * Implementation of kernel_net_t.add_ip.
 */
static status_t add_ip(private_kernel_netlink_net_t *this, 
						host_t *virtual_ip, host_t *iface_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	enumerator_t *addrs, *ifaces;
	int ifindex;

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

/**
 * Implementation of kernel_net_t.del_ip.
 */
static status_t del_ip(private_kernel_netlink_net_t *this, host_t *virtual_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	enumerator_t *addrs, *ifaces;
	status_t status;
	int ifindex;

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
	unsigned char request[NETLINK_BUFFER_SIZE];
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
	chunk = gateway->get_address(gateway);
	netlink_add_attribute(hdr, RTA_GATEWAY, chunk, sizeof(request));
	ifindex = get_interface_index(this, if_name);
	chunk.ptr = (char*)&ifindex;
	chunk.len = sizeof(ifindex);
	netlink_add_attribute(hdr, RTA_OIF, chunk, sizeof(request));

	return this->socket->send_ack(this->socket, hdr);
}

/**
 * Implementation of kernel_net_t.add_route.
 */
status_t add_route(private_kernel_netlink_net_t *this, chunk_t dst_net,
		u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_srcroute(this, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
				dst_net, prefixlen, gateway, src_ip, if_name);
}
	
/**
 * Implementation of kernel_net_t.del_route.
 */
status_t del_route(private_kernel_netlink_net_t *this, chunk_t dst_net,
		u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_srcroute(this, RTM_DELROUTE, 0, dst_net, prefixlen,
				gateway, src_ip, if_name);
}

/**
 * Initialize a list of local addresses.
 */
static status_t init_address_list(private_kernel_netlink_net_t *this)
{
	char request[NETLINK_BUFFER_SIZE];
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
							u_int32_t table, u_int32_t prio)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
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
	msg->rtm_family = AF_INET;
	msg->rtm_protocol = RTPROT_BOOT;
	msg->rtm_scope = RT_SCOPE_UNIVERSE;
	msg->rtm_type = RTN_UNICAST;

	chunk = chunk_from_thing(prio);
	netlink_add_attribute(hdr, RTA_PRIORITY, chunk, sizeof(request));

	return this->socket->send_ack(this->socket, hdr);
}

/**
 * Implementation of kernel_netlink_net_t.destroy.
 */
static void destroy(private_kernel_netlink_net_t *this)
{
	if (this->routing_table)
	{
		manage_rule(this, RTM_DELRULE, this->routing_table,
					this->routing_table_prio);
	}

	this->job->cancel(this->job);
	close(this->socket_events);
	this->socket->destroy(this->socket);
	this->ifaces->destroy_function(this->ifaces, (void*)iface_entry_destroy);
	this->condvar->destroy(this->condvar);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_netlink_net_t *kernel_netlink_net_create()
{
	private_kernel_netlink_net_t *this = malloc_thing(private_kernel_netlink_net_t);
	struct sockaddr_nl addr;
	
	/* public functions */
	this->public.interface.get_interface = (char*(*)(kernel_net_t*,host_t*))get_interface_name;
	this->public.interface.create_address_enumerator = (enumerator_t*(*)(kernel_net_t*,bool,bool))create_address_enumerator;
	this->public.interface.get_source_addr = (host_t*(*)(kernel_net_t*, host_t *dest, host_t *src))get_source_addr;
	this->public.interface.get_nexthop = (host_t*(*)(kernel_net_t*, host_t *dest))get_nexthop;
	this->public.interface.add_ip = (status_t(*)(kernel_net_t*,host_t*,host_t*)) add_ip;
	this->public.interface.del_ip = (status_t(*)(kernel_net_t*,host_t*)) del_ip;
	this->public.interface.add_route = (status_t(*)(kernel_net_t*,chunk_t,u_int8_t,host_t*,host_t*,char*)) add_route;
	this->public.interface.del_route = (status_t(*)(kernel_net_t*,chunk_t,u_int8_t,host_t*,host_t*,char*)) del_route;
	this->public.interface.destroy = (void(*)(kernel_net_t*)) destroy;

	/* private members */
	this->ifaces = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	this->condvar = condvar_create(CONDVAR_DEFAULT);
	timerclear(&this->last_roam);
	this->routing_table = lib->settings->get_int(lib->settings,
					"charon.routing_table", IPSEC_ROUTING_TABLE);
	this->routing_table_prio = lib->settings->get_int(lib->settings,
					"charon.routing_table_prio", IPSEC_ROUTING_TABLE_PRIO);
	this->process_route = lib->settings->get_bool(lib->settings,
					"charon.process_route", TRUE);
	
	this->socket = netlink_socket_create(NETLINK_ROUTE);
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	
	/* create and bind RT socket for events (address/interface/route changes) */
	this->socket_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->socket_events <= 0)
	{
		charon->kill(charon, "unable to create RT event socket");
	}
	addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | 
					 RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_LINK;
	if (bind(this->socket_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind RT event socket");
	}
	
	this->job = callback_job_create((callback_job_cb_t)receive_events,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	if (init_address_list(this) != SUCCESS)
	{
		charon->kill(charon, "unable to get interface list");
	}
	
	if (this->routing_table)
	{
		if (manage_rule(this, RTM_NEWRULE, this->routing_table,
						this->routing_table_prio) != SUCCESS)
		{
			DBG1(DBG_KNL, "unable to create routing table rule");
		}
	}
	
	return &this->public;
}
