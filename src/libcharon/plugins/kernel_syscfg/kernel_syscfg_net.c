/*
 * Copyright (C) 2009-2016 Tobias Brunner
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
 *
 * Copyright (C) 2018 Sophos, Inc.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/route.h>
#include <unistd.h>
#include <errno.h>

#include "kernel_syscfg_net.h"

#include <daemon.h>
#include <utils/debug.h>
#include <networking/host.h>
#include <networking/tun_device.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <threading/rwlock.h>
#include <threading/spinlock.h>
#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#ifndef HAVE_STRUCT_SOCKADDR_SA_LEN
#error Cannot compile this plugin on systems where 'struct sockaddr' has no sa_len member.
#endif

/** properly align sockaddrs */
#ifdef __APPLE__
/* Apple always uses 4 bytes */
#define SA_ALIGN 4
#else
/* while on other platforms like FreeBSD it depends on the architecture */
#define SA_ALIGN sizeof(long)
#endif
#define SA_LEN(len) ((len) > 0 ? (((len)+SA_ALIGN-1) & ~(SA_ALIGN-1)) : SA_ALIGN)

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

/** delay before reinstalling routes (ms) */
#define ROUTE_DELAY 100

/** MTU to set when creating a new TUN device */
#define TUN_DEFAULT_MTU 1400

/** Hack to work around issue where new VIP is sent but not used
    REMOVE WHEN FIXED */
#define IGNORE_VIP_CHANGES  1

typedef struct addr_entry_t addr_entry_t;

/**
 * IP address in an inface_entry_t
 */
struct addr_entry_t {

	/** The ip address */
	host_t *ip;

	/** virtual IP managed by us */
	bool virtual;
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

	/** name of the interface */
	char ifname[IFNAMSIZ];

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

/**
 * check if an interface is up
 */
static inline bool iface_entry_up(iface_entry_t *iface)
{
	return TRUE;
}

/**
 * check if an interface is up and usable
 */
static inline bool iface_entry_up_and_usable(iface_entry_t *iface)
{
	return TRUE;
}

typedef struct addr_map_entry_t addr_map_entry_t;

/**
 * Entry that maps an IP address to an interface entry
 */
struct addr_map_entry_t {
	/** The IP address */
	host_t *ip;

	/** The address entry for this IP address */
	addr_entry_t *addr;

	/** The interface this address is installed on */
	iface_entry_t *iface;
};

/**
 * Hash a addr_map_entry_t object, all entries with the same IP address
 * are stored in the same bucket
 */
static u_int addr_map_entry_hash(addr_map_entry_t *this)
{
	return chunk_hash(this->ip->get_address(this->ip));
}

/**
 * Compare two addr_map_entry_t objects, two entries are equal if they are
 * installed on the same interface
 */
static bool addr_map_entry_equals(addr_map_entry_t *a, addr_map_entry_t *b)
{
	return streq(a->iface->ifname, b->iface->ifname) &&
		   a->ip->ip_equals(a->ip, b->ip);
}

/**
 * Used with get_match this finds an address entry if it is installed on
 * an up and usable interface
 */
static bool addr_map_entry_match_up_and_usable(addr_map_entry_t *a,
											   addr_map_entry_t *b)
{
	return !b->addr->virtual && iface_entry_up_and_usable(b->iface) &&
			a->ip->ip_equals(a->ip, b->ip);
}

/**
 * Used with get_match this finds an address entry if it is installed as virtual
 * IP address
 */
static bool addr_map_entry_match_virtual(addr_map_entry_t *a, addr_map_entry_t *b)
{
	return b->addr->virtual && a->ip->ip_equals(a->ip, b->ip);
}

/**
 * Used with get_match this finds an address entry if it is installed on
 * any active local interface
 */
static bool addr_map_entry_match_up(addr_map_entry_t *a, addr_map_entry_t *b)
{
	return !b->addr->virtual && iface_entry_up(b->iface) &&
			a->ip->ip_equals(a->ip, b->ip);
}

typedef struct route_entry_t route_entry_t;

/**
 * Installed routing entry
 */
struct route_entry_t {
	/** Name of the interface the route is bound to */
	char *if_name;

	/** Gateway for this route */
	host_t *gateway;

	/** Destination net */
	chunk_t dst_net;

	/** Destination net prefixlen */
	uint8_t prefixlen;
};

/**
 * Clone a route_entry_t object.
 */
static route_entry_t *route_entry_clone(route_entry_t *this)
{
	route_entry_t *route;

	INIT(route,
		.if_name = strdup(this->if_name),
		.gateway = this->gateway ? this->gateway->clone(this->gateway) : NULL,
		.dst_net = chunk_clone(this->dst_net),
		.prefixlen = this->prefixlen,
	);
	return route;
}

/**
 * Destroy a route_entry_t object
 */
static void route_entry_destroy(route_entry_t *this)
{
	free(this->if_name);
	DESTROY_IF(this->gateway);
	chunk_free(&this->dst_net);
	free(this);
}

/**
 * Hash a route_entry_t object
 */
static u_int route_entry_hash(route_entry_t *this)
{
	return chunk_hash_inc(chunk_from_thing(this->prefixlen),
						  chunk_hash(this->dst_net));
}

/**
 * Compare two route_entry_t objects
 */
static bool route_entry_equals(route_entry_t *a, route_entry_t *b)
{
	if (chunk_equals(a->dst_net, b->dst_net) && a->prefixlen == b->prefixlen)
	{
		/* Only check interface if both have it specified */
		if (a->if_name && b->if_name && !streq(a->if_name, b->if_name))
		{
			return FALSE;
		}
		return (!a->gateway && !b->gateway) || (a->gateway && b->gateway &&
					a->gateway->ip_equals(a->gateway, b->gateway));
	}
	return FALSE;
}

typedef struct net_change_t net_change_t;

/**
 * Queued network changes
 */
struct net_change_t {
	/** Name of the interface that got activated (or an IP appeared on) */
	char *if_name;
};

/**
 * Destroy a net_change_t object
 */
static void net_change_destroy(net_change_t *this)
{
	free(this->if_name);
	free(this);
}

/**
 * Hash a net_change_t object
 */
static u_int net_change_hash(net_change_t *this)
{
	return chunk_hash(chunk_create(this->if_name, strlen(this->if_name)));
}

/**
 * Compare two net_change_t objects
 */
static bool net_change_equals(net_change_t *a, net_change_t *b)
{
	return streq(a->if_name, b->if_name);
}

typedef struct private_kernel_syscfg_net_t private_kernel_syscfg_net_t;

typedef struct tun_entry_t tun_entry_t;

/**
 * Entry in the tun linked list
 */
struct tun_entry_t {

	/** The tun device */
	tun_device_t *tun;

	/** A reference count for the TUN device */
	int count;
};

/**
 * destroy a tun_entry_t object
 */
static void tun_entry_destroy(tun_entry_t *this)
{
	this->tun->destroy(this->tun);
	free(this);
}

/**
 * find a tun_entry_t object that has a given IP address
 */
static tun_entry_t *tun_entry_find(linked_list_t *tuns, host_t *ip)
{
	tun_entry_t *entry = NULL;
	enumerator_t *enumerator;
	host_t *addr;
	char *name;
	bool found = FALSE;

	enumerator = tuns->create_enumerator(tuns);
	while (enumerator->enumerate(enumerator, &entry))
	{
		name = entry->tun->get_name(entry->tun);
		addr = entry->tun->get_address(entry->tun, NULL);
		if (addr)
		{
			if (addr->ip_equals(addr, ip) || IGNORE_VIP_CHANGES)
			{
				found = TRUE;
				break;
			}
		}
		else
		{
			DBG1(DBG_KNL, "%s has no associated address", name);
		}
	}
	enumerator->destroy(enumerator);
	return found ? entry : NULL;
}

/**
 * Private variables and functions of kernel_syscfg class.
 */
struct private_kernel_syscfg_net_t
{
	/**
	 * Public part of the kernel_syscfg_t object.
	 */
	kernel_syscfg_net_t public;

	/**
	 * lock to access lists and maps
	 */
	rwlock_t *lock;

	/**
	 * Cached list of interfaces and their addresses (iface_entry_t)
	 */
	linked_list_t *ifaces;

	/**
	 * Map for IP addresses to iface_entry_t objects (addr_map_entry_t)
	 */
	hashtable_t *addrs;

	/**
	 * List of tun devices we installed for virtual IPs (tun_entry_t)
	 */
	linked_list_t *tuns;

	/**
	 * mutex to communicate exclusively with PF_KEY
	 */
	mutex_t *mutex;

	/**
	 * condvar to signal if PF_KEY query got a response
	 */
	condvar_t *condvar;

	/**
	 * installed routes
	 */
	hashtable_t *routes;

	/**
	 * mutex for routes
	 */
	mutex_t *routes_lock;

	/**
	 * interface changes which may trigger route reinstallation
	 */
	hashtable_t *net_changes;

	/**
	 * mutex for route reinstallation triggers
	 */
	mutex_t *net_changes_lock;

	/**
	 * time of last route reinstallation
	 */
	timeval_t last_route_reinstall;

	/**
	 * pid to send PF_ROUTE messages with
	 */
	pid_t pid;

	/**
	 * PF_ROUTE socket to communicate with the kernel
	 */
	int socket;

	/**
	 * sequence number for messages sent to the kernel
	 */
	int seq;

	/**
	 * Sequence number a query is waiting for
	 */
	int waiting_seq;

	/**
	 * Allocated reply message from kernel
	 */
	struct rt_msghdr *reply;

	/**
	 * earliest time of the next roam event
	 */
	timeval_t next_roam;

	/**
	 * roam event due to address change
	 */
	bool roam_address;

	/**
	 * lock to check and update roam event time
	 */
	spinlock_t *roam_lock;

	/**
	 * Time in ms to wait for IP addresses to appear/disappear
	 */
	int vip_wait;

	/**
	 * whether to actually install virtual IPs
	 */
	bool install_virtual_ip;

	/**
	 * runloop source which generates IP change events
	 */
	CFRunLoopSourceRef runloop_source;

	/**
	 * runloop reference
	 */
	CFRunLoopRef runloop_ref;

	/**
	 * thread that runs the runloop
	 */
	thread_t *runloop;

	/**
	 * system configuration store handle
	 */
	SCDynamicStoreRef dynamic_store;

	/**
	 * patters and pattern list for system configuration
	 */
	CFStringRef patterns[2];
	CFArrayRef pattern_list;
};


/**
 * Forward declaration
 */
static status_t manage_route(private_kernel_syscfg_net_t *this, int op,
							 chunk_t dst_net, uint8_t prefixlen,
							 host_t *gateway, char *if_name);

/**
 * Clear the queued network changes.
 */
static void net_changes_clear(private_kernel_syscfg_net_t *this)
{
	enumerator_t *enumerator;
	net_change_t *change;

	enumerator = this->net_changes->create_enumerator(this->net_changes);
	while (enumerator->enumerate(enumerator, NULL, (void**)&change))
	{
		this->net_changes->remove_at(this->net_changes, enumerator);
		net_change_destroy(change);
	}
	enumerator->destroy(enumerator);
}

/**
 * Act upon queued network changes.
 */
static job_requeue_t reinstall_routes(private_kernel_syscfg_net_t *this)
{
	enumerator_t *enumerator;
	route_entry_t *route;

	this->net_changes_lock->lock(this->net_changes_lock);
	this->routes_lock->lock(this->routes_lock);

	enumerator = this->routes->create_enumerator(this->routes);
	while (enumerator->enumerate(enumerator, NULL, (void**)&route))
	{
		net_change_t *change, lookup = {
			.if_name = route->if_name,
		};
		/* check if a change for the outgoing interface is queued */
		change = this->net_changes->get(this->net_changes, &lookup);
		if (change)
		{
			manage_route(this, RTM_ADD, route->dst_net, route->prefixlen,
						 route->gateway, route->if_name);
		}
	}
	enumerator->destroy(enumerator);
	this->routes_lock->unlock(this->routes_lock);

	net_changes_clear(this);
	this->net_changes_lock->unlock(this->net_changes_lock);
	return JOB_REQUEUE_NONE;
}

/**
 * Queue route reinstallation caused by network changes for a given interface.
 *
 * The route reinstallation is delayed for a while and only done once for
 * several calls during this delay, in order to avoid doing it too often.
 * The interface name is freed.
 */
static void queue_route_reinstall(private_kernel_syscfg_net_t *this,
								  char *if_name)
{
	net_change_t *update, *found;
	timeval_t now;
	job_t *job;

	INIT(update,
		.if_name = if_name
	);

	this->net_changes_lock->lock(this->net_changes_lock);
	found = this->net_changes->put(this->net_changes, update, update);
	if (found)
	{
		net_change_destroy(found);
	}
	time_monotonic(&now);
	if (timercmp(&now, &this->last_route_reinstall, >))
	{
		timeval_add_ms(&now, ROUTE_DELAY);
		this->last_route_reinstall = now;

		job = (job_t*)callback_job_create((callback_job_cb_t)reinstall_routes,
										  this, NULL, NULL);
		lib->scheduler->schedule_job_ms(lib->scheduler, job, ROUTE_DELAY);
	}
	this->net_changes_lock->unlock(this->net_changes_lock);
}

/**
 * Add an address map entry
 */
static void addr_map_entry_add(private_kernel_syscfg_net_t *this,
							   addr_entry_t *addr, iface_entry_t *iface)
{
	addr_map_entry_t *entry;

	INIT(entry,
		.ip = addr->ip,
		.addr = addr,
		.iface = iface,
	);
	entry = this->addrs->put(this->addrs, entry, entry);
	free(entry);
}

/**
 * Remove an address map entry (the argument order is a bit strange because
 * it is also used with linked_list_t.invoke_function)
 */
static void addr_map_entry_remove(addr_entry_t *addr, iface_entry_t *iface,
								  private_kernel_syscfg_net_t *this)
{
	addr_map_entry_t *entry, lookup = {
		.ip = addr->ip,
		.addr = addr,
		.iface = iface,
	};

	entry = this->addrs->remove(this->addrs, &lookup);
	free(entry);
}

/**
 * callback function that raises the delayed roam event
 */
static job_requeue_t roam_event(private_kernel_syscfg_net_t *this)
{
	bool address;

	this->roam_lock->lock(this->roam_lock);
	address = this->roam_address;
	this->roam_address = FALSE;
	this->roam_lock->unlock(this->roam_lock);
	charon->kernel->roam(charon->kernel, address);
	return JOB_REQUEUE_NONE;
}

/**
 * fire a roaming event. we delay it for a bit and fire only one event
 * for multiple calls. otherwise we would create too many events.
 */
static void fire_roam_event(private_kernel_syscfg_net_t *this, bool address)
{
	timeval_t now;
	job_t *job;

	time_monotonic(&now);
	this->roam_lock->lock(this->roam_lock);
	this->roam_address |= address;
	if (!timercmp(&now, &this->next_roam, >))
	{
		this->roam_lock->unlock(this->roam_lock);
		return;
	}
	timeval_add_ms(&now, ROAM_DELAY);
	this->next_roam = now;
	this->roam_lock->unlock(this->roam_lock);

	job = (job_t*)callback_job_create((callback_job_cb_t)roam_event,
									  this, NULL, NULL);
	lib->scheduler->schedule_job_ms(lib->scheduler, job, ROAM_DELAY);
}

/**
 * Data for enumerator over rtmsg sockaddrs
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** copy of attribute bitfield */
	int types;
	/** bytes remaining in buffer */
	int remaining;
	/** next sockaddr to enumerate */
	struct sockaddr *addr;
} rt_enumerator_t;

METHOD(enumerator_t, rt_enumerate, bool,
	rt_enumerator_t *this, va_list args)
{
	struct sockaddr **addr;
	int i, type, *xtype;

	VA_ARGS_VGET(args, xtype, addr);

	if (this->remaining < sizeof(this->addr->sa_len) ||
		this->remaining < this->addr->sa_len)
	{
		return FALSE;
	}
	for (i = 0; i < RTAX_MAX; i++)
	{
		type = (1 << i);
		if (this->types & type)
		{
			this->types &= ~type;
			*addr = this->addr;
			*xtype = i;
			this->remaining -= SA_LEN(this->addr->sa_len);
			this->addr = (struct sockaddr*)((char*)this->addr +
											SA_LEN(this->addr->sa_len));
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Create an enumerator over sockaddrs in rt/if messages
 */
static enumerator_t *create_rt_enumerator(int types, int remaining,
										  struct sockaddr *addr)
{
	rt_enumerator_t *this;

	INIT(this,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _rt_enumerate,
			.destroy = (void*)free,
		},
		.types = types,
		.remaining = remaining,
		.addr = addr,
	);
	return &this->public;
}

/**
 * Create a safe enumerator over sockaddrs in rt_msghdr
 */
static enumerator_t *create_rtmsg_enumerator(struct rt_msghdr *hdr)
{
	return create_rt_enumerator(hdr->rtm_addrs, hdr->rtm_msglen - sizeof(*hdr),
								(struct sockaddr *)(hdr + 1));
}

/**
 * Receives PF_ROUTE messages from kernel
 */
static bool receive_events(private_kernel_syscfg_net_t *this, int fd,
						   watcher_event_t event)
{
	struct {
		union {
			struct rt_msghdr rtm;
			struct if_msghdr ifm;
			struct ifa_msghdr ifam;
#ifdef HAVE_RTM_IFANNOUNCE
			struct if_announcemsghdr ifanm;
#endif
		};
		char buf[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} msg;
	int len, hdrlen;

	len = recv(this->socket, &msg, sizeof(msg), MSG_DONTWAIT);
	if (len < 0)
	{
		switch (errno)
		{
			case EINTR:
			case EAGAIN:
				return TRUE;
			default:
				DBG1(DBG_KNL, "unable to receive from PF_ROUTE event socket");
				sleep(1);
				return TRUE;
		}
	}

	if (len < offsetof(struct rt_msghdr, rtm_flags) || len < msg.rtm.rtm_msglen)
	{
		DBG1(DBG_KNL, "received invalid PF_ROUTE message");
		return TRUE;
	}
	if (msg.rtm.rtm_version != RTM_VERSION)
	{
		DBG1(DBG_KNL, "received PF_ROUTE message with unsupported version: %d",
			 msg.rtm.rtm_version);
		return TRUE;
	}
	switch (msg.rtm.rtm_type)
	{
		case RTM_NEWADDR:
		case RTM_DELADDR:
			hdrlen = sizeof(msg.ifam);
			break;
		case RTM_IFINFO:
			hdrlen = sizeof(msg.ifm);
			break;
#ifdef HAVE_RTM_IFANNOUNCE
		case RTM_IFANNOUNCE:
			hdrlen = sizeof(msg.ifanm);
			break;
#endif /* HAVE_RTM_IFANNOUNCE */
		case RTM_ADD:
		case RTM_DELETE:
		case RTM_GET:
			hdrlen = sizeof(msg.rtm);
			break;
		default:
			return TRUE;
	}
	if (msg.rtm.rtm_msglen < hdrlen)
	{
		DBG1(DBG_KNL, "ignoring short PF_ROUTE message");
		return TRUE;
	}
	switch (msg.rtm.rtm_type)
	{
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_IFINFO:
			break;
#ifdef HAVE_RTM_IFANNOUNCE
		case RTM_IFANNOUNCE:
			break;
#endif /* HAVE_RTM_IFANNOUNCE */
		case RTM_ADD:
		case RTM_DELETE:
			break;
		default:
			break;
	}

	this->mutex->lock(this->mutex);
	if (msg.rtm.rtm_pid == this->pid && msg.rtm.rtm_seq == this->waiting_seq)
	{
		/* seems like the message someone is waiting for, deliver */
		this->reply = realloc(this->reply, msg.rtm.rtm_msglen);
		memcpy(this->reply, &msg, msg.rtm.rtm_msglen);
	}
	/* signal on any event, get_route() might wait for it */
	this->condvar->broadcast(this->condvar);
	this->mutex->unlock(this->mutex);

	return TRUE;
}


/** enumerator over addresses */
typedef struct {
	private_kernel_syscfg_net_t* this;
	/** which addresses to enumerate */
	kernel_address_type_t which;
} address_enumerator_t;

CALLBACK(address_enumerator_destroy, void,
	address_enumerator_t *data)
{
	data->this->lock->unlock(data->this->lock);
	free(data);
}

CALLBACK(filter_addresses, bool,
	address_enumerator_t *data, enumerator_t *orig, va_list args)
{
	addr_entry_t *addr;
	host_t *ip, **out;
	struct sockaddr_in6 *sin6;

	VA_ARGS_VGET(args, out);

	while (orig->enumerate(orig, &addr))
	{
		if (!(data->which & ADDR_TYPE_VIRTUAL) && addr->virtual)
		{   /* skip virtual interfaces added by us */
			continue;
		}
		if (!(data->which & ADDR_TYPE_REGULAR) && !addr->virtual)
		{	/* address is regular, but not requested */
			continue;
		}
		ip = addr->ip;
		if (ip->get_family(ip) == AF_INET6)
		{
			sin6 = (struct sockaddr_in6 *)ip->get_sockaddr(ip);
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			{   /* skip addresses with a unusable scope */
				continue;
			}
		}
		*out = ip;
		return TRUE;
	}
	return FALSE;
}

/**
 * enumerator constructor for interfaces
 */
static enumerator_t *create_iface_enumerator(iface_entry_t *iface,
											 address_enumerator_t *data)
{
	return enumerator_create_filter(iface->addrs->create_enumerator(iface->addrs),
									filter_addresses, data, NULL);
}

CALLBACK(filter_interfaces, bool,
	address_enumerator_t *data, enumerator_t *orig, va_list args)
{
	iface_entry_t *iface, **out;

	VA_ARGS_VGET(args, out);

	while (orig->enumerate(orig, &iface))
	{
		*out = iface;
		return TRUE;
	}
	return FALSE;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_syscfg_net_t *this, kernel_address_type_t which)
{
	address_enumerator_t *data;

	INIT(data,
		.this = this,
		.which = which,
	);

	this->lock->read_lock(this->lock);
	return enumerator_create_nested(
				enumerator_create_filter(
					this->ifaces->create_enumerator(this->ifaces),
					filter_interfaces, data, NULL),
				(void*)create_iface_enumerator, data,
				address_enumerator_destroy);
}

METHOD(kernel_net_t, get_features, kernel_feature_t,
	private_kernel_syscfg_net_t *this)
{
	return KERNEL_REQUIRE_EXCLUDE_ROUTE;
}

METHOD(kernel_net_t, get_interface_name, bool,
	private_kernel_syscfg_net_t *this, host_t* ip, char **name)
{
	addr_map_entry_t *entry, lookup = {
		.ip = ip,
	};

	if (ip->is_anyaddr(ip))
	{
		return FALSE;
	}
	this->lock->read_lock(this->lock);
	/* first try to find it on an up and usable interface */
	entry = this->addrs->get_match(this->addrs, &lookup,
								  (void*)addr_map_entry_match_up_and_usable);
	if (entry)
	{
		if (name)
		{
			*name = strdup(entry->iface->ifname);
			DBG2(DBG_KNL, "%H is on interface %s", ip, *name);
		}
		this->lock->unlock(this->lock);
		return TRUE;
	}
	/* check if it is a virtual IP */
	entry = this->addrs->get_match(this->addrs, &lookup,
								  (void*)addr_map_entry_match_virtual);
	if (entry)
	{
		if (name)
		{
			*name = strdup(entry->iface->ifname);
			DBG2(DBG_KNL, "virtual IP %H is on interface %s", ip, *name);
		}
		this->lock->unlock(this->lock);
		return TRUE;
	}
	/* maybe it is installed on an ignored interface */
	entry = this->addrs->get_match(this->addrs, &lookup,
								  (void*)addr_map_entry_match_up);
	if (!entry)
	{	/* the address does not exist, is on a down interface */
		DBG2(DBG_KNL, "%H is not a local address or the interface is down", ip);
	}
	this->lock->unlock(this->lock);
	return FALSE;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_syscfg_net_t *this, host_t *vip, int prefix,
	char *ifname)
{
	enumerator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	tun_device_t *tun_dev;
	bool timeout = FALSE, found = FALSE;
	tun_entry_t *tun = NULL;

	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	DBG2(DBG_KNL, "adding virtual IP %H", vip);

	/* If we already have a TUN adapter with this virtual IP we want to continue
	 * using it. So just increase the reference count and return success. */
	this->lock->write_lock(this->lock);
	tun = tun_entry_find(this->tuns, vip);
	if (tun)
	{
		found = TRUE;
		tun->count++;
		DBG2(DBG_KNL, "%s:%H found, count = %d", tun->tun->get_name(tun->tun), vip, tun->count);
	}
	this->lock->unlock(this->lock);
	if (found)
	{
		return SUCCESS;
	}

	/* We don't yet have a TUN device with this virtual IP, so create one and
	 * add it to our list. */
	tun_dev = tun_device_create(NULL);
	if (!tun_dev)
	{
		return FAILED;
	}
	if (prefix == -1)
	{
		prefix = vip->get_address(vip).len * 8;
	}
	if (!tun_dev->up(tun_dev) || !tun_dev->set_address(tun_dev, vip, prefix))
	{
		tun_dev->destroy(tun_dev);
		return FAILED;
	}
	if (!tun_dev->set_mtu(tun_dev, TUN_DEFAULT_MTU))
	{
		/* not a fatal error */
		DBG1(DBG_KNL, "failed to set MTU to %d on %s",
			 TUN_DEFAULT_MTU, tun_dev->get_name(tun_dev));
	}

	/* wait until address appears */
	this->mutex->lock(this->mutex);
	while (!timeout && !get_interface_name(this, vip, NULL))
	{
		timeout = this->condvar->timed_wait(this->condvar, this->mutex,
											this->vip_wait);
	}
	this->mutex->unlock(this->mutex);
	if (timeout)
	{
		DBG1(DBG_KNL, "virtual IP %H did not appear on %s",
			 vip, tun_dev->get_name(tun_dev));
		tun_dev->destroy(tun_dev);
		return FAILED;
	}

	INIT(tun,
		 .tun = tun_dev,
		 .count = 1,
	);

	this->lock->write_lock(this->lock);
	this->tuns->insert_last(this->tuns, tun);

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		if (streq(iface->ifname, tun_dev->get_name(tun_dev)))
		{
			addrs = iface->addrs->create_enumerator(iface->addrs);
			while (addrs->enumerate(addrs, &addr))
			{
				if (addr->ip->ip_equals(addr->ip, vip))
				{
					addr->virtual = TRUE;
				}
			}
			addrs->destroy(addrs);
			/* during IKEv1 reauthentication, children get moved from
			 * old the new SA before the virtual IP is available. This
			 * kills the route for our virtual IP, reinstall. */
			queue_route_reinstall(this, strdup(iface->ifname));
			break;
		}
	}
	ifaces->destroy(ifaces);
	/* lets do this while holding the lock, thus preventing another thread
	 * from deleting the TUN device concurrently, hopefully listeners are quick
	 * and cause no deadlocks */
	charon->kernel->tun(charon->kernel, tun_dev, TRUE);
	this->lock->unlock(this->lock);

	return SUCCESS;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_syscfg_net_t *this, host_t *vip, int prefix,
	bool wait)
{
	tun_entry_t *tun;
	bool timeout = FALSE, found = FALSE, alive = FALSE;

	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	DBG2(DBG_KNL, "deleting virtual IP %H", vip);

	this->lock->write_lock(this->lock);
	tun = tun_entry_find(this->tuns, vip);
	if (tun)
	{
		tun->count--;
		if (tun->count > 0)
		{
			DBG2(DBG_KNL, "%s:%H not destroyed, count = %d", tun->tun->get_name(tun->tun), vip, tun->count);
			alive = TRUE;
		}
		else
		{
			DBG2(DBG_KNL, "destroying %s:%H", tun->tun->get_name(tun->tun), vip);
			this->tuns->remove(this->tuns, tun, NULL);
			charon->kernel->tun(charon->kernel, tun->tun, FALSE);
			tun_entry_destroy(tun);
		}
		found = TRUE;
	}
	this->lock->unlock(this->lock);

	if (!found)
	{
		return NOT_FOUND;
	}
	else if (alive)
	{
		return SUCCESS;
	}

	/* wait until address disappears */
	if (wait)
	{
		this->mutex->lock(this->mutex);
		while (!timeout && get_interface_name(this, vip, NULL))
		{
			timeout = this->condvar->timed_wait(this->condvar, this->mutex,
												this->vip_wait);
		}
		this->mutex->unlock(this->mutex);
		if (timeout)
		{
			DBG1(DBG_KNL, "virtual IP %H did not disappear from tun", vip);
			return FAILED;
		}
	}
	return SUCCESS;
}

/**
 * Append a sockaddr_in/in6 of given type to routing message
 */
static void add_rt_addr(struct rt_msghdr *hdr, int type, host_t *addr)
{
	if (addr)
	{
		int len;

		len = *addr->get_sockaddr_len(addr);
		memcpy((char*)hdr + hdr->rtm_msglen, addr->get_sockaddr(addr), len);
		hdr->rtm_msglen += SA_LEN(len);
		hdr->rtm_addrs |= type;
	}
}

/**
 * Append a subnet mask sockaddr using the given prefix to routing message
 */
static void add_rt_mask(struct rt_msghdr *hdr, int type, int family, int prefix)
{
	host_t *mask;

	mask = host_create_netmask(family, prefix);
	if (mask)
	{
		add_rt_addr(hdr, type, mask);
		mask->destroy(mask);
	}
}

/**
 * Append an interface name sockaddr_dl to routing message
 */
static void add_rt_ifname(struct rt_msghdr *hdr, int type, char *name)
{
	struct sockaddr_dl sdl = {
		.sdl_len = sizeof(struct sockaddr_dl),
		.sdl_family = AF_LINK,
		.sdl_nlen = strlen(name),
	};

	if (strlen(name) <= sizeof(sdl.sdl_data))
	{
		memcpy(sdl.sdl_data, name, sdl.sdl_nlen);
		memcpy((char*)hdr + hdr->rtm_msglen, &sdl, sdl.sdl_len);
		hdr->rtm_msglen += SA_LEN(sdl.sdl_len);
		hdr->rtm_addrs |= type;
	}
}

/**
 * Add or remove a route
 */
static status_t manage_route(private_kernel_syscfg_net_t *this, int op,
							 chunk_t dst_net, uint8_t prefixlen,
							 host_t *gateway, char *if_name)
{
	struct {
		struct rt_msghdr hdr;
		char buf[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} msg = {
		.hdr = {
			.rtm_version = RTM_VERSION,
			.rtm_type = op,
			.rtm_flags = RTF_UP | RTF_STATIC,
			.rtm_pid = this->pid,
			.rtm_seq = ref_get(&this->seq),
		},
	};
	host_t *dst;
	int type;

	if (prefixlen == 0 && dst_net.len)
	{
		status_t status;
		chunk_t half;

		half = chunk_clonea(dst_net);
		half.ptr[0] |= 0x80;
		prefixlen = 1;
		status = manage_route(this, op, half, prefixlen, gateway, if_name);
		if (status != SUCCESS)
		{
			return status;
		}
	}

	dst = host_create_from_chunk(AF_UNSPEC, dst_net, 0);
	if (!dst)
	{
		DBG1(DBG_KNL, "failed to create host from chunk");
		return FAILED;
	}

	if ((dst->get_family(dst) == AF_INET && prefixlen == 32) ||
		(dst->get_family(dst) == AF_INET6 && prefixlen == 128))
	{
		msg.hdr.rtm_flags |= RTF_HOST | RTF_GATEWAY;
	}

	msg.hdr.rtm_msglen = sizeof(struct rt_msghdr);
	for (type = 0; type < RTAX_MAX; type++)
	{
		switch (type)
		{
			case RTAX_DST:
				add_rt_addr(&msg.hdr, RTA_DST, dst);
				break;
			case RTAX_NETMASK:
				if (!(msg.hdr.rtm_flags & RTF_HOST))
				{
					add_rt_mask(&msg.hdr, RTA_NETMASK,
								dst->get_family(dst), prefixlen);
				}
				break;
			case RTAX_IFP:
				if (if_name)
				{
					add_rt_ifname(&msg.hdr, RTA_IFP, if_name);
				}
				break;
			case RTAX_GATEWAY:
				if (gateway &&
					gateway->get_family(gateway) == dst->get_family(dst))
				{
					add_rt_addr(&msg.hdr, RTA_GATEWAY, gateway);
				}
				break;
			default:
				break;
		}
	}
	dst->destroy(dst);

	if (send(this->socket, &msg, msg.hdr.rtm_msglen, 0) != msg.hdr.rtm_msglen)
	{
		if (errno == EEXIST)
		{
			return ALREADY_DONE;
		}
		DBG1(DBG_KNL, "%s PF_ROUTE route failed: %s",
			 op == RTM_ADD ? "adding" : "deleting", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_syscfg_net_t *this, chunk_t dst_net, uint8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	status_t status;
	route_entry_t *found, route = {
		.dst_net = dst_net,
		.prefixlen = prefixlen,
		.gateway = gateway,
		.if_name = if_name,
	};

	this->routes_lock->lock(this->routes_lock);
	found = this->routes->get(this->routes, &route);
	if (found)
	{
		this->routes_lock->unlock(this->routes_lock);
		return ALREADY_DONE;
	}
	status = manage_route(this, RTM_ADD, dst_net, prefixlen, gateway, if_name);
	if (status == SUCCESS)
	{
		found = route_entry_clone(&route);
		this->routes->put(this->routes, found, found);
	}
	this->routes_lock->unlock(this->routes_lock);
	return status;
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_syscfg_net_t *this, chunk_t dst_net, uint8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	status_t status;
	route_entry_t *found, route = {
		.dst_net = dst_net,
		.prefixlen = prefixlen,
		.gateway = gateway,
		.if_name = if_name,
	};

	this->routes_lock->lock(this->routes_lock);
	found = this->routes->get(this->routes, &route);
	if (!found)
	{
		this->routes_lock->unlock(this->routes_lock);
		return NOT_FOUND;
	}
	this->routes->remove(this->routes, found);
	route_entry_destroy(found);
	status = manage_route(this, RTM_DELETE, dst_net, prefixlen, gateway,
						  if_name);
	this->routes_lock->unlock(this->routes_lock);
	return status;
}

/**
 * Do a route lookup for dest and return either the nexthop or the source
 * address.
 */
static host_t *get_route(private_kernel_syscfg_net_t *this, bool nexthop,
						 host_t *dest, host_t *src, char **iface)
{
	struct {
		struct rt_msghdr hdr;
		char buf[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} msg = {
		.hdr = {
			.rtm_version = RTM_VERSION,
			.rtm_type = RTM_GET,
			.rtm_pid = this->pid,
			.rtm_seq = ref_get(&this->seq),
		},
	};
	host_t *host = NULL;
	enumerator_t *enumerator;
	struct sockaddr *addr;
	bool failed = FALSE;
	int type;

	if ( src )
	{
		/* We were given a source interface, make sure it exists. If it doesn't
		 * then there's no way we could find a route that uses it. */
		this->mutex->lock(this->mutex);
		failed = !get_interface_name(this, src, NULL);
		this->mutex->unlock(this->mutex);
		if (failed)
		{
			DBG1(DBG_KNL, "interface for source address %H not found", src);
			return NULL;
		}
	}

retry:
	msg.hdr.rtm_msglen = sizeof(struct rt_msghdr);
	for (type = 0; type < RTAX_MAX; type++)
	{
		switch (type)
		{
			case RTAX_DST:
				add_rt_addr(&msg.hdr, RTA_DST, dest);
				break;
			case RTAX_IFA:
				add_rt_addr(&msg.hdr, RTA_IFA, src);
				break;
			case RTAX_IFP:
				if (!nexthop)
				{	/* add an empty IFP to ensure we get a source address */
					add_rt_ifname(&msg.hdr, RTA_IFP, "");
				}
				break;
			default:
				break;
		}
	}
	this->mutex->lock(this->mutex);

	while (this->waiting_seq)
	{
		this->condvar->wait(this->condvar, this->mutex);
	}
	this->waiting_seq = msg.hdr.rtm_seq;
	if (send(this->socket, &msg, msg.hdr.rtm_msglen, 0) == msg.hdr.rtm_msglen)
	{
		while (TRUE)
		{
			if (this->condvar->timed_wait(this->condvar, this->mutex, 1000))
			{	/* timed out? */
				DBG1(DBG_KNL, "get_route: timed out waiting for condition variable");
				break;
			}
			if (!this->reply)
			{
				DBG1(DBG_KNL, "get_route: no reply");
				continue;
			}
			enumerator = create_rtmsg_enumerator(this->reply);
			while (enumerator->enumerate(enumerator, &type, &addr))
			{
				if (nexthop)
				{
					if (type == RTAX_DST && this->reply->rtm_flags & RTF_HOST)
					{	/* probably a cloned/cached direct route, only use that
						 * as fallback if no gateway is found */
						host = host ?: host_create_from_sockaddr(addr);
					}
					if (type == RTAX_GATEWAY)
					{	/* could actually be a MAC address */
						host_t *gtw = host_create_from_sockaddr(addr);
						if (gtw)
						{
							DESTROY_IF(host);
							host = gtw;
						}
					}
					if (type == RTAX_IFP && addr->sa_family == AF_LINK)
					{
						struct sockaddr_dl *sdl = (struct sockaddr_dl*)addr;
						if (iface)
						{
							free(*iface);
							*iface = strndup(sdl->sdl_data, sdl->sdl_nlen);
						}
					}
				}
				else
				{
					if (type == RTAX_IFA)
					{
						host = host_create_from_sockaddr(addr);
					}
				}
			}
			enumerator->destroy(enumerator);
			break;
		}
	}
	else
	{
		DBG1(DBG_KNL, "get_route: send failed");
		failed = TRUE;
	}
	free(this->reply);
	this->reply = NULL;
	/* signal completion of query to a waiting thread */
	this->waiting_seq = 0;
	this->condvar->signal(this->condvar);
	this->mutex->unlock(this->mutex);

	if (failed)
	{
		if (src)
		{	/* the given source address might be gone, try again without */
			src = NULL;
			msg.hdr.rtm_seq = ref_get(&this->seq);
			msg.hdr.rtm_addrs = 0;
			memset(msg.buf, 0, sizeof(msg.buf));
			goto retry;
		}
		DBG1(DBG_KNL, "PF_ROUTE lookup failed: %s", strerror(errno));
	}
	if (nexthop)
	{
		host = host ?: dest->clone(dest);
	}
	else
	{	/* make sure the source address is not virtual and usable */
		addr_entry_t *entry, lookup = {
			.ip = host,
		};

		if (!host)
		{
			DBG2(DBG_KNL, "get_route: no host found");
			return NULL;
		}
		this->lock->read_lock(this->lock);
		entry = this->addrs->get_match(this->addrs, &lookup,
									(void*)addr_map_entry_match_up_and_usable);
		this->lock->unlock(this->lock);
		if (!entry)
		{
			host->destroy(host);
			DBG2(DBG_KNL, "get_route: host %H not matched", host);
			return NULL;
		}
	}
	DBG2(DBG_KNL, "using %H as %s to reach %H", host,
		 nexthop ? "nexthop" : "address", dest);
	return host;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_syscfg_net_t *this, host_t *dest, host_t *src)
{
	return get_route(this, FALSE, dest, src, NULL);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_syscfg_net_t *this, host_t *dest, int prefix, host_t *src,
	char **iface)
{
	if (iface)
	{
		*iface = NULL;
	}
	return get_route(this, TRUE, dest, src, iface);
}

/**
 * Get the number of set bits in the given netmask
 */
static uint8_t sockaddr_to_netmask(sockaddr_t *sockaddr, host_t *dst)
{
	uint8_t len = 0, i, byte, mask = 0;
	struct sockaddr_storage ss;
	char *addr;

	/* at least some older FreeBSD versions send us shorter sockaddrs
	 * with the family set to -1 (255) */
	if (sockaddr->sa_family == 255)
	{
		memset(&ss, 0, sizeof(ss));
		memcpy(&ss, sockaddr, sockaddr->sa_len);
		/* use the address family and length of the destination as hint */
		ss.ss_len = *dst->get_sockaddr_len(dst);
		ss.ss_family = dst->get_family(dst);
		sockaddr = (sockaddr_t*)&ss;
	}

	switch (sockaddr->sa_family)
	{
		case AF_INET:
			len = 4;
			addr = (char*)&((struct sockaddr_in*)sockaddr)->sin_addr;
			break;
		case AF_INET6:
			len = 16;
			addr = (char*)&((struct sockaddr_in6*)sockaddr)->sin6_addr;
			break;
		default:
			break;
	}

	for (i = 0; i < len; i++)
	{
		byte = addr[i];

		if (byte == 0x00)
		{
			break;
		}
		if (byte == 0xff)
		{
			mask += 8;
		}
		else
		{
			while (byte & 0x80)
			{
				mask++;
				byte <<= 1;
			}
		}
	}
	return mask;
}

/** enumerator over subnets */
typedef struct {
	enumerator_t public;
	/** sysctl result */
	char *buf;
	/** length of the complete result */
	size_t len;
	/** start of the current route entry */
	char *current;
	/** last subnet enumerated */
	host_t *net;
	/** interface of current net */
	char *ifname;
} subnet_enumerator_t;

METHOD(enumerator_t, destroy_subnet_enumerator, void,
	subnet_enumerator_t *this)
{
	DESTROY_IF(this->net);
	free(this->ifname);
	free(this->buf);
	free(this);
}

METHOD(enumerator_t, enumerate_subnets, bool,
	subnet_enumerator_t *this, va_list args)
{
	enumerator_t *enumerator;
	host_t **net;
	struct rt_msghdr *rtm;
	struct sockaddr *addr;
	uint8_t *mask;
	char **ifname;
	int type;

	VA_ARGS_VGET(args, net, mask, ifname);

	if (!this->current)
	{
		this->current = this->buf;
	}
	else
	{
		rtm = (struct rt_msghdr*)this->current;
		this->current += rtm->rtm_msglen;
		DESTROY_IF(this->net);
		this->net = NULL;
		free(this->ifname);
		this->ifname = NULL;
	}

	for (; this->current < this->buf + this->len;
		 this->current += rtm->rtm_msglen)
	{
		struct sockaddr *netmask = NULL;
		uint8_t netbits = 0;

		rtm = (struct rt_msghdr*)this->current;

		if (rtm->rtm_version != RTM_VERSION)
		{
			continue;
		}
		if (rtm->rtm_flags & RTF_GATEWAY ||
			rtm->rtm_flags & RTF_HOST ||
			rtm->rtm_flags & RTF_REJECT)
		{
			continue;
		}
		enumerator = create_rtmsg_enumerator(rtm);
		while (enumerator->enumerate(enumerator, &type, &addr))
		{
			if (type == RTAX_DST)
			{
				this->net = this->net ?: host_create_from_sockaddr(addr);
			}
			if (type == RTAX_NETMASK)
			{
				netmask = addr;
			}
			if (type == RTAX_IFP && addr->sa_family == AF_LINK)
			{
				struct sockaddr_dl *sdl = (struct sockaddr_dl*)addr;
				free(this->ifname);
				this->ifname = strndup(sdl->sdl_data, sdl->sdl_nlen);
			}
		}
		if (this->net && netmask)
		{
			netbits = sockaddr_to_netmask(netmask, this->net);
		}
		enumerator->destroy(enumerator);

		if (this->net && this->ifname)
		{
			*net = this->net;
			*mask = netbits ?: this->net->get_address(this->net).len * 8;
			*ifname = this->ifname;
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(kernel_net_t, create_local_subnet_enumerator, enumerator_t*,
	private_kernel_syscfg_net_t *this)
{
	subnet_enumerator_t *enumerator;
	char *buf;
	size_t len;
	int mib[7] = {
		CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0, 0
	};

	if (sysctl(mib, countof(mib), NULL, &len, NULL, 0) < 0)
	{
		DBG2(DBG_KNL, "enumerating local subnets failed");
		return enumerator_create_empty();
	}
	buf = malloc(len);
	if (sysctl(mib, countof(mib), buf, &len, NULL, 0) < 0)
	{
		DBG2(DBG_KNL, "enumerating local subnets failed");
		free(buf);
		return enumerator_create_empty();
	}

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _enumerate_subnets,
			.destroy = _destroy_subnet_enumerator,
		},
		.buf = buf,
		.len = len,
	);
	return &enumerator->public;
}

/* Extract the string from the CFStringRef into the given C string buffer */
static status_t to_char_str( CFStringRef str_ref, char *buf, size_t buf_len )
{
	CFStringEncoding encoding = kCFStringEncodingMacRoman;
	CFIndex len, max_size;

	len = CFStringGetLength( str_ref );
	if ( len <= 0 )
	{
		return FAILED;
	}

	max_size = CFStringGetMaximumSizeForEncoding( len, encoding );
	if ( max_size <= 0 )
	{
		return FAILED;
	}
	max_size += 1;
	if ( max_size > buf_len )
	{
		DBG1(DBG_KNL, "can't copy string ref, buffer size %d given, %d required", buf_len, max_size);
		return FAILED;
	}

	if ( !CFStringGetCString( str_ref, buf, max_size, encoding ) )
	{
		return FAILED;
	}

	return SUCCESS;
}

/* ifname is assumed to be at least IFNAMSIZ + 1 bytes */
static status_t parse_key_ref( CFStringRef key_ref, char *ifname, int *family )
{
	CFRange range;
	CFStringRef ifname_ref;
	static CFStringRef prefix = CFSTR("State:/Network/Interface/");
	CFIndex prefix_len = CFStringGetLength( prefix );
	static CFStringRef suffix = CFSTR("/IPv4");
	CFIndex suffix_len = CFStringGetLength( suffix );

	if ( !CFStringHasPrefix( key_ref, CFSTR("State:/Network/Interface/") ) )
	{
		/* The key is not correct - ignore */
		 return FAILED;
	}

	if ( CFStringHasSuffix( key_ref, CFSTR("/IPv4") ) )
	{
		*family = AF_INET;
	}
	else if ( CFStringHasSuffix( key_ref, CFSTR("/IPv6") ) )
	{
		*family = AF_INET6;
	}
	else
	{
		/* The key is not correct - ignore */
		return FAILED;
	}

	/* Extract the interface name substring */
	range.location = prefix_len;
	range.length = CFStringGetLength( key_ref ) - prefix_len - suffix_len;
	ifname_ref = CFStringCreateWithSubstring( NULL, key_ref, range );
	return to_char_str( ifname_ref, ifname, IFNAMSIZ );
}

static bool ignore_address( CFStringRef addr_ref )
{
	/* Ignore link local addresses */
	CFRange range = CFStringFind( addr_ref, CFSTR("fe80"), 0 );
	if ( range.location == 0 )
	{
		/* Ignoring IPv6 link local address */
		return TRUE;
	}
	/* Ignore automatic private IP addresses */
	range = CFStringFind( addr_ref, CFSTR("169.254"), 0 );
	if ( range.location == 0 )
	{
		/* Ignoring IPv4 automatic private IP addresses */
		return TRUE;
	}
	/* Don't ignore the address */
	return FALSE;
}

static linked_list_t *addrs_from_dict( CFDictionaryRef dict_ref, int family )
{
	CFArrayRef addrs_ref = NULL;
	linked_list_t *result = NULL;

	/* Our result will be a linked list of host_t objects */
	result = linked_list_create();
	if (!result)
	{
		return NULL;
	}

	/* It's possible to be called with no dictionary reference. In this case we
	 * still want to return the empty linked list. */
	if (!dict_ref)
	{
		return result;
	}

	/* Extract the addresses and add them to the host_t object linked list */
	addrs_ref = (CFArrayRef)CFDictionaryGetValue( dict_ref, family == AF_INET ? kSCPropNetIPv4Addresses : kSCPropNetIPv6Addresses );
	if ( addrs_ref )
	{
		CFStringRef addr_ref = NULL;
		host_t *host;
		CFIndex idx, count;
		char addr_str[64];

		//CFShow(addrs_ref);
		count = CFArrayGetCount( addrs_ref );
		for ( idx = 0; idx < count; idx++ )
		{
			/* Get the next entry in the array - it's a string ref */
			addr_ref = (CFStringRef)CFArrayGetValueAtIndex( addrs_ref, idx );

			/* Ensure it's one we are interested in */
			if ( ignore_address( addr_ref ) )
			{
				continue;
			}

			/* Convert to a C string */
			if ( to_char_str( addr_ref, addr_str, sizeof(addr_str) ) != SUCCESS )
			{
				continue;
			}

			/* Create the host object */
			host = host_create_from_string(addr_str, 0);
			if ( host == NULL )
			{
				continue;
			}

			/* And add it to the linked list */
			result->insert_last(result, host);
		}
	}

	return result;
}

static void dump_addresses(private_kernel_syscfg_net_t *this)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	enumerator_t *ifaces, *addrs;

	DBG2(DBG_KNL, "known interfaces and IP addresses:");

	this->lock->write_lock(this->lock);

	/* Dump out the interfaces and addresses */
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface))
	{
		DBG2(DBG_KNL, "  %s", iface->ifname);
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, (void**)&addr))
		{
			DBG2(DBG_KNL, "    %H", addr->ip);
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);

	this->lock->unlock(this->lock);
}

static void update_ipaddrs_from_key( CFStringRef key_ref, CFDictionaryRef dict_ref, private_kernel_syscfg_net_t *this, bool init )
{
	char ifname[IFNAMSIZ + 1] = {0};
	int family = 0;

	enumerator_t *ifaces = NULL;
	iface_entry_t *iface = NULL, *iface_current = NULL;
	bool found = FALSE, roam = FALSE, update_routes = FALSE;

	linked_list_t *hosts_list = NULL;
	enumerator_t *hosts = NULL;
	host_t *host = NULL;

	enumerator_t *addrs = NULL;
	addr_entry_t *addr = NULL;

	/* Sanity checks. Note that it's OK if dict_ref is NULL */
	if ( !key_ref || CFGetTypeID(key_ref) != CFStringGetTypeID() ||
		 (dict_ref && CFGetTypeID( dict_ref ) != CFDictionaryGetTypeID()) ||
		 !this )
	{
		DBG1(DBG_KNL, "update_ipaddrs_from_key: invalid parameter");
		return;
	}

	//DBG1(DBG_KNL, "update_ipaddrs_from_key:");
	//CFShow(key_ref);


	if ( parse_key_ref( key_ref, ifname, &family ) != SUCCESS )
	{
		DBG1(DBG_KNL, "update_ipaddrs_from_key: malformed key");
		return;
	}

	/* Ignore the loopback interface */
	if ( ifname[0] == 'l' && ifname[1] == 'o' )
	{
		return;
	}

	/* Create a linked list of hosts from the given dictionary ref */
	hosts_list = addrs_from_dict( dict_ref, family );
	if (!hosts_list)
	{
		DBG1(DBG_KNL, "update_ipaddrs_from_key: failed to create hosts list");
		return;
	}

	this->lock->write_lock(this->lock);

	/* If this interface is not known, create it and add it to our list */
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &iface_current))
	{
		if (streq(iface_current->ifname, ifname))
		{
			iface = iface_current;
			break;
		}
	}
	ifaces->destroy(ifaces);

	if (!iface)
	{
		INIT(iface,
			 .addrs = linked_list_create(),
			 );
		memcpy(iface->ifname, ifname, IFNAMSIZ);
		this->ifaces->insert_last(this->ifaces, iface);
	}

	/* Determine what has changed on the interface. Anything that was in the
	 * current IP address list that is not in the new IP address list has been
	 * removed. Anything that is in the new IP address list that was not in the
	 * current IP address list has been added. */

	/* Note that the key we get is for either IPv4 or IPv6. That means when we
	 * get the addresses for the key, we only get IPv4 or IPv6 addresses.
	 * Therefore, we only look for changes for the appropriate family in the
	 * code below. */

	/* Determine if any addresses have been removed */
	addrs = iface->addrs->create_enumerator(iface->addrs);
	while (addrs->enumerate(addrs, &addr))
	{
		if ( addr->ip->get_family(addr->ip) != family)
		{
			continue;
		}

		found = FALSE;
		hosts = hosts_list->create_enumerator(hosts_list);
		while (hosts->enumerate(hosts, &host))
		{
			if (host->ip_equals(host, addr->ip))
			{
				found = TRUE;
				break;
			}
		}
		hosts->destroy(hosts);

		if (!found)
		{
			iface->addrs->remove_at(iface->addrs, addrs);
			if (!addr->virtual)
			{
				DBG1(DBG_KNL, "%H disappeared from %s", addr->ip, ifname);
			}
			addr_map_entry_remove(addr, iface, this);
			addr_entry_destroy(addr);
			this->condvar->broadcast(this->condvar);
			if (!init)
			{
				roam = TRUE;
			}
		}
	}
	addrs->destroy(addrs);

	/* Determine if any addresses have been added */
	hosts = hosts_list->create_enumerator(hosts_list);
	while (hosts->enumerate(hosts, &host))
	{
		found = FALSE;
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (addrs->enumerate(addrs, &addr))
		{
			if ( addr->ip->get_family(addr->ip) != family)
			{
				continue;
			}

			if (host->ip_equals(host, addr->ip))
			{
				found = TRUE;
				break;
			}
		}
		addrs->destroy(addrs);

		if (!found)
		{
			INIT(addr,
				 .ip = host->clone(host),
				 );
			iface->addrs->insert_last(iface->addrs, addr);
			addr_map_entry_add(this, addr, iface);
			this->condvar->broadcast(this->condvar);
			if (!init)
			{
				DBG1(DBG_KNL, "%H appeared on %s", host, iface->ifname);
				roam = update_routes = TRUE;
			}
		}
	}
	hosts->destroy(hosts);

	this->lock->unlock(this->lock);
	hosts_list->destroy(hosts_list);

	if (update_routes)
	{
		queue_route_reinstall(this, strdup(ifname));
	}

	if (roam)
	{
		fire_roam_event(this, TRUE);

		if (!init)
		{
			dump_addresses(this);
		}
	}
}

static void update_ipaddrs_from_key_init( const void *key, const void *value, void *context )
{
	update_ipaddrs_from_key( (CFStringRef)key, (CFDictionaryRef)value, (private_kernel_syscfg_net_t *)context, TRUE );
}

/**
 * Create a search pattern list that finds all IPv4 and IPv6 changes. This
 * pattern list constains two patterns, one for IPv4 and another for IPv6.
 */
static status_t create_pattern_list(private_kernel_syscfg_net_t *this)
{
	/* This pattern is State:/Network/Interface/[^/]+/IPv4 */
	this->patterns[0] = SCDynamicStoreKeyCreateNetworkInterfaceEntity( NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4 );
	if ( this->patterns[0] == NULL )
	{
		DBG1(DBG_KNL, "Failed to create IPv4 pattern");
		return FAILED;
	}

	/* This pattern is State:/Network/Interface/[^/]+/IPv6 */
	this->patterns[1] = SCDynamicStoreKeyCreateNetworkInterfaceEntity( NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6 );
	if ( this->patterns[1] == NULL )
	{
		DBG1(DBG_KNL, "Failed to create IPv6 pattern");
		return FAILED;
	}

	this->pattern_list = CFArrayCreate( NULL, (const void **)this->patterns, 2, &kCFTypeArrayCallBacks );
	if ( this->pattern_list == NULL )
	{
		DBG1(DBG_KNL, "Failed to create pattern list");
		return FAILED;
	}

	return SUCCESS;
}

static void destroy_pattern_list(private_kernel_syscfg_net_t *this)
{
	if ( this->pattern_list )
	{
		CFRelease( this->pattern_list );
		this->pattern_list = NULL;
	}

	if ( this->patterns[1] )
	{
		CFRelease( this->patterns[1] );
		this->patterns[1] = NULL;
	}

	if ( this->patterns[0] )
	{
		CFRelease( this->patterns[0] );
		this->patterns[0] = NULL;
	}
}

static void ipchange_callback( SCDynamicStoreRef store, CFArrayRef changed_keys, void *info )
{
	CFStringRef key = NULL;
	CFPropertyListRef prop_list = NULL;
	CFIndex idx, count = CFArrayGetCount( changed_keys );
	private_kernel_syscfg_net_t *this = (private_kernel_syscfg_net_t *)info;

	/* One or more IP addresses have been added or removed. We are given an
	 * array of changed System Configuration keys that have changed (we are not
	 * given the actual changes - we need to figure that out). For each of the
	 * changed keys we get the the addresses under that key and then call the
	 * function to figure out what changed. */
	for ( idx = 0; idx < count; idx++ )
	{
		/* Get the next changed key */
		key = (CFStringRef)CFArrayGetValueAtIndex( changed_keys, idx );

		/* Get the IP addresses under the changed key. These are returned as a
		 * propertly list ref, which is just a form of a dictionary ref. */
		prop_list = SCDynamicStoreCopyValue( this->dynamic_store, key );

		/* This function will figure out that addresses have actually changed
		 * (been added or deleted). Note that it's possible for prop_list to be
		 * NULL at this point, which means there are no addresses under the
		 * changed key. This is fine as update_ipaddrs_from_key() handles that
		 * case. */
		update_ipaddrs_from_key( key, (CFDictionaryRef)prop_list, this, FALSE );
		if (prop_list)
		{
			CFRelease( prop_list );
		}
	}
}

/**
 * Create a connection to the System Configuration dynamic store, register our
 * pattern list and create a runloop source that can be added to our runloop and
 * will get notified when IP address changes occur.
 */
static status_t create_dynamic_store(private_kernel_syscfg_net_t *this)
{
	/* Create a connection to the dynamic store */
	SCDynamicStoreContext context = { 0, this, NULL, NULL, NULL };
	this->dynamic_store = SCDynamicStoreCreate( NULL, CFSTR("strongswan_ipchange"), ipchange_callback, &context );
	if ( this->dynamic_store == NULL )
	{
		DBG1(DBG_KNL, "Failed to create dynamic store for IP address changes");
		return FAILED;
	}

	return SUCCESS;
}

static void destroy_dynamic_store(private_kernel_syscfg_net_t *this)
{
	if (this->dynamic_store)
	{
		CFRelease( this->dynamic_store );
		this->dynamic_store = NULL;
	}
}

/**
 * Create a connection to the System Configuration dynamic store, register our
 * pattern list and create a runloop source that can be added to our runloop and
 * will get notified when IP address changes occur.
 */
static status_t create_runloop_source(private_kernel_syscfg_net_t *this)
{
	/* Tell the dynamic store to watch for changes using our pattern list */
	if ( !SCDynamicStoreSetNotificationKeys( this->dynamic_store, NULL, this->pattern_list ) )
	{
		DBG1(DBG_KNL, "Failed to register pattern list with dynamic store");
		return FAILED;
	}

	/* Create a run loop source for the dynamic store */
	this->runloop_source = SCDynamicStoreCreateRunLoopSource( NULL, this->dynamic_store, 0 );
	if ( this->runloop_source == NULL )
	{
		DBG1(DBG_KNL, "Failed to create runloop source from dynamic store");
		return FAILED;
	}

	return SUCCESS;
}

static void destroy_runloop_source(private_kernel_syscfg_net_t *this)
{
	if (this->runloop_source)
	{
		CFRelease(this->runloop_source);
		this->runloop_source = NULL;
	}
}

/**
 * Initialize a list of local addresses from the System Configuration.
 */
static status_t init_address_list(private_kernel_syscfg_net_t *this)
{
	CFDictionaryRef initial_keys = NULL;

	/* Get the keys that match our pattern list from the System Configuration
	 * framework */
	initial_keys = SCDynamicStoreCopyMultiple( this->dynamic_store, NULL, this->pattern_list );
	if ( initial_keys == NULL )
	{
		DBG1(DBG_KNL, "  failed to get initial keys!");
		return FAILED;
	}

	/* Extract the interfaces and addresses from the keys. This function calls
	 * the specified function for every matching initial key. */
	CFDictionaryApplyFunction( initial_keys, update_ipaddrs_from_key_init, this );
	CFRelease( initial_keys );

	dump_addresses(this);

	return SUCCESS;
}

static void *runloop_run(void *info)
{
	private_kernel_syscfg_net_t *this = (private_kernel_syscfg_net_t *)info;

	this->runloop_ref = CFRunLoopGetCurrent();
	CFRunLoopAddSource(this->runloop_ref, this->runloop_source, kCFRunLoopDefaultMode);

	CFRunLoopRun();

	CFRunLoopSourceInvalidate(this->runloop_source);
	return 0;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_syscfg_net_t *this)
{
	enumerator_t *enumerator;
	route_entry_t *route;
	addr_entry_t *addr;

	enumerator = this->routes->create_enumerator(this->routes);
	while (enumerator->enumerate(enumerator, NULL, (void**)&route))
	{
		manage_route(this, RTM_DELETE, route->dst_net, route->prefixlen,
					 route->gateway, route->if_name);
		route_entry_destroy(route);
	}
	enumerator->destroy(enumerator);
	this->routes->destroy(this->routes);
	this->routes_lock->destroy(this->routes_lock);

	if (this->runloop_ref)
	{
		CFRunLoopStop( this->runloop_ref );
		this->runloop->join(this->runloop);
	}

	destroy_runloop_source( this );
	destroy_pattern_list( this );
	destroy_dynamic_store( this );

	if (this->socket != -1)
	{
		lib->watcher->remove(lib->watcher, this->socket);
		close(this->socket);
	}

	net_changes_clear(this);
	this->net_changes->destroy(this->net_changes);
	this->net_changes_lock->destroy(this->net_changes_lock);

	enumerator = this->addrs->create_enumerator(this->addrs);
	while (enumerator->enumerate(enumerator, NULL, (void**)&addr))
	{
		free(addr);
	}
	enumerator->destroy(enumerator);
	this->addrs->destroy(this->addrs);
	this->ifaces->destroy_function(this->ifaces, (void*)iface_entry_destroy);
	this->tuns->destroy(this->tuns);
	this->lock->destroy(this->lock);
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	this->roam_lock->destroy(this->roam_lock);
	free(this->reply);
	free(this);
}

/*
 * Described in header.
 */
kernel_syscfg_net_t *kernel_syscfg_net_create()
{
	private_kernel_syscfg_net_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_interface = _get_interface_name,
				.create_address_enumerator = _create_address_enumerator,
				.create_local_subnet_enumerator = _create_local_subnet_enumerator,
				.get_source_addr = _get_source_addr,
				.get_nexthop = _get_nexthop,
				.add_ip = _add_ip,
				.del_ip = _del_ip,
				.add_route = _add_route,
				.del_route = _del_route,
				.destroy = _destroy,
			},
		},
		.pid = getpid(),
		.ifaces = linked_list_create(),
		.addrs = hashtable_create(
								(hashtable_hash_t)addr_map_entry_hash,
								(hashtable_equals_t)addr_map_entry_equals, 16),
		.routes = hashtable_create((hashtable_hash_t)route_entry_hash,
								   (hashtable_equals_t)route_entry_equals, 16),
		.net_changes = hashtable_create(
								   (hashtable_hash_t)net_change_hash,
								   (hashtable_equals_t)net_change_equals, 16),
		.tuns = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.routes_lock = mutex_create(MUTEX_TYPE_DEFAULT),
		.net_changes_lock = mutex_create(MUTEX_TYPE_DEFAULT),
		.roam_lock = spinlock_create(),
		.vip_wait = lib->settings->get_int(lib->settings,
						"%s.plugins.kernel-syscfg.vip_wait", 1000, lib->ns),
		.install_virtual_ip = lib->settings->get_bool(lib->settings,
						"%s.install_virtual_ip", TRUE, lib->ns),
		.runloop_source = NULL,
		.runloop_ref = NULL,
		.runloop = NULL,
		.patterns = { NULL, NULL },
		.pattern_list = NULL,
		.dynamic_store = NULL,
	);
	timerclear(&this->last_route_reinstall);
	timerclear(&this->next_roam);

	/* create the dynamic store */
	if ( create_dynamic_store( this ) != SUCCESS )
	{
		DBG1(DBG_KNL, "unable to create dynamic store");
		destroy(this);
		return NULL;
	}

	/* create the pattern list */
	if ( create_pattern_list( this ) != SUCCESS )
	{
		DBG1(DBG_KNL, "unable to create pattern list");
		destroy(this);
		return NULL;
	}

	/* create the runloop source */
	if ( create_runloop_source( this ) != SUCCESS )
	{
		DBG1(DBG_KNL, "unable to create runloop source");
		destroy(this);
		return NULL;
	}

	/* Get the initial interfaces and addresses */
	if ( init_address_list( this ) != SUCCESS )
	{
		DBG1(DBG_KNL, "unable to get interface list");
		destroy(this);
		return NULL;
	}

	/* create a PF_ROUTE socket to communicate with the kernel */
	this->socket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (this->socket == -1)
	{
		DBG1(DBG_KNL, "unable to create PF_ROUTE socket");
		destroy(this);
		return NULL;
	}

	if (streq(lib->ns, "starter"))
	{
		/* starter has no threads, so we do not register for kernel events */
		if (shutdown(this->socket, SHUT_RD) != 0)
		{
			DBG1(DBG_KNL, "closing read end of PF_ROUTE socket failed: %s",
				 strerror(errno));
		}
	}
	else
	{
		/* Add the PF route socket to the watcher so we can respond to route changes */
		lib->watcher->add(lib->watcher, this->socket, WATCHER_READ,
						  (watcher_cb_t)receive_events, this);

		/* Start a thread that will watch for IP address changes */
		this->runloop = thread_create(runloop_run, this);
	}

	return &this->public;
}
