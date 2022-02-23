/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 * Copyright (C) 2016 Noel Kuntze
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

/* Windows 7, for some iphlpapi.h functionality */
#ifdef NOCRYPT
#undef NOCRYPT
#endif
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <ntddndis.h>
#include <naptypes.h>
#include <iphlpapi.h>

#include "kernel_iph_net.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>


/** delay before firing roam events (ms) */
#define ROAM_DELAY 500

typedef struct private_kernel_iph_net_t private_kernel_iph_net_t;

/**
 * Private data of kernel_iph_net implementation.
 */
struct private_kernel_iph_net_t {

	/**
	 * Public interface.
	 */
	kernel_iph_net_t public;

	/**
	 * NotifyIpInterfaceChange() handle
	 */
	HANDLE changes;

	/**
	 * EnableRouter() OVERLAPPED
	 */
	OVERLAPPED router;

	/**
	 * Mutex to access interface list
	 */
	mutex_t *mutex;

	/**
	 * Known interfaces, as iface_t
	 */
	linked_list_t *ifaces;

	/**
	 * Earliest time of the next roam event
	 */
	timeval_t roam_next;

	/**
	 * Roam event due to address change?
	 */
	bool roam_address;

	/**
	 * Whether to install virtual IPs
	 */
	bool install_virtual_ip;

	/**
	 * Where to install virtual IPs
	 */
	char *install_virtual_ip_on;
};

/**
 * Interface address entry
 */
typedef struct {
	/** address */
	host_t *ip;
	/** is virtual installed by us? */
	bool virtual;
	/** reference count */
	int count;
} addr_t;

/**
 * Clean up an addr_t
 */
CALLBACK(addr_destroy, void,
	addr_t *this)
{
	this->ip->destroy(this->ip);
	free(this);
}

/**
 * Interface entry
 */
typedef struct  {
	/** interface index */
	DWORD ifindex;
	/** interface name */
	char *ifname;
	/** interface description */
	char *ifdesc;
	/** type of interface */
	DWORD iftype;
	/** interface status */
	IF_OPER_STATUS status;
	/** list of known addresses, as addr_t */
	linked_list_t *addrs;
} iface_t;

/**
 * Clean up an iface_t
 */
static void iface_destroy(iface_t *this)
{
	this->addrs->destroy_function(this->addrs, addr_destroy);
	free(this->ifname);
	free(this->ifdesc);
	free(this);
}
/**
 * find an interface entry by name
 */
static bool iface_by_name(iface_t *this, char *ifname)
{
	return streq(this->ifname, ifname);
}

/**
 * Enum names for Windows IF_OPER_STATUS
 */
ENUM(if_oper_names, IfOperStatusUp, IfOperStatusLowerLayerDown,
	"Up",
	"Down",
	"Testing",
	"Unknown",
	"Dormant",
	"NotPresent",
	"LowerLayerDown",
);

/**
 * Callback function that raises the delayed roam event
 */
static job_requeue_t roam_event(private_kernel_iph_net_t *this)
{
	bool address;

	this->mutex->lock(this->mutex);
	address = this->roam_address;
	this->roam_address = FALSE;
	this->mutex->unlock(this->mutex);

	charon->kernel->roam(charon->kernel, address);
	return JOB_REQUEUE_NONE;
}

/**
 * Fire delayed roam event, caller should hold mutex
 */
static void fire_roam_event(private_kernel_iph_net_t *this, bool address)
{
	timeval_t now;

	time_monotonic(&now);
	this->roam_address |= address;
	if (timercmp(&now, &this->roam_next, >))
	{
		timeval_add_ms(&now, ROAM_DELAY);
		this->roam_next = now;
		lib->scheduler->schedule_job_ms(lib->scheduler, (job_t*)
							callback_job_create((callback_job_cb_t)roam_event,
												this, NULL, NULL),
							ROAM_DELAY);
	}
}

/**
 * Find an address entry given its IP address
 */
static void find_addr( iface_t *iface, host_t *ip, addr_t **found )
{
	enumerator_t *enumerator;
	addr_t *addr = NULL;
	*found = NULL;

	enumerator = iface->addrs->create_enumerator( iface->addrs );
	while ( enumerator->enumerate( enumerator, &addr ) )
	{
		if ( ip->ip_equals( ip, addr->ip ) )
		{
			*found = addr;
			break;
		}
	}
	enumerator->destroy( enumerator );
}

/**
 * Add an address entry to a named interface, return ifindex
 */
static DWORD add_addr(private_kernel_iph_net_t *this, char *name, host_t *ip,
					  bool virtual, bool *first)
{
	enumerator_t *enumerator;
	iface_t *iface;
	DWORD ifindex = 0;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &iface))
	{
		if (streq(name, iface->ifname))
		{
			addr_t *addr = NULL;

			// See if this IP address is already in the list
			find_addr(iface, ip, &addr);
			if (addr)
			{
				addr->count++;
				*first = FALSE;
				DBG1( DBG_KNL, "%H already in addresses list, count = %d", ip, addr->count );
			}
			else
			{
				INIT(addr,
					.ip = ip->clone(ip),
					.virtual = virtual,
					.count = 1
				);
				iface->addrs->insert_last(iface->addrs, addr);

				*first = TRUE;
				DBG1(DBG_KNL, "%H added to addresses list", ip);
			}
			ifindex = iface->ifindex;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return ifindex;
}

/**
 * Remove address entry from named interface, return ifindex
 */
static DWORD remove_addr(private_kernel_iph_net_t *this, host_t *ip, bool *last)
{
	enumerator_t *ifaces, *addrs;
	iface_t *iface;
	addr_t *addr;
	DWORD ifindex = 0;

	this->mutex->lock(this->mutex);
	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (!ifindex && ifaces->enumerate(ifaces, &iface))
	{
		addrs = iface->addrs->create_enumerator(iface->addrs);
		while (!ifindex && addrs->enumerate(addrs, &addr))
		{
			if (ip->ip_equals(ip, addr->ip))
			{
				addr->count--;
				if (addr->count == 0)
				{
					iface->addrs->remove_at(iface->addrs, addrs);
					addr_destroy(addr);
					*last = TRUE;
					DBG1( DBG_KNL, "%H removed from addresses list", ip );
				}
				else
				{
					*last = FALSE;
					DBG1( DBG_KNL, "%H still in addresses list, count = %d", ip, addr->count );
				}
				ifindex = iface->ifindex;
			}
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);
	this->mutex->unlock(this->mutex);

	return ifindex;
}

/**
 * Update addresses for an iface entry
 */
static void update_addrs(private_kernel_iph_net_t *this, iface_t *entry,
						 IP_ADAPTER_ADDRESSES *addr, bool log)
{
	IP_ADAPTER_UNICAST_ADDRESS *current;
	enumerator_t *enumerator;
	linked_list_t *list;
	host_t *host;
	addr_t *aentry;
	bool changes = FALSE;

	list = entry->addrs;
	entry->addrs = linked_list_create();

	for (current = addr->FirstUnicastAddress; current; current = current->Next)
	{
		if (current->Address.lpSockaddr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *sin;

			sin = (struct sockaddr_in6*)current->Address.lpSockaddr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr))
			{
				continue;
			}
		}

		host = host_create_from_sockaddr(current->Address.lpSockaddr);
		if (host)
		{
			addr_t *found = FALSE;

			enumerator = list->create_enumerator(list);
			while (enumerator->enumerate(enumerator, &aentry))
			{
				if (host->ip_equals(host, aentry->ip))
				{
					list->remove_at(list, enumerator);
					found = aentry;
					break;
				}
			}
			enumerator->destroy(enumerator);

			if (!found)
			{
				INIT(found,
					.ip = host->clone(host),
				);
			}
			entry->addrs->insert_last(entry->addrs, found);

			if (!found && log)
			{
				DBG1(DBG_KNL, "%H appeared on interface %u '%s'",
					 host, entry->ifindex, entry->ifdesc);
				changes = TRUE;
			}
			host->destroy(host);
		}
	}

	while (list->remove_first(list, (void**)&aentry) == SUCCESS)
	{
		if (log)
		{
			DBG1(DBG_KNL, "%H disappeared from interface %u '%s'",
				 aentry->ip, entry->ifindex, entry->ifdesc);
			changes = TRUE;
		}
		addr_destroy(aentry);
	}
	list->destroy(list);

	if (changes)
	{
		fire_roam_event(this, TRUE);
	}
}

/**
 * Add an interface entry
 */
static void add_interface(private_kernel_iph_net_t *this,
						  IP_ADAPTER_ADDRESSES *addr, bool log)
{
	enumerator_t *enumerator;
	iface_t *entry;
	bool exists = FALSE;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ifindex == addr->IfIndex)
		{
			exists = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (!exists)
	{
		char desc[128] = "";

		wcstombs(desc, addr->Description, sizeof(desc));

		INIT(entry,
			.ifindex = addr->IfIndex,
			.ifname = strdup(addr->AdapterName),
			.ifdesc = strdup(desc),
			.iftype = addr->IfType,
			.status = addr->OperStatus,
			.addrs = linked_list_create(),
		);

		if (log)
		{
			DBG1(DBG_KNL, "interface %u '%s' appeared",
				 entry->ifindex, entry->ifdesc);
		}

		this->mutex->lock(this->mutex);
		update_addrs(this, entry, addr, log);
		this->ifaces->insert_last(this->ifaces, entry);
		this->mutex->unlock(this->mutex);
	}
}

/**
 * Remove an interface entry that is gone
 */
static void remove_interface(private_kernel_iph_net_t *this, NET_IFINDEX index)
{
	enumerator_t *enumerator;
	iface_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ifindex == index)
		{
			this->ifaces->remove_at(this->ifaces, enumerator);
			DBG1(DBG_KNL, "interface %u '%s' disappeared",
				 entry->ifindex, entry->ifdesc);
			iface_destroy(entry);
			//fire_roam_event(this, TRUE);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Update an interface entry changed
 */
static void update_interface(private_kernel_iph_net_t *this,
							 IP_ADAPTER_ADDRESSES *addr)
{
	enumerator_t *enumerator;
	iface_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ifindex == addr->IfIndex)
		{
			if (entry->status != addr->OperStatus)
			{
				DBG1(DBG_KNL, "interface %u '%s' changed state from %N to %N",
					 entry->ifindex, entry->ifdesc, if_oper_names,
					 entry->status, if_oper_names, addr->OperStatus);
				entry->status = addr->OperStatus;
				fire_roam_event(this, TRUE);
			}
			update_addrs(this, entry, addr, TRUE);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * MinGW gets MIB_IPINTERFACE_ROW wrong, as it packs InterfaceLuid just after
 * Family. Fix that with our own version of the struct header.
 */
typedef struct {
	ADDRESS_FAMILY Family;
	union {
		ULONG64 Value;
		struct {
			ULONG64 Reserved :24;
			ULONG64 NetLuidIndex :24;
			ULONG64 IfType :16;
		} Info;
	} InterfaceLuid;
	NET_IFINDEX InterfaceIndex;
	/* more would go here if needed */
} MIB_IPINTERFACE_ROW_FIXUP;

/**
 * NotifyIpInterfaceChange() callback
 */
static void WINAPI change_interface(void *user, PMIB_IPINTERFACE_ROW row_badal,
									MIB_NOTIFICATION_TYPE type)
{
	private_kernel_iph_net_t *this = user;
	MIB_IPINTERFACE_ROW_FIXUP* row = (MIB_IPINTERFACE_ROW_FIXUP*)row_badal;
	IP_ADAPTER_ADDRESSES addrs[64], *current;
	ULONG res, size = sizeof(addrs);

	if (row && type == MibDeleteInstance)
	{
		remove_interface(this, row->InterfaceIndex);
	}
	else
	{
		res = GetAdaptersAddresses(AF_UNSPEC,
						GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
						GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
						NULL, addrs, &size);
		if (res == NO_ERROR)
		{
			current = addrs;
			while (current)
			{
				/* row is NULL only on MibInitialNotification */
				if (!row || row->InterfaceIndex == current->IfIndex)
				{
					switch (type)
					{
						case MibParameterNotification:
							update_interface(this, current);
							break;
						case MibInitialNotification:
							add_interface(this, current, FALSE);
							break;
						case MibAddInstance:
							add_interface(this, current, TRUE);
							break;
						default:
							break;
					}
				}
				current = current->Next;
			}
		}
		else
		{
			DBG1(DBG_KNL, "getting IPH adapter addresses failed: 0x%08lx", res);
		}
	}
}

/**
 * Get an iface entry for a local address, does no locking
 */
static iface_t* address2entry(private_kernel_iph_net_t *this, host_t *ip)
{
	enumerator_t *ifaces, *addrs;
	iface_t *entry, *found = NULL;
	addr_t *addr;

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (!found && ifaces->enumerate(ifaces, &entry))
	{
		addrs = entry->addrs->create_enumerator(entry->addrs);
		while (!found && addrs->enumerate(addrs, &addr))
		{
			if (ip->ip_equals(ip, addr->ip))
			{
				found = entry;
			}
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);

	return found;
}

/**
 * Find an interface index by interface name
 */
static DWORD ifname2index(private_kernel_iph_net_t *this, char *name)
{
	enumerator_t *enumerator;
	iface_t *entry;
	DWORD ifindex = 0;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(name, entry->ifname))
		{
			ifindex = entry->ifindex;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return ifindex;
}

METHOD(kernel_net_t, get_interface_name, bool,
	private_kernel_iph_net_t *this, host_t* ip, char **name)
{
	iface_t *entry;

	this->mutex->lock(this->mutex);
	entry = address2entry(this, ip);
	if (entry && name)
	{
		*name = strdup(entry->ifname);
	}
	this->mutex->unlock(this->mutex);

	return entry != NULL;
}

/**
 * Address enumerator
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** what kind of address should we enumerate? */
	kernel_address_type_t which;
	/** enumerator over interfaces */
	enumerator_t *ifaces;
	/** current enumerator over addresses, or NULL */
	enumerator_t *addrs;
	/** mutex to unlock on destruction */
	mutex_t *mutex;
} addr_enumerator_t;

METHOD(enumerator_t, addr_enumerate, bool,
	addr_enumerator_t *this, va_list args)
{
	iface_t *entry;
	addr_t *addr;
	host_t **host;

	VA_ARGS_VGET(args, host);

	while (TRUE)
	{
		while (!this->addrs)
		{
			if (!this->ifaces->enumerate(this->ifaces, &entry))
			{
				return FALSE;
			}
			if (entry->iftype == IF_TYPE_SOFTWARE_LOOPBACK &&
				!(this->which & ADDR_TYPE_LOOPBACK))
			{
				continue;
			}
			if (entry->status != IfOperStatusUp &&
				!(this->which & ADDR_TYPE_DOWN))
			{
				continue;
			}
			this->addrs = entry->addrs->create_enumerator(entry->addrs);
		}
		if (this->addrs->enumerate(this->addrs, &addr))
		{
			if (addr->virtual && (this->which & ADDR_TYPE_REGULAR))
			{
				continue;
			}
			*host = addr->ip;
			return TRUE;
		}
		this->addrs->destroy(this->addrs);
		this->addrs = NULL;
	}
}

METHOD(enumerator_t, addr_enumerator_destroy, void,
	addr_enumerator_t *this)
{
	DESTROY_IF(this->addrs);
	this->ifaces->destroy(this->ifaces);
	this->mutex->unlock(this->mutex);
	free(this);
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_iph_net_t *this, kernel_address_type_t which)
{
	addr_enumerator_t *enumerator;

	this->mutex->lock(this->mutex);

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _addr_enumerate,
			.destroy = _addr_enumerator_destroy,
		},
		.which = which,
		.ifaces = this->ifaces->create_enumerator(this->ifaces),
		.mutex = this->mutex,
	);
	return &enumerator->public;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_iph_net_t *this, host_t *dest, host_t *src)
{
	MIB_IPFORWARD_ROW2 route;
	SOCKADDR_INET best, *sai_dst, *sai_src = NULL;
	DWORD res, index = 0;

	res = GetBestInterfaceEx(dest->get_sockaddr(dest), &index);
	if (res != NO_ERROR)
	{
		DBG1(DBG_KNL, "getting interface to %H failed: 0x%08x", dest, res);
		return NULL;
	}

	sai_dst = (SOCKADDR_INET*)dest->get_sockaddr(dest);
	if (src)
	{
		sai_src = (SOCKADDR_INET*)src->get_sockaddr(src);
	}
	res = GetBestRoute2(0, index, sai_src, sai_dst, 0, &route, &best);
	if (res != NO_ERROR)
	{
		DBG2(DBG_KNL, "getting src address to %H failed: 0x%08x", dest, res);
		return NULL;
	}
	return host_create_from_sockaddr((struct sockaddr*)&best);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_iph_net_t *this, host_t *dest, int prefix, host_t *src,
	char **iface)
{
	MIB_IPFORWARD_ROW2 route;
	SOCKADDR_INET best, *sai_dst, *sai_src = NULL;
	DWORD res, index = 0;
	host_t *nexthop;

	res = GetBestInterfaceEx(dest->get_sockaddr(dest), &index);
	if (res != NO_ERROR)
	{
		DBG1(DBG_KNL, "getting interface to %H failed: 0x%08x", dest, res);
		return NULL;
	}

	sai_dst = (SOCKADDR_INET*)dest->get_sockaddr(dest);
	if (src)
	{
		sai_src = (SOCKADDR_INET*)src->get_sockaddr(src);
	}
	res = GetBestRoute2(0, index, sai_src, sai_dst, 0, &route, &best);
	if (res != NO_ERROR)
	{
		DBG2(DBG_KNL, "getting nexthop to %H failed: 0x%08x", dest, res);
		return NULL;
	}
	nexthop = host_create_from_sockaddr((struct sockaddr*)&route.NextHop);
	if (nexthop)
	{
		if (!nexthop->is_anyaddr(nexthop))
		{
			if (iface)
			{
				*iface = NULL;
			}
			return nexthop;
		}
		nexthop->destroy(nexthop);
	}
	return NULL;
}


/**
 * Create a MIB unicast row from a host
 */
static void host2unicast(host_t *host, int prefix, MIB_UNICASTIPADDRESS_ROW *row)
{
	InitializeUnicastIpAddressEntry(row);

	row->Address.si_family = host->get_family(host);
	memcpy(&row->Address, host->get_sockaddr(host),
		   *host->get_sockaddr_len(host));

	row->PrefixOrigin = IpPrefixOriginOther;
	row->SuffixOrigin = IpSuffixOriginOther;
	/* don't change the default route to this address */
	row->SkipAsSource = FALSE;
	if (prefix == -1)
	{
		if (row->Address.si_family == AF_INET)
		{
			row->OnLinkPrefixLength = 32;
		}
		else
		{
			row->OnLinkPrefixLength = 128;
		}
	}
	else
	{
		row->OnLinkPrefixLength = prefix;
	}
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_iph_net_t *this, host_t *vip, int prefix, char *name)
{
	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	MIB_UNICASTIPADDRESS_ROW row;
	u_long status;
	iface_t *iface = NULL;
	bool first = FALSE;

	DBG1( DBG_KNL, "Adding virtual IP %H", vip );

	/* name of the MS Loopback adapter */
	if (!this->install_virtual_ip_on ||
		 this->ifaces->find_first(this->ifaces, (void*)iface_by_name, (void**)&iface, this->install_virtual_ip_on) != SUCCESS)
	{
		name = "{DB2C49B1-7C90-4253-9E61-8C6A881194ED}";
	}
	else
	{
		name = this->install_virtual_ip_on;
	}
	host2unicast(vip, prefix, &row);

	row.InterfaceIndex = add_addr(this, name, vip, TRUE, &first);
	if (!row.InterfaceIndex)
	{
		DBG1(DBG_KNL, "interface '%s' not found", name);
		return NOT_FOUND;
	}

	/* Only do the add if this is the first time we've seen this address */
	if (first)
	{
		DBG1( DBG_KNL, "%H is not yet assigned to the virtual adapter - adding", vip );
		status = CreateUnicastIpAddressEntry(&row);
		if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS)
		{
			DBG1(DBG_KNL, "creating IPH address entry failed: %lu", status);
			remove_addr(this, vip, &first);
			return FAILED;
		}
	}
	else
	{
		DBG1( DBG_KNL, "%H is already assigned to the virtual adapter - nothing more to do", vip );
	}
	return SUCCESS;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_iph_net_t *this, host_t *vip, int prefix, bool wait)
{
	if (!this->install_virtual_ip)
	{	/* disabled by config */
		return SUCCESS;
	}

	MIB_UNICASTIPADDRESS_ROW row;
	u_long status;
	bool last = FALSE;

	DBG1( DBG_KNL, "Removing virtual IP %H", vip );
	host2unicast(vip, prefix, &row);

	row.InterfaceIndex = remove_addr(this, vip, &last);
	if (!row.InterfaceIndex)
	{
		DBG1(DBG_KNL, "virtual IP %H not found", vip);
		return NOT_FOUND;
	}

	/* Only do the deletion if this is the last time we've seen this address */
	if (last)
	{
		status = DeleteUnicastIpAddressEntry(&row);
		if (status != NO_ERROR)
		{
			DBG1(DBG_KNL, "deleting IPH address entry failed: %lu", status);
			return FAILED;
		}
		DBG1( DBG_KNL, "%H has been removed from the virtual adapter", vip );
	}
	else
	{
		DBG1( DBG_KNL, "There are still more %H addresses on the virtual adapter - nothing more to do", vip );
	}

	return SUCCESS;
}

/**
 * Add or remove a route
 */
static status_t manage_route(private_kernel_iph_net_t *this, bool add,
					chunk_t dst, uint8_t prefixlen, host_t *gtw, char *name)
{
	MIB_IPFORWARD_ROW2 row = {
		.DestinationPrefix = {
			.PrefixLength = prefixlen,
		},
		.SitePrefixLength = prefixlen,
		.ValidLifetime = INFINITE,
		.PreferredLifetime = INFINITE,
		.Metric = 10,
		.Protocol = MIB_IPPROTO_NETMGMT,
	};
	ULONG ret;

	/* if route is 0.0.0.0/0, we can't install it, as it would
	 * overwrite the default route. Instead, we add two routes:
	 * 0.0.0.0/1 and 128.0.0.0/1 */
	if (prefixlen == 0)
	{
		chunk_t half;
		status_t status;

		half = chunk_alloca(dst.len);
		memset(half.ptr, 0, half.len);
		prefixlen = 1;

		status = manage_route(this, add, half, prefixlen, gtw, name);
		if (status == SUCCESS)
		{
			half.ptr[0] |= 0x80;
			status = manage_route(this, add, half, prefixlen, gtw, name);
		}
		return status;
	}

	row.InterfaceIndex = ifname2index(this, name);
	if (!row.InterfaceIndex)
	{
		return NOT_FOUND;
	}
	switch (dst.len)
	{
		case 4:
			row.DestinationPrefix.Prefix.si_family = AF_INET;
			memcpy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr,
				   dst.ptr, dst.len);
			break;
		case 16:
			row.DestinationPrefix.Prefix.si_family = AF_INET6;
			memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
				   dst.ptr, dst.len);
			break;
		default:
			return FAILED;
	}
	if (gtw)
	{
		memcpy(&row.NextHop, gtw->get_sockaddr(gtw),
			   *gtw->get_sockaddr_len(gtw));
	}

	if (add)
	{
		ret = CreateIpForwardEntry2(&row);
		if (ret == ERROR_OBJECT_ALREADY_EXISTS)
		{
			DBG1(DBG_KNL, "route exists, attempting to remove");
			ULONG dret = DeleteIpForwardEntry2(&row);
			if (dret != NO_ERROR)
			{
				DBG1(DBG_KNL, "removing route failed: 0x%08lx", dret);
			}
			else
			{
				ret = CreateIpForwardEntry2(&row);
			}
		}
	}
	else
	{
		ret = DeleteIpForwardEntry2(&row);
	}
	if (ret != NO_ERROR)
	{
		DBG1(DBG_KNL, "%sing route failed: 0x%08lx", add ? "add" : "remov", ret);
		return FAILED;
	}

	if (add)
	{
		ret = EnableRouter(NULL, &this->router);
		if (ret != ERROR_IO_PENDING)
		{
			DBG1(DBG_KNL, "EnableRouter router failed: 0x%08lx", ret);
		}
	}
	else
	{
		ret = UnenableRouter(&this->router, NULL);
		if (ret != NO_ERROR)
		{
			DBG1(DBG_KNL, "UnenableRouter router failed: 0x%08lx", ret);
		}
	}
	return SUCCESS;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst, uint8_t prefixlen,
	host_t *gateway, host_t *src, char *name, bool pass)
{
	return manage_route(this, TRUE, dst, prefixlen, gateway, name);
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst, uint8_t prefixlen,
	host_t *gateway, host_t *src, char *name, bool pass)
{
	return manage_route(this, FALSE, dst, prefixlen, gateway, name);
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_iph_net_t *this)
{
	if (this->changes)
	{
		CancelMibChangeNotify2(this->changes);
	}
	CloseHandle(this->router.hEvent);
	this->mutex->destroy(this->mutex);
	this->ifaces->destroy_function(this->ifaces, (void*)iface_destroy);
	free(this);
}

/*
 * Described in header.
 */
kernel_iph_net_t *kernel_iph_net_create()
{
	private_kernel_iph_net_t *this;
	ULONG res;

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
		.router = {
			.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL),
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.ifaces = linked_list_create(),
		.install_virtual_ip = lib->settings->get_bool(lib->settings,
						"%s.install_virtual_ip", TRUE, lib->ns),
		.install_virtual_ip_on = lib->settings->get_str(lib->settings,
						"%s.install_virtual_ip_on", NULL, lib->ns),
	);
	/* PIPINTERFACE_CHANGE_CALLBACK is not using WINAPI in MinGW, which seems
	 * to be wrong. Force a cast to our WINAPI call */
	res = NotifyIpInterfaceChange(AF_UNSPEC, (void*)change_interface,
								  this, TRUE, &this->changes);
	if (res != NO_ERROR)
	{
		DBG1(DBG_KNL, "registering for IPH interface changes failed: 0x%08lx",
			 res);
		destroy(this);
		return NULL;
	}

	return &this->public;
}
