/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <ntddndis.h>
#include <naptypes.h>
#include <iphlpapi.h>

#include "kernel_iph_net.h"

#include <hydra.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>


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
	 * Mutex to access interface list
	 */
	mutex_t *mutex;

	/**
	 * Known interfaces, as iface_t
	 */
	linked_list_t *ifaces;
};

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
	/** list of known addresses, as host_t */
	linked_list_t *addrs;
} iface_t;

/**
 * Clean up an iface_t
 */
static void iface_destroy(iface_t *this)
{
	this->addrs->destroy_offset(this->addrs, offsetof(host_t, destroy));
	free(this->ifname);
	free(this->ifdesc);
	free(this);
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
 * Update addresses for an iface entry
 */
static void update_addrs(private_kernel_iph_net_t *this, iface_t *entry,
						 IP_ADAPTER_ADDRESSES *addr, bool log)
{
	IP_ADAPTER_UNICAST_ADDRESS *current;
	enumerator_t *enumerator;
	linked_list_t *list;
	host_t *host, *old;

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
			bool found = FALSE;

			enumerator = list->create_enumerator(list);
			while (enumerator->enumerate(enumerator, &old))
			{
				if (host->ip_equals(host, old))
				{
					list->remove_at(list, enumerator);
					old->destroy(old);
					found = TRUE;
				}
			}
			enumerator->destroy(enumerator);

			entry->addrs->insert_last(entry->addrs, host);

			if (!found && log)
			{
				DBG1(DBG_KNL, "%H appeared on interface %u '%s'",
					 host, entry->ifindex, entry->ifdesc);
			}
		}
	}

	while (list->remove_first(list, (void**)&old) == SUCCESS)
	{
		if (log)
		{
			DBG1(DBG_KNL, "%H disappeared from interface %u '%s'",
				 old, entry->ifindex, entry->ifdesc);
		}
		old->destroy(old);
	}
	list->destroy(list);
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
static void change_interface(private_kernel_iph_net_t *this,
					MIB_IPINTERFACE_ROW_FIXUP *row, MIB_NOTIFICATION_TYPE type)
{
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
	host_t *host;

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (!found && ifaces->enumerate(ifaces, &entry))
	{
		addrs = entry->addrs->create_enumerator(entry->addrs);
		while (!found && addrs->enumerate(addrs, &host))
		{
			if (host->ip_equals(host, ip))
			{
				found = entry;
			}
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);

	return found;
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
	addr_enumerator_t *this, host_t **host)
{
	iface_t *entry;

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
		if (this->addrs->enumerate(this->addrs, host))
		{
			return TRUE;
		}
		this->addrs->destroy(this->addrs);
		this->addrs = NULL;
	}
}

METHOD(enumerator_t, addr_destroy, void,
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

	if (!(which & ADDR_TYPE_REGULAR))
	{
		/* we currently have no virtual, but regular IPs only */
		return enumerator_create_empty();
	}

	this->mutex->lock(this->mutex);

	INIT(enumerator,
		.public = {
			.enumerate = (void*)_addr_enumerate,
			.destroy = _addr_destroy,
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
	private_kernel_iph_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_iph_net_t *this, host_t *virtual_ip, int prefix,
	char *iface_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_iph_net_t *this, host_t *virtual_ip, int prefix,
	bool wait)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_iph_net_t *this)
{
	if (this->changes)
	{
		CancelMibChangeNotify2(this->changes);
	}
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
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.ifaces = linked_list_create(),
	);

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
