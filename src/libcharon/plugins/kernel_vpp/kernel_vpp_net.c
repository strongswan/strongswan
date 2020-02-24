#include <collections/array.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <utils/debug.h>

#include <processing/jobs/callback_job.h>
#include <threading/spinlock.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#include "kernel_vpp_net.h"
#include "kernel_vpp_shared.h"

typedef struct private_kernel_vpp_net_t private_kernel_vpp_net_t;

/** delay before firing roam events (ms) */
#define ROAM_DELAY 100

/**
 * Private data of kernel_vpp_net implementation.
 */
struct private_kernel_vpp_net_t {

	/**
	 * Public interface.
	 */
	kernel_vpp_net_t public;

	/**
	 * Mutex to access interface list
	 */
	mutex_t *mutex;

	/**
	 * Known interfaces, as iface_t
	 */
	linked_list_t *ifaces;

	/**
	 * Inteface update thread
	 */
	thread_t *net_update;

	/**
	 * TRUE if interface events enabled
	 */
	bool events_on;

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
	 * whether to trigger roam events
	 */
	bool roam_events;
};

/**
 * Interface entry
 */
typedef struct {
	/** interface index */
	uint32_t index;
	/** interface name */
	char if_name[64];
	/** array of known addresses, as host_t */
	array_t *addrs;
	/** TRUE if not filtered */
	bool usable;
	/** TRUE if up */
	bool up;
} iface_t;

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

/**
 * FIB path entry
 */
typedef struct {
	chunk_t next_hop;
	uint32_t sw_if_index;
	uint8_t preference;
} fib_path_t;

static int
cmpaddrs(const void *_a, const void *_b)
{
	chunk_t a = ((host_t *)_a)->get_address((host_t *)_a);
	chunk_t b = ((host_t *)_b)->get_address((host_t *)_b);

	if (a.len < b.len)
		return -1;
	if (a.len > b.len)
		return 1;
	return memcmp(a.ptr, b.ptr, a.len);
}

static int
cmpaddrs3(const void *_a, const void *_b, void *_)
{
	chunk_t a = ((host_t *)_a)->get_address((host_t *)_a);
	chunk_t b = ((host_t *)_b)->get_address((host_t *)_b);

	if (a.len < b.len)
		return -1;
	if (a.len > b.len)
		return 1;
	return memcmp(a.ptr, b.ptr, a.len);
}

#if 0
static int
addrseq(void *_a, void *_b)
{
    return cmpaddrs(_a, _b) == 0;
}
#endif

/**
 * callback function that raises the delayed roam event
 */
static job_requeue_t
roam_event(private_kernel_vpp_net_t *this)
{
	bool address;

	this->roam_lock->lock(this->roam_lock);
	address = this->roam_address;
	this->roam_address = FALSE;
	this->roam_lock->unlock(this->roam_lock);
	NDBG1("roam_event: %s", address ? "address-update" : "global");
	charon->kernel->roam(charon->kernel, address);
	return JOB_REQUEUE_NONE;
}

/**
 * fire a roaming event. we delay it for a bit and fire only one event
 * for multiple calls. otherwise we would create too many events.
 */
static void
fire_roam_event(private_kernel_vpp_net_t *this, bool address)
{
	timeval_t now;
	job_t *job;

	if (!this->roam_events)
	{
		return;
	}

	NDBG3("fire_roam_event: (schedule) due to %s",
		  address ? "address-update" : "global");

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

	job = (job_t *)callback_job_create((callback_job_cb_t)roam_event, this,
									   NULL, NULL);
	lib->scheduler->schedule_job_ms(lib->scheduler, job, ROAM_DELAY);
}

/**
 * Get an iface entry for a local address
 */
static iface_t *
address2entry(private_kernel_vpp_net_t *this, host_t *ip)
{
	enumerator_t *ifaces;
	iface_t *entry;

	ifaces = this->ifaces->create_enumerator(this->ifaces);
	while (ifaces->enumerate(ifaces, &entry))
	{
		if (array_bsearch(entry->addrs, ip, cmpaddrs, NULL) != -1)
		{
			ifaces->destroy(ifaces);
			return entry;
		}
	}
	ifaces->destroy(ifaces);
	return NULL;
}

/**
 * Add or remove a route
 */
static status_t
manage_route(private_kernel_vpp_net_t *this, bool add, chunk_t dst,
			 uint8_t prefixlen, host_t *gtw, char *name)
{
	char *out;
	int out_len;
	enumerator_t *enumerator;
	iface_t *entry;
	vl_api_ip_route_add_del_t *mp;
	vl_api_ip_route_add_del_reply_t *rmp;
	vl_api_fib_path_t *fibp;
	bool exists = FALSE;

	NDBG3("%s: %s dest %B pfxlen %d gw %H dev %s", __FUNCTION__,
		  add ? "ADDING" : "REMOVING", &dst, prefixlen, gtw, name);

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(name, entry->if_name))
		{
			exists = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (!exists)
	{
		NDBG3("%s: %s NOT FOUND", __FUNCTION__, name);
		return NOT_FOUND;
	}

	size_t msg_size = sizeof(*mp) + sizeof(*fibp) * (gtw != NULL);
	mp = vl_msg_api_alloc_zero(msg_size);
	mp->_vl_msg_id = VL_API_IP_ROUTE_ADD_DEL;
	mp->is_add = add;

	/* mp->route.table_id = 0; default table */
	/* mp->route.stats_index = 0; who knows why we need this */
	chunk_to_api(dst, &mp->route.prefix.address);
	mp->route.prefix.len = prefixlen;
	if (gtw)
	{
		chunk_t gwc = gtw->get_address(gtw);

		mp->route.n_paths = 1;
		fibp = mp->route.paths;
		fibp->sw_if_index = entry->index;
		fibp->table_id = mp->route.table_id;
		/* fibp->rpf_id = 0; */
		/* fibp->weight = 0; */
		/* fibp->preference = 0; */
		/* fibp->type = 0; */
		/* fibp->flags = 0; */
		/* fibp->n_labels = 0; */
		if (gwc.len == IPV4_LEN)
			fibp->proto = FIB_API_PATH_NH_PROTO_IP4;
		else
			fibp->proto = FIB_API_PATH_NH_PROTO_IP6;
		chunk_to_addrun(gwc, &fibp->nh.address);
	}

	/* Convert to network order and send */
	vl_api_ip_route_add_del_t_endian(mp);
	if (vac->send(vac, (char *)mp, msg_size, &out, &out_len))
	{
		KDBG1("vac %sing route failed", add ? "add" : "remov");
		vl_msg_api_free(mp);
		return FAILED;
	}

	/* Get reply and convert to host order */
	rmp = (void *)out;
	vl_api_ip_route_add_del_reply_t_endian(rmp);

	vl_msg_api_free(mp);
	if (rmp->retval)
	{
		KDBG1("%s route failed: %E", add ? "add" : "delete", rmp->retval);
		free(out);
		return FAILED;
	}
	free(out);
	return SUCCESS;
}

#ifdef HAVE_VL_API_IP_ROUTE_LOOKUP
/**
 * Get a route: If "nexthop" the nexthop is returned, source addr otherwise
 */
static host_t *
get_route(private_kernel_vpp_net_t *this, host_t *dest, int prefix,
		  bool nexthop, char **iface, host_t *src)
{
	/* XXX chopps: does nothing with src except clone it */
	fib_path_t path;
	char *out;
	int family, out_len;
	host_t *addr = NULL;
	enumerator_t *enumerator;
	iface_t *entry;

	path.sw_if_index = ~0;
	path.preference = ~0;
	path.next_hop = chunk_empty;

	vl_api_ip_route_lookup_t *mp;
	vl_api_ip_route_lookup_reply_t *rmp;
	int addrlen;

	NDBG3("get_route: LOOKUP dest %H pfxlen %d nexthop %d", dest, prefix,
		  nexthop);

	family = dest->get_family(dest);
	addrlen = (family == AF_INET) ? IPV4_LEN : IPV6_LEN;
	if (prefix == -1)
	{
		prefix = (family == AF_INET) ? 32 : 128;
	}

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IP_ROUTE_LOOKUP;
	/* mp->table_id = 0; default table */

	chunk_to_api(dest->get_address(dest), &mp->prefix.address);
	mp->prefix.len = prefix;

	/* Convert to network order and send */
	vl_api_ip_route_lookup_t_endian(mp);
	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		return NULL;
	}

	vl_msg_api_free(mp);

	/* Get reply and convert to host order */
	rmp = (vl_api_ip_route_lookup_reply_t *)out;
	vl_api_ip_route_lookup_reply_t_endian(rmp);

	vl_api_ip_route_t *route = &rmp->route;
	vl_api_fib_path_t *nh = route->paths;
	vl_api_fib_path_t *enh = nh + route->n_paths;

	for (; nh < enh; nh++)
	{
		chunk_t chunk = addrun_to_chunk(&nh->nh.address, addrlen);
		NDBG3("get_route: CANDIDATE for dest %H pfxlen %d nexthop %d: "
			  "type %d flags 0x%x proto %d sw_if_index %d address %B "
			  "preference %d weight %d",
			  dest, prefix, nexthop, nh->type, nh->flags, nh->proto,
			  nh->sw_if_index, &chunk, nh->preference, nh->weight);

		if ((family == AF_INET && nh->proto != FIB_API_PATH_NH_PROTO_IP4) ||
			(family == AF_INET6 && nh->proto != FIB_API_PATH_NH_PROTO_IP6) ||
			(nh->type != FIB_API_PATH_TYPE_NORMAL &&
			 nh->type != FIB_API_PATH_TYPE_LOCAL))
		{
			continue;
		}
		else if ((nh->preference < path.preference) || (path.sw_if_index == ~0))
		{
			path.sw_if_index = nh->sw_if_index;
			path.preference = nh->preference;
			path.next_hop = addrun_to_chunk(&nh->nh.address, addrlen);
		}
	}

	if (path.next_hop.len || path.sw_if_index != ~0)
	{
		if (nexthop)
		{
			if (iface)
			{
				*iface = NULL;
				this->mutex->lock(this->mutex);
				enumerator = this->ifaces->create_enumerator(this->ifaces);
				while (enumerator->enumerate(enumerator, &entry))
				{
					if (entry->index == path.sw_if_index)
					{
						*iface = strdup(entry->if_name);
						break;
					}
				}
				enumerator->destroy(enumerator);
				this->mutex->unlock(this->mutex);
			}
			addr = host_create_from_chunk(family, path.next_hop, 0);

			NDBG3("get_route: FOUND: dest %H -> nexthop: %H iface: %s", dest,
				  addr, (iface && *iface) ? *iface : "");
		}
		else if (src)
		{
			/* XXX chopps this is probably bogus */
			addr = src->clone(src);
		}
	}
	else
	{
		if (iface)
		{
			*iface = NULL;
		}
		NDBG3("get_route: NOTFOUND dest %H pfxlen %d nexthop %d", dest, prefix,
			  nexthop);
	}

	free(out);
	return addr;
}
#else

/**
 * Check if a prefix (covers) contains a prefix (pfx)
 */
static inline bool
prefix_covers_prefix(chunk_t covers, int covlen, chunk_t pfx, int pfxlen)
{
	static const u_char mask[] = {0x00, 0x80, 0xc0, 0xe0,
								  0xf0, 0xf8, 0xfc, 0xfe};
	int byte = 0;

	if (covlen == 0)
	{
		/* any address matches a /0 network */
		return TRUE;
	}
	if (pfxlen < covlen)
	{
		return FALSE;
	}

	ASSERT(covers.len == covers.len);
	ASSERT(covlen <= 8 * covers.len);

	/* scan through all bytes in network order */
	while (covlen)
	{
		if (covlen < 8)
		{
			return (mask[covlen] & pfx.ptr[byte]) ==
				   (mask[covlen] & covers.ptr[byte]);
		}
		else
		{
			if (pfx.ptr[byte] != covers.ptr[byte])
			{
				return FALSE;
			}
			byte++;
			covlen -= 8;
		}
	}
	return TRUE;
}

/**
 * Get a route: If "nexthop" the nexthop is returned, source addr otherwise
 */
static host_t *
get_route(private_kernel_vpp_net_t *this, host_t *dest, int pfxlen,
		  bool nexthop, char **iface, host_t *src)
{
	/*
	 * No get-route option from VPP so do a dump of the fib and filter on our
	 * routes
	 */
	/* XXX chopps: does nothing with src except clone it */
	char *out, *walk, *ewalk;
	int family, out_len;
	host_t *addr = NULL;
	enumerator_t *enumerator;
	iface_t *entry;
	int best_prefix_len = -1;
	vl_api_ip_route_dump_t *mp;
	int addrlen;

	NDBG3("get_route: LOOKUP dest %H pfxlen %d nexthop %d", dest, pfxlen,
		  nexthop);

	family = dest->get_family(dest);
	addrlen = (family == AF_INET) ? IPV4_LEN : IPV6_LEN;
	if (pfxlen == -1)
	{
		pfxlen = (family == AF_INET) ? 32 : 128;
	}

	uint32_t path_if_index = ~0;
	uint8_t path_pref = ~0;
	host_t *path_nh = NULL;

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IP_ROUTE_DUMP;
	mp->table.is_ip6 = family == AF_INET6;
	/* mp->table.table_id = 0; default table */

	/* Convert to network order and send */
	vl_api_ip_route_dump_t_endian(mp);
	if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		return NULL;
	}

	vl_msg_api_free(mp);

	walk = out;
	ewalk = out + out_len;
	vl_api_fib_path_t *nh, *enh;
	for (; walk < ewalk; walk = (char *)enh)
	{

		vl_api_ip_route_details_t *rmp = (vl_api_ip_route_details_t *)walk;
		vl_api_ip_route_t *route = &rmp->route;

		/* Convert to host order */
		vl_api_ip_route_t_endian(route);

		nh = route->paths;
		enh = nh + route->n_paths;

		/* If we already have a better/equal prefix skip this one */
		if (route->prefix.len <= best_prefix_len)
		{
			continue;
		}

		/* Crazy to allocate memory if the debug isn't going to print */
		host_t *host_pfx = addr_to_host(&route->prefix.address);
		NDBG4("get_route: CHECK_PREFIX %H/%d for dest %H/%d", host_pfx,
			  route->prefix.len, dest, pfxlen);
		free(host_pfx);

		if (!prefix_covers_prefix(
				addrun_to_chunk(&route->prefix.address.un, addrlen),
				route->prefix.len, dest->get_address(dest), pfxlen))
		{
			continue;
		}

		for (; nh < enh; nh++)
		{
			host_t *host_nh = addrun_to_host(&nh->nh.address, addrlen);
			NDBG4("get_route: CANDIDATE for dest %H pfxlen %d nexthop %d: "
				  "type %d flags 0x%x proto %d sw_if_index %d address %H "
				  "preference %d weight %d",
				  dest, pfxlen, nexthop, nh->type, nh->flags, nh->proto,
				  nh->sw_if_index, host_nh, nh->preference, nh->weight);

			if ((family == AF_INET && nh->proto != FIB_API_PATH_NH_PROTO_IP4) ||
				(family == AF_INET6 &&
				 nh->proto != FIB_API_PATH_NH_PROTO_IP6) ||
				(nh->type != FIB_API_PATH_TYPE_NORMAL &&
				 nh->type != FIB_API_PATH_TYPE_LOCAL))
			{
				free(host_nh);
				continue;
			}
			else if (!path_nh || route->prefix.len > best_prefix_len ||
					 (nh->preference < path_pref))
			{
				best_prefix_len = route->prefix.len;
				path_if_index = nh->sw_if_index;
				path_pref = nh->preference;

				free(path_nh);
				path_nh = host_nh;
			}
			else
			{
				free(host_nh);
			}
		}
	}

	if (best_prefix_len != -1)
	{
		if (nexthop)
		{
			if (iface)
			{
				*iface = NULL;
				this->mutex->lock(this->mutex);
				enumerator = this->ifaces->create_enumerator(this->ifaces);
				while (enumerator->enumerate(enumerator, &entry))
				{
					if (entry->index == path_if_index)
					{
						*iface = strdup(entry->if_name);
						break;
					}
				}
				enumerator->destroy(enumerator);
				this->mutex->unlock(this->mutex);
			}
			addr = path_nh->clone(path_nh);

			NDBG3("get_route: FOUND: dest %H/%d -> nexthop: %H iface: %s", dest,
				  pfxlen, addr, (iface && *iface) ? *iface : "");
		}
		else if (src)
		{
			/* XXX chopps this is probably bogus */
			addr = src->clone(src);
		}
	}
	else
	{
		if (iface)
		{
			*iface = NULL;
		}
		NDBG3("get_route: NOTFOUND dest %H pfxlen %d nexthop %d", dest, pfxlen,
			  nexthop);
	}
	free(path_nh);
	free(out);
	return addr;
}
#endif

METHOD(enumerator_t, addr_enumerate, bool, addr_enumerator_t *this,
	   va_list args)
{
	iface_t *entry;
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
			if (!entry->up && !(this->which & ADDR_TYPE_DOWN))
			{
				continue;
			}
			this->addrs = array_create_enumerator(entry->addrs);
		}
		if (this->addrs->enumerate(this->addrs, host))
		{
			return TRUE;
		}
		if (this->addrs)
		{
			this->addrs->destroy(this->addrs);
		}
		this->addrs = NULL;
	}
}

METHOD(enumerator_t, addr_destroy, void, addr_enumerator_t *this)
{
	DESTROY_IF(this->addrs);
	this->ifaces->destroy(this->ifaces);
	this->mutex->unlock(this->mutex);
	free(this);
}

METHOD(kernel_net_t, get_interface_name, bool, private_kernel_vpp_net_t *this,
	   host_t *ip, char **name)
{
	iface_t *entry;

	this->mutex->lock(this->mutex);
	entry = address2entry(this, ip);
	if (entry && name)
	{
		*name = strdup(entry->if_name);
	}
	this->mutex->unlock(this->mutex);

	return entry != NULL;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t *,
	   private_kernel_vpp_net_t *this, kernel_address_type_t which)
{
	addr_enumerator_t *enumerator;

	if (!(which & ADDR_TYPE_REGULAR))
	{
		/* we currently have no virtual, but regular IPs only */
		return enumerator_create_empty();
	}

	this->mutex->lock(this->mutex);

	INIT(enumerator,
		 .public =
			 {
				 .enumerate = enumerator_enumerate_default,
				 .venumerate = _addr_enumerate,
				 .destroy = _addr_destroy,
			 },
		 .which = which,
		 .ifaces = this->ifaces->create_enumerator(this->ifaces),
		 .mutex = this->mutex, );
	return &enumerator->public;
}

METHOD(kernel_net_t, get_source_addr, host_t *, private_kernel_vpp_net_t *this,
	   host_t *dest, host_t *src)
{
	return get_route(this, dest, -1, FALSE, NULL, src);
}

METHOD(kernel_net_t, get_nexthop, host_t *, private_kernel_vpp_net_t *this,
	   host_t *dest, int prefix, host_t *src, char **iface)
{
	return get_route(this, dest, prefix, TRUE, iface, src);
}

METHOD(kernel_net_t, add_ip, status_t, private_kernel_vpp_net_t *this,
	   host_t *virtual_ip, int prefix, char *iface_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_ip, status_t, private_kernel_vpp_net_t *this,
	   host_t *virtual_ip, int prefix, bool wait)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, add_route, status_t, private_kernel_vpp_net_t *this,
	   chunk_t dst_net, u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
	   char *if_name)
{
	return manage_route(this, TRUE, dst_net, prefixlen, gateway, if_name);
}

METHOD(kernel_net_t, del_route, status_t, private_kernel_vpp_net_t *this,
	   chunk_t dst_net, u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
	   char *if_name)
{
	return manage_route(this, FALSE, dst_net, prefixlen, gateway, if_name);
}

static void
iface_destroy(iface_t *this)
{
	array_destroy_offset(this->addrs, offsetof(host_t, destroy));
	free(this);
}

METHOD(kernel_net_t, destroy, void, private_kernel_vpp_net_t *this)
{
	this->net_update->cancel(this->net_update);
	this->mutex->destroy(this->mutex);
	this->ifaces->destroy_function(this->ifaces, (void *)iface_destroy);
	free(this);
}

static int
array_is_equal(array_t *a, array_t *b,
			   int (*cmp)(const void *, const void *, void *), void *data)
{
	int i, count = array_count(a);
	if (count != array_count(b))
	{
		return FALSE;
	}
	for (i = 0; i < count; i++)
	{
		host_t *ha, *hb;
		(void)array_get(a, i, (void *)&ha);
		(void)array_get(b, i, (void *)&hb);
		if (cmp(ha, hb, data))
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Update addresses for an iface entry
 */
static int
update_addrs(private_kernel_vpp_net_t *this, iface_t *entry)
{
	char *out4 = NULL, *out6 = NULL;
	int i, out_len4, out_len6;
	vl_api_ip_address_dump_t *mp;
	vl_api_ip_address_details_t *rmp, *ermp;
	array_t *addrs;
	host_t *host;
	int signal = FALSE;

	NDBG3("interface %s: requesting addresses", entry->if_name);

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IP_ADDRESS_DUMP;
	mp->sw_if_index = entry->index;

	/* Convert to network order and send */
	vl_api_ip_address_dump_t_endian(mp);
	mp->is_ipv6 = 0;
	if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out4, &out_len4))
		goto out;
	mp->is_ipv6 = 1;
	if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out6, &out_len6))
		goto out;

	addrs = array_create(0, (out_len4 + out_len6) / sizeof(*rmp));
	rmp = (void *)out4;
	ermp = rmp + (out_len4 / sizeof(*rmp));
	i = 0;
	for (; rmp < ermp; rmp++)
	{
		/* convert reply to host order */
		/* XXX this function uses an unimplemented endian conversion for the
		   prefix. */
		fixed_vl_api_ip_address_details_t_endian(rmp);
		host = addr_to_host(&rmp->prefix.address);
		NDBG3("interface %s: got addr %H", entry->if_name, host);
		array_insert(addrs, i++, host);
	}

	rmp = (void *)out6;
	ermp = rmp + (out_len6 / sizeof(*rmp));
	for (; rmp < ermp; rmp++)
	{
		/* convert reply to host order */
		fixed_vl_api_ip_address_details_t_endian(rmp);
		host = addr_to_host(&rmp->prefix.address);
		NDBG3("interface %s: got addr %H", entry->if_name, host);
		array_insert(addrs, i++, host);
	}

	array_sort(addrs, cmpaddrs3, 0);

	int changed = !entry->addrs
					  ? TRUE
					  : !array_is_equal(entry->addrs, addrs, cmpaddrs3, NULL);

	if (changed)
	{
		/* Would be nice if we had an API to check if this will be filtered */
		int count;
		if (entry->addrs)
		{
			for (i = 0, count = array_count(entry->addrs); i < count; i++)
			{
				(void)array_get(entry->addrs, i, &host);
				NDBG3("interface %s: OLD ADDR: %H", entry->if_name, host);
			}
		}
		for (i = 0, count = array_count(addrs); i < count; i++)
		{
			(void)array_get(addrs, i, &host);
			NDBG3("interface %s: NEW ADDR: %H", entry->if_name, host);
		}
	}

	if (changed && entry->addrs)
	{
		array_destroy_offset(entry->addrs, offsetof(host_t, destroy));
		entry->addrs = addrs;
		/* Let everyone know something changed */
		if (entry->usable && entry->up)
		{
			signal = TRUE;
		}
	}
	else if (!entry->addrs)
	{
		entry->addrs = addrs;
	}
out:
	vl_msg_api_free(mp);
	free(out4);
	free(out6);

	return signal;
}

/**
 * VPP API interface event callback
 */
static void
event_cb(char *data, int data_len, void *ctx)
{
	private_kernel_vpp_net_t *this = ctx;
	vl_api_sw_interface_event_t *event;
	iface_t *entry;
	enumerator_t *enumerator;

	/* Get event data and convert to host order */
	event = (void *)data;
	vl_api_sw_interface_event_t_endian(event);

	NDBG3("interface event %d", event->sw_if_index);
	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->index == event->sw_if_index)
		{
			bool admin_up;
#ifdef HAVE_VL_API_IF_STATUS_FLAGS_T
			admin_up = (event->flags & IF_STATUS_API_FLAG_ADMIN_UP) != 0;
#else
			admin_up = event->admin_up_down ? TRUE : FALSE;
#endif
			if (event->deleted)
			{
				this->ifaces->remove_at(this->ifaces, enumerator);
				NDBG2("interface deleted %u %s", entry->index, entry->if_name);
				iface_destroy(entry);
			}
			else if (entry->up != admin_up)
			{
				entry->up = admin_up;
				NDBG2("interface state changed %u %s %s", entry->index,
					  entry->if_name, entry->up ? "UP" : "DOWN");
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	free(data);
}

/**
 * Inteface update thread (update interface list and interface address)
 */
static void *
net_update_thread_fn(private_kernel_vpp_net_t *this)
{
	status_t rv;
	while (1)
	{
		char *out;
		int out_len;
		vl_api_sw_interface_dump_t *mp;
		vl_api_sw_interface_details_t *rmp, *ermp;
		enumerator_t *enumerator;
		iface_t *entry;
		int signal = FALSE;

		mp = vl_msg_api_alloc_zero(sizeof(*mp));
		mp->_vl_msg_id = VL_API_SW_INTERFACE_DUMP;
		mp->name_filter_valid = 0;

		/* Convert to network order and send */
		vl_api_sw_interface_dump_t_endian(mp);
		rv = vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len);
		if (!rv)
		{

			this->mutex->lock(this->mutex);
			enumerator = this->ifaces->create_enumerator(this->ifaces);
			rmp = (void *)out;
			ermp = rmp + (out_len / sizeof(*rmp));
			for (; rmp < ermp; rmp++)
			{
				bool exists = FALSE;

				/* Convert reply to host order */
				vl_api_sw_interface_details_t_endian(rmp);

				while (enumerator->enumerate(enumerator, &entry))
				{
					if (entry->index == rmp->sw_if_index)
					{
						exists = TRUE;
						break;
					}
				}
				if (!exists)
				{
					bool admin_up;
#ifdef HAVE_VL_API_IF_STATUS_FLAGS_T
					admin_up = (rmp->flags & IF_STATUS_API_FLAG_ADMIN_UP) != 0;
#else
					admin_up = rmp->admin_up_down ? TRUE : FALSE;
#endif
					INIT(entry, .index = rmp->sw_if_index, .up = admin_up,
						 .addrs = NULL, );
					strncpy(entry->if_name, rmp->interface_name, 64);
					KDBG2("IF %d %s %s", entry->index, entry->if_name,
						  entry->up ? "UP" : "DOWN");
					this->ifaces->insert_last(this->ifaces, entry);

					/* XXX chopps: what if config changed? */
					entry->usable = charon->kernel->is_interface_usable(
						charon->kernel, entry->if_name);
				}

				if (update_addrs(this, entry))
				{
					signal = TRUE;
				}
			}
			enumerator->destroy(enumerator);
			this->mutex->unlock(this->mutex);
			free(out);
		}
		vl_msg_api_free(mp);

		if (!this->events_on)
		{
			vl_api_want_interface_events_t *emp;
#ifdef HAVE_VLIBAPI_GET_MAIN
			api_main_t *am = vlibapi_get_main();
#else
			api_main_t *am = &api_main;
#endif

			emp = vl_msg_api_alloc_zero(sizeof(*emp));
			emp->_vl_msg_id = VL_API_WANT_INTERFACE_EVENTS;
			emp->enable_disable = 1;
			emp->pid = am->our_pid;

			/* Convert to network order and register */
			vl_api_want_interface_events_t_endian(emp);
			rv = vac->register_event(vac, (char *)emp, sizeof(*emp), event_cb,
									 VL_API_SW_INTERFACE_EVENT, this);
			if (!rv)
				this->events_on = TRUE;
		}
		if (signal)
		{
			fire_roam_event(this, TRUE);
		}

		/* XXX chopps: we want events for address changes -- not this */
		sleep(600);
	}
	return NULL;
}

#if 0
METHOD(kernel_net_t, get_sw_if_index, uint32_t, private_kernel_vpp_net_t *this,
	   const char *name)
{
	enumerator_t *enumerator;
	iface_t *entry;
	bool found = FALSE;

	this->mutex->lock(this->mutex);
	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(name, entry->if_name))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return found ? entry->index : ~0;
}
#endif

kernel_vpp_net_t *
kernel_vpp_net_create()
{
	private_kernel_vpp_net_t *this;

	INIT(
		this,
		.public =
			{
				.interface =
					{
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
				/* .get_sw_if_index = _get_sw_if_index, */
			},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.ifaces = linked_list_create(), .events_on = FALSE,

		.roam_lock = spinlock_create(),
		.roam_events = lib->settings->get_bool(
			lib->settings, "%s.plugins.kernel-vpp.roam_events", TRUE,
			lib->ns), );

	this->net_update = thread_create((thread_main_t)net_update_thread_fn, this);
	return &this->public;
}

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
