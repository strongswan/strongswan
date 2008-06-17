/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2003 Herbert Xu.
 * 
 * Based on xfrm code from pluto.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/udp.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "kernel_interface.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <processing/jobs/delete_child_sa_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/acquire_job.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/roam_job.h>

/** routing table for routes installed by us */
#ifndef IPSEC_ROUTING_TABLE
#define IPSEC_ROUTING_TABLE 100
#endif
#ifndef IPSEC_ROUTING_TABLE_PRIO
#define IPSEC_ROUTING_TABLE_PRIO 100
#endif

/** kernel level protocol identifiers */
#define KERNEL_ESP 50
#define KERNEL_AH 51

/** default priority of installed policies */
#define PRIO_LOW 3000
#define PRIO_HIGH 2000

/** delay before firing roam jobs (ms) */
#define ROAM_DELAY 100

#define BUFFER_SIZE 1024

/**
 * returns a pointer to the first rtattr following the nlmsghdr *nlh and the 
 * 'usual' netlink data x like 'struct xfrm_usersa_info' 
 */
#define XFRM_RTA(nlh, x) ((struct rtattr*)(NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(x))))
/**
 * returns a pointer to the next rtattr following rta.
 * !!! do not use this to parse messages. use RTA_NEXT and RTA_OK instead !!!
 */
#define XFRM_RTA_NEXT(rta) ((struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
/**
 * returns the total size of attached rta data 
 * (after 'usual' netlink data x like 'struct xfrm_usersa_info') 
 */
#define XFRM_PAYLOAD(nlh, x) NLMSG_PAYLOAD(nlh, sizeof(x))

typedef struct kernel_algorithm_t kernel_algorithm_t;

/**
 * Mapping from the algorithms defined in IKEv2 to
 * kernel level algorithm names and their key length
 */
struct kernel_algorithm_t {
	/**
	 * Identifier specified in IKEv2
	 */
	int ikev2_id;
	
	/**
	 * Name of the algorithm, as used as kernel identifier
	 */
	char *name;
	
	/**
	 * Key length in bits, if fixed size
	 */
	u_int key_size;
};
#define END_OF_LIST -1

/**
 * Algorithms for encryption
 */
static kernel_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64, 		"***", 					0}, */
	{ENCR_DES, 				"des", 					64},
	{ENCR_3DES, 			"des3_ede",				192},
/*	{ENCR_RC5, 				"***", 					0}, */
/*	{ENCR_IDEA, 			"***",					0}, */
	{ENCR_CAST, 			"cast128",				0},
	{ENCR_BLOWFISH, 		"blowfish",				0},
/*	{ENCR_3IDEA, 			"***",					0}, */
/*	{ENCR_DES_IV32, 		"***",					0}, */
	{ENCR_NULL, 			"cipher_null",			0},
	{ENCR_AES_CBC,	 		"aes",					0},
/*	{ENCR_AES_CTR, 			"***",					0}, */
	{ENCR_AES_CCM_ICV8,		"rfc4309(ccm(aes))",	64},	/* key_size = ICV size */
	{ENCR_AES_CCM_ICV12,	"rfc4309(ccm(aes))",	96},	/* key_size = ICV size */
	{ENCR_AES_CCM_ICV16,	"rfc4309(ccm(aes))",	128},	/* key_size = ICV size */
	{ENCR_AES_GCM_ICV8,		"rfc4106(gcm(aes))",	64},	/* key_size = ICV size */
	{ENCR_AES_GCM_ICV12,	"rfc4106(gcm(aes))",	96},	/* key_size = ICV size */
	{ENCR_AES_GCM_ICV16,	"rfc4106(gcm(aes))",	128},	/* key_size = ICV size */
	{END_OF_LIST, 		NULL,			0},
};

/**
 * Algorithms for integrity protection
 */
static kernel_algorithm_t integrity_algs[] = {
	{AUTH_HMAC_MD5_96, 			"md5",			128},
	{AUTH_HMAC_SHA1_96,			"sha1",			160},
	{AUTH_HMAC_SHA2_256_128,	"sha256",		256},
	{AUTH_HMAC_SHA2_384_192,	"sha384",		384},
	{AUTH_HMAC_SHA2_512_256,	"sha512",		512},
/*	{AUTH_DES_MAC,				"***",			0}, */
/*	{AUTH_KPDK_MD5,				"***",			0}, */
	{AUTH_AES_XCBC_96,			"xcbc(aes)",	128},
	{END_OF_LIST, 				NULL,			0},
};

/**
 * Algorithms for IPComp
 */
static kernel_algorithm_t compression_algs[] = {
/*	{IPCOMP_OUI, 			"***",			0}, */
	{IPCOMP_DEFLATE,		"deflate",		0},
	{IPCOMP_LZS,			"lzs",			0},
	{IPCOMP_LZJH,			"lzjh",			0},
	{END_OF_LIST, 			NULL,			0},
};

/**
 * Look up a kernel algorithm name and its key size
 */
static char* lookup_algorithm(kernel_algorithm_t *kernel_algo, 
					   u_int16_t ikev2_algo, u_int16_t *key_size)
{
	while (kernel_algo->ikev2_id != END_OF_LIST)
	{
		if (ikev2_algo == kernel_algo->ikev2_id)
		{
			/* match, evaluate key length */
			if (key_size && *key_size == 0)
			{	/* update key size if not set */
				*key_size = kernel_algo->key_size;
			}
			return kernel_algo->name;
		}
		kernel_algo++;
	}
	return NULL;
}

typedef struct route_entry_t route_entry_t;

/**
 * installed routing entry
 */
struct route_entry_t {

	/** Index of the interface the route is bound to */
	int if_index;

	/** Source ip of the route */
	host_t *src_ip;
	
	/** gateway for this route */
	host_t *gateway;

	/** Destination net */
	chunk_t dst_net;

	/** Destination net prefixlen */
	u_int8_t prefixlen;
};

/**
 * destroy an route_entry_t object
 */
static void route_entry_destroy(route_entry_t *this)
{
	this->src_ip->destroy(this->src_ip);
	this->gateway->destroy(this->gateway);
	chunk_free(&this->dst_net);
	free(this);
}

typedef struct policy_entry_t policy_entry_t;

/**
 * installed kernel policy.
 */
struct policy_entry_t {
	
	/** direction of this policy: in, out, forward */
	u_int8_t direction;
	
	/** reqid of the policy */
	u_int32_t reqid;
	
	/** parameters of installed policy */
	struct xfrm_selector sel;
	
	/** associated route installed for this policy */
	route_entry_t *route;
	
	/** by how many CHILD_SA's this policy is used */
	u_int refcount;
};

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

typedef struct private_kernel_interface_t private_kernel_interface_t;

/**
 * Private variables and functions of kernel_interface class.
 */
struct private_kernel_interface_t {
	/**
	 * Public part of the kernel_interface_t object.
	 */
	kernel_interface_t public;
	
	/**
	 * mutex to lock access to netlink socket
	 */
	pthread_mutex_t nl_mutex;
	
	/**
	 * mutex to lock access to various lists
	 */
	pthread_mutex_t mutex;
	
	/**
	 * condition variable to signal virtual IP add/removal
	 */
	pthread_cond_t cond;
	
	/**
	 * List of installed policies (policy_entry_t)
	 */
	linked_list_t *policies;
	
	/**
	 * Cached list of interfaces and its adresses (iface_entry_t)
	 */
	linked_list_t *ifaces;
	
	/**
	 * iterator used in hook()
	 */
	iterator_t *hiter;
	 
	/**
	 * job receiving netlink events
	 */
	callback_job_t *job;
	
	/**
	 * current sequence number for netlink request
	 */
	int seq;
	
	/**
	 * Netlink xfrm socket (IPsec)
	 */
	int socket_xfrm;
	
	/**
	 * netlink xfrm socket to receive acquire and expire events
	 */
	int socket_xfrm_events;
	
	/**
	 * Netlink rt socket (routing)
	 */
	int socket_rt;
	
	/**
	 * Netlink rt socket to receive address change events
	 */
	int socket_rt_events;
	
	/**
	 * time of the last roam_job
	 */
	struct timeval last_roam;
	
	/**
	 * whether to install routes along policies
	 */
	bool install_routes;
	
	/**
	 * routing table to install routes
	 */
	int routing_table;
	
	/**
	 * priority of used routing table
	 */
	int routing_table_prio;
};

/**
 * convert a host_t to a struct xfrm_address
 */
static void host2xfrm(host_t *host, xfrm_address_t *xfrm)
{
	chunk_t chunk = host->get_address(host);
	memcpy(xfrm, chunk.ptr, min(chunk.len, sizeof(xfrm_address_t)));	
}

/**
 * convert a traffic selector address range to subnet and its mask.
 */
static void ts2subnet(traffic_selector_t* ts, 
					  xfrm_address_t *net, u_int8_t *mask)
{
	/* there is no way to do this cleanly, as the address range may
	 * be anything else but a subnet. We use from_addr as subnet 
	 * and try to calculate a usable subnet mask.
	 */
	int byte, bit;
	bool found = FALSE;
	chunk_t from, to;
	size_t size = (ts->get_type(ts) == TS_IPV4_ADDR_RANGE) ? 4 : 16;
	
	from = ts->get_from_address(ts);
	to = ts->get_to_address(ts);
	
	*mask = (size * 8);
	/* go trough all bits of the addresses, beginning in the front.
	 * as long as they are equal, the subnet gets larger
	 */
	for (byte = 0; byte < size; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			if ((1<<bit & from.ptr[byte]) != (1<<bit & to.ptr[byte]))
			{
				*mask = ((7 - bit) + (byte * 8));
				found = TRUE;
				break;
			}
		}
		if (found)
		{
			break;
		}
	}
	memcpy(net, from.ptr, from.len);
	chunk_free(&from);
	chunk_free(&to);
}

/**
 * convert a traffic selector port range to port/portmask
 */
static void ts2ports(traffic_selector_t* ts, 
					 u_int16_t *port, u_int16_t *mask)
{
	/* linux does not seem to accept complex portmasks. Only
	 * any or a specific port is allowed. We set to any, if we have
	 * a port range, or to a specific, if we have one port only.
	 */
	u_int16_t from, to;
	
	from = ts->get_from_port(ts);
	to = ts->get_to_port(ts);
	
	if (from == to)
	{
		*port = htons(from);
		*mask = ~0;
	}
	else
	{
		*port = 0;
		*mask = 0;
	}
}

/**
 * convert a pair of traffic_selectors to a xfrm_selector
 */
static struct xfrm_selector ts2selector(traffic_selector_t *src, 
										traffic_selector_t *dst)
{
	struct xfrm_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.family = src->get_type(src) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
	/* src or dest proto may be "any" (0), use more restrictive one */
	sel.proto = max(src->get_protocol(src), dst->get_protocol(dst));
	ts2subnet(dst, &sel.daddr, &sel.prefixlen_d);
	ts2subnet(src, &sel.saddr, &sel.prefixlen_s);
	ts2ports(dst, &sel.dport, &sel.dport_mask);
	ts2ports(src, &sel.sport, &sel.sport_mask);
	sel.ifindex = 0;
	sel.user = 0;
	
	return sel;
}

/**
 * Creates an rtattr and adds it to the netlink message
 */
static void add_attribute(struct nlmsghdr *hdr, int rta_type, chunk_t data,
						  size_t buflen)
{
	struct rtattr *rta;
	
	if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(data.len) > buflen)
	{
		DBG1(DBG_KNL, "unable to add attribute, buffer too small");
		return;
	}
	
	rta = (struct rtattr*)(((char*)hdr) + NLMSG_ALIGN(hdr->nlmsg_len));
	rta->rta_type = rta_type;
	rta->rta_len = RTA_LENGTH(data.len);
	memcpy(RTA_DATA(rta), data.ptr, data.len);
	hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + rta->rta_len;
}

/**
 * process a XFRM_MSG_ACQUIRE from kernel
 */
static void process_acquire(private_kernel_interface_t *this, struct nlmsghdr *hdr)
{
	u_int32_t reqid = 0;
	job_t *job;
	struct rtattr *rtattr = XFRM_RTA(hdr, struct xfrm_user_acquire);
	size_t rtsize = XFRM_PAYLOAD(hdr, struct xfrm_user_tmpl);
	
	if (RTA_OK(rtattr, rtsize))
	{
		if (rtattr->rta_type == XFRMA_TMPL)
		{
			struct xfrm_user_tmpl* tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rtattr);
			reqid = tmpl->reqid;
		}
	}
	if (reqid == 0)
	{
		DBG1(DBG_KNL, "received a XFRM_MSG_ACQUIRE, but no reqid found");
		return;
	}
	DBG2(DBG_KNL, "received a XFRM_MSG_ACQUIRE");
	DBG1(DBG_KNL, "creating acquire job for CHILD_SA with reqid %d", reqid);
	job = (job_t*)acquire_job_create(reqid);
	charon->processor->queue_job(charon->processor, job);
}

/**
 * process a XFRM_MSG_EXPIRE from kernel
 */
static void process_expire(private_kernel_interface_t *this, struct nlmsghdr *hdr)
{
	job_t *job;
	protocol_id_t protocol;
	u_int32_t spi, reqid;
	struct xfrm_user_expire *expire;
	
	expire = (struct xfrm_user_expire*)NLMSG_DATA(hdr);
	protocol = expire->state.id.proto;
	protocol = (protocol == KERNEL_ESP) ? PROTO_ESP : (protocol == KERNEL_AH) ? PROTO_AH : protocol;
	spi = expire->state.id.spi;
	reqid = expire->state.reqid;
	
	DBG2(DBG_KNL, "received a XFRM_MSG_EXPIRE");
	
	if (protocol != PROTO_ESP && protocol != PROTO_AH)
	{
		DBG2(DBG_KNL, "ignoring XFRM_MSG_EXPIRE for SA 0x%x (reqid %d) which is "
				"not a CHILD_SA", ntohl(spi), reqid);
		return;
	}
	
	DBG1(DBG_KNL, "creating %s job for %N CHILD_SA 0x%x (reqid %d)",
		 expire->hard ? "delete" : "rekey",  protocol_id_names,
		 protocol, ntohl(spi), reqid);
	if (expire->hard)
	{
		job = (job_t*)delete_child_sa_job_create(reqid, protocol, spi);
	}
	else
	{
		job = (job_t*)rekey_child_sa_job_create(reqid, protocol, spi);
	}
	charon->processor->queue_job(charon->processor, job);
}

/**
 * start a roaming job. We delay it for a second and fire only one job
 * for multiple events. Otherwise we would create two many jobs.
 */
static void fire_roam_job(private_kernel_interface_t *this, bool address)
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
static void process_link(private_kernel_interface_t *this,
						 struct nlmsghdr *hdr, bool event)
{
	struct ifinfomsg* msg = (struct ifinfomsg*)(NLMSG_DATA(hdr));
	struct rtattr *rta = IFLA_RTA(msg);
	size_t rtasize = IFLA_PAYLOAD (hdr);
	iterator_t *iterator;
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
	
	switch (hdr->nlmsg_type)
	{
		case RTM_NEWLINK:
		{
			if (msg->ifi_flags & IFF_LOOPBACK)
			{	/* ignore loopback interfaces */
				break;
			}
			iterator = this->ifaces->create_iterator_locked(this->ifaces,
															&this->mutex);
			while (iterator->iterate(iterator, (void**)&current))
			{
				if (current->ifindex == msg->ifi_index)
				{
					entry = current;
					break;
				}
			}
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
			iterator->destroy(iterator);
			break;
		}
		case RTM_DELLINK:
		{
			iterator = this->ifaces->create_iterator_locked(this->ifaces,
															&this->mutex);
			while (iterator->iterate(iterator, (void**)&current))
			{
				if (current->ifindex == msg->ifi_index)
				{
					/* we do not remove it, as an address may be added to a 
					 * "down" interface and we wan't to know that. */
					current->flags = msg->ifi_flags;
					break;
				}
			}
			iterator->destroy(iterator);
			break;
		}
	}
	
	/* send an update to all IKE_SAs */
	if (update && event)
	{
		fire_roam_job(this, TRUE);
	}
}

/**
 * process RTM_NEWADDR/RTM_DELADDR from kernel
 */
static void process_addr(private_kernel_interface_t *this,
						 struct nlmsghdr *hdr, bool event)
{
	struct ifaddrmsg* msg = (struct ifaddrmsg*)(NLMSG_DATA(hdr));
	struct rtattr *rta = IFA_RTA(msg);
	size_t rtasize = IFA_PAYLOAD (hdr);
	host_t *host = NULL;
	iterator_t *ifaces, *addrs;
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
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		if (iface->ifindex == msg->ifa_index)
		{
			addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
			while (addrs->iterate(addrs, (void**)&addr))
			{
				if (host->ip_equals(host, addr->ip))
				{
					found = TRUE;
					if (hdr->nlmsg_type == RTM_DELADDR)
					{
						changed = TRUE;
						addrs->remove(addrs);
						if (!addr->virtual)
						{
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
	host->destroy(host);
	
	/* send an update to all IKE_SAs */
	if (update && event && changed)
	{
		fire_roam_job(this, TRUE);
	}
}

/**
 * Receives events from kernel
 */
static job_requeue_t receive_events(private_kernel_interface_t *this)
{
	char response[1024];
	struct nlmsghdr *hdr = (struct nlmsghdr*)response;
	struct sockaddr_nl addr;
	socklen_t addr_len = sizeof(addr);
	int len, oldstate, maxfd, selected;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(this->socket_xfrm_events, &rfds);
	FD_SET(this->socket_rt_events, &rfds);
	maxfd = max(this->socket_xfrm_events, this->socket_rt_events);
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	selected = select(maxfd + 1, &rfds, NULL, NULL, NULL);
	pthread_setcancelstate(oldstate, NULL);
	if (selected <= 0)
	{
		DBG1(DBG_KNL, "selecting on sockets failed: %s", strerror(errno));
		return JOB_REQUEUE_FAIR;
	}
	if (FD_ISSET(this->socket_xfrm_events, &rfds))
	{
		selected = this->socket_xfrm_events;
	}
	else if (FD_ISSET(this->socket_rt_events, &rfds))
	{
		selected = this->socket_rt_events;
	}
	else
	{
		return JOB_REQUEUE_DIRECT;
	}
	
	len = recvfrom(selected, response, sizeof(response), MSG_DONTWAIT,
				   (struct sockaddr*)&addr, &addr_len);
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
				DBG1(DBG_KNL, "unable to receive from xfrm event socket");
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
		if (selected == this->socket_xfrm_events)
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_ACQUIRE:
					process_acquire(this, hdr);
					break;
				case XFRM_MSG_EXPIRE:
					process_expire(this, hdr);
					break;
				default:
					break;
			}
		}
		else if (selected == this->socket_rt_events)
		{
			switch (hdr->nlmsg_type)
			{
				case RTM_NEWADDR:
				case RTM_DELADDR:
					process_addr(this, hdr, TRUE);
					pthread_cond_signal(&this->cond);
					break;
				case RTM_NEWLINK:
				case RTM_DELLINK:
					process_link(this, hdr, TRUE);
					pthread_cond_signal(&this->cond);
					break;
				case RTM_NEWROUTE:
				case RTM_DELROUTE:
					fire_roam_job(this, FALSE);
					break;
				default:
					break;
			}
		}
		hdr = NLMSG_NEXT(hdr, len);
	}
	return JOB_REQUEUE_DIRECT;
}

/**
 * send a netlink message and wait for a reply
 */
static status_t netlink_send(private_kernel_interface_t *this,
							 int socket, struct nlmsghdr *in,
							 struct nlmsghdr **out, size_t *out_len)
{
	int len, addr_len;
	struct sockaddr_nl addr;
	chunk_t result = chunk_empty, tmp;
	struct nlmsghdr *msg, peek;
	
	pthread_mutex_lock(&this->nl_mutex);
	
	in->nlmsg_seq = ++this->seq;
	in->nlmsg_pid = getpid();
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;

	while (TRUE)
	{
		len = sendto(socket, in, in->nlmsg_len, 0, 
					 (struct sockaddr*)&addr, sizeof(addr));
		
		if (len != in->nlmsg_len)
		{	
			if (errno == EINTR)
			{
				/* interrupted, try again */
				continue;
			}
			pthread_mutex_unlock(&this->nl_mutex);
			DBG1(DBG_KNL, "error sending to netlink socket: %s", strerror(errno));
			return FAILED;
		}
		break;
	}
	
	while (TRUE)
	{	
		char buf[4096];
		tmp.len = sizeof(buf);
		tmp.ptr = buf;
		msg = (struct nlmsghdr*)tmp.ptr;
		
		memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		addr.nl_pid = getpid();
		addr.nl_groups = 0;
		addr_len = sizeof(addr);
		
		len = recvfrom(socket, tmp.ptr, tmp.len, 0,
					   (struct sockaddr*)&addr, &addr_len);
		
		if (len < 0)
		{
			if (errno == EINTR)
			{
				DBG1(DBG_KNL, "got interrupted");
				/* interrupted, try again */
				continue;
			}
			DBG1(DBG_KNL, "error reading from netlink socket: %s", strerror(errno));
			pthread_mutex_unlock(&this->nl_mutex);
			return FAILED;
		}
		if (!NLMSG_OK(msg, len))
		{
			DBG1(DBG_KNL, "received corrupted netlink message");
			pthread_mutex_unlock(&this->nl_mutex);
			return FAILED;
		}
		if (msg->nlmsg_seq != this->seq)
		{
			DBG1(DBG_KNL, "received invalid netlink sequence number");
			if (msg->nlmsg_seq < this->seq)
			{
				continue;
			}
			pthread_mutex_unlock(&this->nl_mutex);
			return FAILED;
		}
		
		tmp.len = len;
		result = chunk_cata("cc", result, tmp);
		
		/* NLM_F_MULTI flag does not seem to be set correctly, we use sequence
		 * numbers to detect multi header messages */
		len = recvfrom(socket, &peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT,
					   (struct sockaddr*)&addr, &addr_len);
		
		if (len == sizeof(peek) && peek.nlmsg_seq == this->seq)
		{
			/* seems to be multipart */
			continue;
		}
		break;
	}
	
	*out_len = result.len;
	*out = (struct nlmsghdr*)clalloc(result.ptr, result.len);
	
	pthread_mutex_unlock(&this->nl_mutex);
	
	return SUCCESS;
}

/**
 * send a netlink message and wait for its acknowlegde
 */
static status_t netlink_send_ack(private_kernel_interface_t *this,
								 int socket, struct nlmsghdr *in)
{
	struct nlmsghdr *out, *hdr;
	size_t len;

	if (netlink_send(this, socket, in, &out, &len) != SUCCESS)
	{
		return FAILED;
	}
	hdr = out;
	while (NLMSG_OK(hdr, len))
	{
		switch (hdr->nlmsg_type)
		{
			case NLMSG_ERROR:
			{
				struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(hdr);
				
				if (err->error)
				{
					DBG1(DBG_KNL, "received netlink error: %s (%d)",
						 strerror(-err->error), -err->error);
					free(out);
					return FAILED;
				}
				free(out);
				return SUCCESS;
			}
			default:
				hdr = NLMSG_NEXT(hdr, len);
				continue;
			case NLMSG_DONE:
				break;
		}
		break;
	}
	DBG1(DBG_KNL, "netlink request not acknowlegded");
	free(out);
	return FAILED;
}
	
/**
 * Initialize a list of local addresses.
 */
static status_t init_address_list(private_kernel_interface_t *this)
{
	char request[BUFFER_SIZE];
	struct nlmsghdr *out, *current, *in;
	struct rtgenmsg *msg;
	size_t len;
	iterator_t *ifaces, *addrs;
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
	if (netlink_send(this, this->socket_rt, in, &out, &len) != SUCCESS)
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
	if (netlink_send(this, this->socket_rt, in, &out, &len) != SUCCESS)
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
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		if (iface->flags & IFF_UP)
		{
			DBG1(DBG_KNL, "  %s", iface->ifname);
			addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
			while (addrs->iterate(addrs, (void**)&addr))
			{
				DBG1(DBG_KNL, "    %H", addr->ip);
			}
			addrs->destroy(addrs);
		}
	}
	ifaces->destroy(ifaces);
	return SUCCESS;
}

/**
 * iterator hook to iterate over addrs
 */
static hook_result_t addr_hook(private_kernel_interface_t *this,
							   addr_entry_t *in, host_t **out)
{
	if (in->virtual)
	{	/* skip virtual interfaces added by us */
		return HOOK_SKIP;
	}
	if (in->scope >= RT_SCOPE_LINK)
	{	/* skip addresses with a unusable scope */
		return HOOK_SKIP;
	}
	*out = in->ip;
	return HOOK_NEXT;
}
								
/**
 * iterator hook to iterate over ifaces
 */
static hook_result_t iface_hook(private_kernel_interface_t *this,
								iface_entry_t *in, host_t **out)
{
	if (!(in->flags & IFF_UP))
	{	/* skip interfaces not up */
		return HOOK_SKIP;
	}

	if (this->hiter == NULL)
	{
		this->hiter = in->addrs->create_iterator(in->addrs, TRUE);
		this->hiter->set_iterator_hook(this->hiter,
									   (iterator_hook_t*)addr_hook, this);
	}
	while (this->hiter->iterate(this->hiter, (void**)out))
	{
		return HOOK_AGAIN;
	}
	this->hiter->destroy(this->hiter);
	this->hiter = NULL;
	return HOOK_SKIP;
}

/**
 * Implements kernel_interface_t.create_address_iterator.
 */
static iterator_t *create_address_iterator(private_kernel_interface_t *this)
{
	iterator_t *iterator;
	
	/* This iterator is not only hooked, is is double-hooked. As we have stored
	 * our addresses in iface_entry->addr_entry->ip, we need to iterate the
	 * entries in each interface we iterate. This does the iface_hook. The
	 * addr_hook returns the ip instead of the addr_entry. */
	
	iterator = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	iterator->set_iterator_hook(iterator, (iterator_hook_t*)iface_hook, this);
	return iterator;
}

/**
 * implementation of kernel_interface_t.get_interface_name
 */
static char *get_interface_name(private_kernel_interface_t *this, host_t* ip)
{
	iterator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	char *name = NULL;
	
	DBG2(DBG_KNL, "getting interface name for %H", ip);
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
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
 * Tries to find an ip address of a local interface that is included in the
 * supplied traffic selector.
 */
static status_t get_address_by_ts(private_kernel_interface_t *this,
								  traffic_selector_t *ts, host_t **ip)
{
	iterator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	host_t *host;
	int family;
	bool found = FALSE;
	
	DBG2(DBG_KNL, "getting a local address in traffic selector %R", ts);
	
	/* if we have a family which includes localhost, we do not
	 * search for an IP, we use the default */
	family = ts->get_type(ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
	
	if (family == AF_INET)
	{
		host = host_create_from_string("127.0.0.1", 0);
	}
	else
	{
		host = host_create_from_string("::1", 0);
	}
	
	if (ts->includes(ts, host))
	{
		*ip = host_create_any(family);
		host->destroy(host);
		DBG2(DBG_KNL, "using host %H", *ip);
		return SUCCESS;
	}
	host->destroy(host);
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces,	&this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
		{
			if (ts->includes(ts, addr->ip))
			{
				found = TRUE;
				*ip = addr->ip->clone(addr->ip);
				break;
			}
		}
		addrs->destroy(addrs);
		if (found)
		{
			break;
		}
	}
	ifaces->destroy(ifaces);
	
	if (!found)
	{
		DBG1(DBG_KNL, "no local address found in traffic selector %R", ts);
		return FAILED;
	}
	DBG2(DBG_KNL, "using host %H", *ip);
	return SUCCESS;
}

/**
 * get the interface of a local address
 */
static int get_interface_index(private_kernel_interface_t *this, host_t* ip)
{
	iterator_t *ifaces, *addrs;
	iface_entry_t *iface;
	addr_entry_t *addr;
	int ifindex = 0;
	
	DBG2(DBG_KNL, "getting iface for %H", ip);
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces,	&this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
		{
			if (ip->ip_equals(ip, addr->ip))
			{
				ifindex = iface->ifindex;
				break;
			}
		}
		addrs->destroy(addrs);
		if (ifindex)
		{
			break;
		}
	}
	ifaces->destroy(ifaces);

	if (ifindex == 0)
	{
		DBG1(DBG_KNL, "unable to get interface for %H", ip);
	}
	return ifindex;
}

/**
 * get the refcount of a virtual ip
 */
static int get_vip_refcount(private_kernel_interface_t *this, host_t* ip)
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
 * Manages the creation and deletion of ip addresses on an interface.
 * By setting the appropriate nlmsg_type, the ip will be set or unset.
 */
static status_t manage_ipaddr(private_kernel_interface_t *this, int nlmsg_type,
							  int flags, int if_index, host_t *ip)
{
	unsigned char request[BUFFER_SIZE];
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
	
	add_attribute(hdr, IFA_LOCAL, chunk, sizeof(request));

	return netlink_send_ack(this, this->socket_rt, hdr);
}

/**
 * Manages source routes in the routing table.
 * By setting the appropriate nlmsg_type, the route added or r.
 */
static status_t manage_srcroute(private_kernel_interface_t *this, int nlmsg_type,
								int flags, route_entry_t *route)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct rtmsg *msg;
	chunk_t chunk;

	/* if route is 0.0.0.0/0, we can't install it, as it would
	 * overwrite the default route. Instead, we add two routes:
	 * 0.0.0.0/1 and 128.0.0.0/1 */
	if (this->routing_table == 0 && route->prefixlen == 0)
	{
		route_entry_t half;
		status_t status;
		
		half.dst_net = chunk_alloca(route->dst_net.len);
		memset(half.dst_net.ptr, 0, half.dst_net.len);
		half.src_ip = route->src_ip;
		half.gateway = route->gateway;
		half.if_index = route->if_index;
		half.prefixlen = 1;
		
		status = manage_srcroute(this, nlmsg_type, flags, &half);
		half.dst_net.ptr[0] |= 0x80;
		status = manage_srcroute(this, nlmsg_type, flags, &half);
		return status;
	}
	
	memset(&request, 0, sizeof(request));

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	hdr->nlmsg_type = nlmsg_type;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_family = route->src_ip->get_family(route->src_ip);
	msg->rtm_dst_len = route->prefixlen;
	msg->rtm_table = this->routing_table;
	msg->rtm_protocol = RTPROT_STATIC;
	msg->rtm_type = RTN_UNICAST;
	msg->rtm_scope = RT_SCOPE_UNIVERSE;
	
	add_attribute(hdr, RTA_DST, route->dst_net, sizeof(request));
	chunk = route->src_ip->get_address(route->src_ip);
	add_attribute(hdr, RTA_PREFSRC, chunk, sizeof(request));
	chunk = route->gateway->get_address(route->gateway);
	add_attribute(hdr, RTA_GATEWAY, chunk, sizeof(request));
	chunk.ptr = (char*)&route->if_index;
	chunk.len = sizeof(route->if_index);
	add_attribute(hdr, RTA_OIF, chunk, sizeof(request));

	return netlink_send_ack(this, this->socket_rt, hdr);
}

/**
 * create or delete an rule to use our routing table
 */
static status_t manage_rule(private_kernel_interface_t *this, int nlmsg_type,
							u_int32_t table, u_int32_t prio)
{
	unsigned char request[BUFFER_SIZE];
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
	add_attribute(hdr, RTA_PRIORITY, chunk, sizeof(request));

	return netlink_send_ack(this, this->socket_rt, hdr);
}

/**
 * check if an address (chunk) addr is in subnet (net with net_len net bits)
 */
static bool addr_in_subnet(chunk_t addr, chunk_t net, int net_len)
{
	int bit, byte;

	if (addr.len != net.len)
	{
		return FALSE;
	}
	/* scan through all bits, beginning in the front */
	for (byte = 0; byte < addr.len; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			/* check if bits are equal (or we reached the end of the net) */
			if (bit + byte * 8 > net_len)
			{
				return TRUE;
			}
			if (((1<<bit) & addr.ptr[byte]) != ((1<<bit) & net.ptr[byte]))
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}

/**
 * Get a route: If "nexthop", the nexthop is returned. source addr otherwise.
 */
static host_t *get_route(private_kernel_interface_t *this, host_t *dest,
						 bool nexthop)
{
	unsigned char request[BUFFER_SIZE];
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
	add_attribute(hdr, RTA_DST, chunk, sizeof(request));
			
	if (netlink_send(this, this->socket_rt, hdr, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "getting address to %H failed", dest);
		return NULL;
	}
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
					iterator_t *ifaces, *addrs;
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
						ifaces = this->ifaces->create_iterator_locked(
													this->ifaces, &this->mutex);
						while (ifaces->iterate(ifaces, (void**)&iface))
						{
							if (iface->ifindex == rta_oif)
							{
								addrs = iface->addrs->create_iterator(
															iface->addrs, TRUE);
								while (addrs->iterate(addrs, (void**)&addr))
								{
									chunk_t ip = addr->ip->get_address(addr->ip);
									if (msg->rtm_dst_len == 0
									||	addr_in_subnet(ip, rta_dst, msg->rtm_dst_len))
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
 * Implementation of kernel_interface_t.get_source_addr.
 */
static host_t* get_source_addr(private_kernel_interface_t *this, host_t *dest)
{
	return get_route(this, dest, FALSE);
}

/**
 * Implementation of kernel_interface_t.add_ip.
 */
static status_t add_ip(private_kernel_interface_t *this, 
						host_t *virtual_ip, host_t *iface_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	iterator_t *addrs, *ifaces;
	int ifindex;

	DBG2(DBG_KNL, "adding virtual IP %H", virtual_ip);
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		bool iface_found = FALSE;
	
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
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
					pthread_cond_wait(&this->cond, &this->mutex);
				}
				ifaces->destroy(ifaces);
				return SUCCESS;
			}
			ifaces->destroy(ifaces);
			DBG1(DBG_KNL, "adding virtual IP %H failed", virtual_ip);
			return FAILED;
		}
	}
	ifaces->destroy(ifaces);
	
	DBG1(DBG_KNL, "interface address %H not found, unable to install"
		 "virtual IP %H", iface_ip, virtual_ip);
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.del_ip.
 */
static status_t del_ip(private_kernel_interface_t *this, host_t *virtual_ip)
{
	iface_entry_t *iface;
	addr_entry_t *addr;
	iterator_t *addrs, *ifaces;
	status_t status;
	int ifindex;

	DBG2(DBG_KNL, "deleting virtual IP %H", virtual_ip);
	
	ifaces = this->ifaces->create_iterator_locked(this->ifaces, &this->mutex);
	while (ifaces->iterate(ifaces, (void**)&iface))
	{
		addrs = iface->addrs->create_iterator(iface->addrs, TRUE);
		while (addrs->iterate(addrs, (void**)&addr))
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
							pthread_cond_wait(&this->cond, &this->mutex);
						}
					}
					addrs->destroy(addrs);
					ifaces->destroy(ifaces);
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
				return SUCCESS;
			}
		}
		addrs->destroy(addrs);
	}
	ifaces->destroy(ifaces);
	
	DBG2(DBG_KNL, "virtual IP %H not cached, unable to delete", virtual_ip);
	return FAILED;
}

/**
 * Get an SPI for a specific protocol from the kernel.
 */
static status_t get_spi_internal(private_kernel_interface_t *this,
		host_t *src, host_t *dst, u_int8_t proto, u_int32_t min, u_int32_t max,
		u_int32_t reqid, u_int32_t *spi)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr, *out;
	struct xfrm_userspi_info *userspi;
	u_int32_t received_spi = 0;
	size_t len;
	
	memset(&request, 0, sizeof(request));
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_ALLOCSPI;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userspi_info));

	userspi = (struct xfrm_userspi_info*)NLMSG_DATA(hdr);
	host2xfrm(src, &userspi->info.saddr);
	host2xfrm(dst, &userspi->info.id.daddr);
	userspi->info.id.proto = proto;
	userspi->info.mode = TRUE; /* tunnel mode */
	userspi->info.reqid = reqid;
	userspi->info.family = src->get_family(src);
	userspi->min = min;
	userspi->max = max;
	
	if (netlink_send(this, this->socket_xfrm, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_NEWSA:
				{
					struct xfrm_usersa_info* usersa = NLMSG_DATA(hdr);
					received_spi = usersa->id.spi;
					break;
				}
				case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(hdr);
					
					DBG1(DBG_KNL, "allocating SPI failed: %s (%d)",
						 strerror(-err->error), -err->error);
					break;
				}
				default:
					hdr = NLMSG_NEXT(hdr, len);
					continue;
				case NLMSG_DONE:
					break;
			}
			break;
		}
		free(out);
	}
	
	if (received_spi == 0)
	{
		return FAILED;
	}
	
	*spi = received_spi;
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_kernel_interface_t *this, 
						host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	DBG2(DBG_KNL, "getting SPI for reqid %d", reqid);
	
	if (get_spi_internal(this, src, dst,
			(protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH,
			0xc0000000, 0xcFFFFFFF, reqid, spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get SPI for reqid %d", reqid);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "got SPI 0x%x for reqid %d", *spi, reqid);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.get_cpi.
 */
static status_t get_cpi(private_kernel_interface_t *this, 
						host_t *src, host_t *dst, 
						u_int32_t reqid, u_int16_t *cpi)
{
	u_int32_t received_spi = 0;
	DBG2(DBG_KNL, "getting CPI for reqid %d", reqid);
	
	if (get_spi_internal(this, src, dst,
			IPPROTO_COMP, 0x100, 0xEFFF, reqid, &received_spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get CPI for reqid %d", reqid);
		return FAILED;
	}
	
	*cpi = htons((u_int16_t)ntohl(received_spi));
	
	DBG2(DBG_KNL, "got CPI 0x%x for reqid %d", *cpi, reqid);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_kernel_interface_t *this,
					   host_t *src, host_t *dst, u_int32_t spi,
					   protocol_id_t protocol, u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   u_int16_t enc_alg, u_int16_t enc_size,
					   u_int16_t int_alg, u_int16_t int_size,
					   prf_plus_t *prf_plus, mode_t mode,
					   u_int16_t ipcomp, bool encap,
					   bool replace)
{
	unsigned char request[BUFFER_SIZE];
	char *alg_name;
	u_int16_t add_keymat = 32; /* additional 4 octets KEYMAT required for AES-GCM as of RFC4106 8.1. */
	struct nlmsghdr *hdr;
	struct xfrm_usersa_info *sa;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "adding SAD entry with SPI 0x%x and reqid %d", spi, reqid);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	
	sa = (struct xfrm_usersa_info*)NLMSG_DATA(hdr);
	host2xfrm(src, &sa->saddr);
	host2xfrm(dst, &sa->id.daddr);
	sa->id.spi = spi;
	sa->id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : (protocol == PROTO_AH) ? KERNEL_AH : protocol;
	sa->family = src->get_family(src);
	sa->mode = mode;
	sa->replay_window = (protocol == IPPROTO_COMP) ? 0 : 32;
	sa->reqid = reqid;
	/* we currently do not expire SAs by volume/packet count */
	sa->lft.soft_byte_limit = XFRM_INF;
	sa->lft.hard_byte_limit = XFRM_INF;
	sa->lft.soft_packet_limit = XFRM_INF;
	sa->lft.hard_packet_limit = XFRM_INF;
	/* we use lifetimes since added, not since used */
	sa->lft.soft_add_expires_seconds = expire_soft;
	sa->lft.hard_add_expires_seconds = expire_hard;
	sa->lft.soft_use_expires_seconds = 0;
	sa->lft.hard_use_expires_seconds = 0;
	
	struct rtattr *rthdr = XFRM_RTA(hdr, struct xfrm_usersa_info);
	
	switch (enc_alg)
	{
		case ENCR_UNDEFINED:
			/* no encryption */
			break;
		case ENCR_AES_CCM_ICV8:
		case ENCR_AES_CCM_ICV12:
		case ENCR_AES_CCM_ICV16:
			/* AES-CCM needs only 3 additional octets KEYMAT as of RFC 4309 7.1. */
			add_keymat = 24;
			/* fall-through */
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
		{
			u_int16_t icv_size = 0;
			rthdr->rta_type = XFRMA_ALG_AEAD;
			alg_name = lookup_algorithm(encryption_algs, enc_alg, &icv_size);
			if (alg_name == NULL)
			{
				DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
					 encryption_algorithm_names, enc_alg);
				return FAILED;
			}
			DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
				 encryption_algorithm_names, enc_alg, enc_size);
			
			/* additional KEYMAT required */
			enc_size += add_keymat;
			
			rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo_aead) + enc_size / 8);
			hdr->nlmsg_len += rthdr->rta_len;
			if (hdr->nlmsg_len > sizeof(request))
			{
				return FAILED;
			}
			
			struct xfrm_algo_aead* algo = (struct xfrm_algo_aead*)RTA_DATA(rthdr);
			algo->alg_key_len = enc_size;
			algo->alg_icv_len = icv_size;
			strcpy(algo->alg_name, alg_name);
			prf_plus->get_bytes(prf_plus, enc_size / 8, algo->alg_key);
			
			rthdr = XFRM_RTA_NEXT(rthdr);
			break;
		}
		default:
		{
			rthdr->rta_type = XFRMA_ALG_CRYPT;
			alg_name = lookup_algorithm(encryption_algs, enc_alg, &enc_size);
			if (alg_name == NULL)
			{
				DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
					 encryption_algorithm_names, enc_alg);
				return FAILED;
			}
			DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
				 encryption_algorithm_names, enc_alg, enc_size);
			
			rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + enc_size / 8);
			hdr->nlmsg_len += rthdr->rta_len;
			if (hdr->nlmsg_len > sizeof(request))
			{
				return FAILED;
			}
			
			struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
			algo->alg_key_len = enc_size;
			strcpy(algo->alg_name, alg_name);
			prf_plus->get_bytes(prf_plus, enc_size / 8, algo->alg_key);
			
			rthdr = XFRM_RTA_NEXT(rthdr);
			break;
		}
	}
		
	if (int_alg  != AUTH_UNDEFINED)
	{
		rthdr->rta_type = XFRMA_ALG_AUTH;
		alg_name = lookup_algorithm(integrity_algs, int_alg, &int_size);
		if (alg_name == NULL)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!", 
				 integrity_algorithm_names, int_alg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using integrity algorithm %N with key size %d",
			 integrity_algorithm_names, int_alg, int_size);
		
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + int_size / 8);
		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
		algo->alg_key_len = int_size;
		strcpy(algo->alg_name, alg_name);
		prf_plus->get_bytes(prf_plus, int_size / 8, algo->alg_key);
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	if (ipcomp != IPCOMP_NONE)
	{
		rthdr->rta_type = XFRMA_ALG_COMP;
		alg_name = lookup_algorithm(compression_algs, ipcomp, NULL);
		if (alg_name == NULL)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!", 
				 ipcomp_transform_names, ipcomp);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using compression algorithm %N",
			 ipcomp_transform_names, ipcomp);
		
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo));
		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
		algo->alg_key_len = 0;
		strcpy(algo->alg_name, alg_name);
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	if (encap)
	{
		rthdr->rta_type = XFRMA_ENCAP;
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_encap_tmpl));

		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}

		struct xfrm_encap_tmpl* tmpl = (struct xfrm_encap_tmpl*)RTA_DATA(rthdr);
		tmpl->encap_type = UDP_ENCAP_ESPINUDP;
		tmpl->encap_sport = htons(src->get_port(src));
		tmpl->encap_dport = htons(dst->get_port(dst));
		memset(&tmpl->encap_oa, 0, sizeof (xfrm_address_t));
		/* encap_oa could probably be derived from the 
		 * traffic selectors [rfc4306, p39]. In the netlink kernel implementation 
		 * pluto does the same as we do here but it uses encap_oa in the 
		 * pfkey implementation. BUT as /usr/src/linux/net/key/af_key.c indicates 
		 * the kernel ignores it anyway
		 *   -> does that mean that NAT-T encap doesn't work in transport mode?
		 * No. The reason the kernel ignores NAT-OA is that it recomputes 
		 * (or, rather, just ignores) the checksum. If packets pass
		 * the IPsec checks it marks them "checksum ok" so OA isn't needed. */
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	if (netlink_send_ack(this, this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add SAD entry with SPI 0x%x", spi);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(private_kernel_interface_t *this,
						  u_int32_t spi, protocol_id_t protocol,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst, bool encap)
{
	unsigned char request[BUFFER_SIZE], *pos;
	struct nlmsghdr *hdr, *out = NULL;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *out_sa = NULL, *sa;
	size_t len;
	struct rtattr *rta;
	size_t rtasize;
	struct xfrm_encap_tmpl* tmpl = NULL;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying SAD entry with SPI 0x%x for update", spi);

	/* query the exisiting SA first */
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : (protocol == PROTO_AH) ? KERNEL_AH : protocol;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send(this, this->socket_xfrm, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_NEWSA:
				{
					out_sa = NLMSG_DATA(hdr);
					break;
				}
				case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(hdr);
					DBG1(DBG_KNL, "querying SAD entry failed: %s (%d)",
						 strerror(-err->error), -err->error);
					break;
				}
				default:
					hdr = NLMSG_NEXT(hdr, len);
					continue;
				case NLMSG_DONE:
					break;
			}
			break;
		}
	}
	if (out_sa == NULL ||
		this->public.del_sa(&this->public, dst, spi, protocol) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI 0x%x", spi);
		free(out);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "updating SAD entry with SPI 0x%x from %#H..%#H to %#H..%#H",
		 spi, src, dst, new_src, new_dst);
	
	/* copy over the SA from out to request */
	hdr = (struct nlmsghdr*)request;
	memcpy(hdr, out, min(out->nlmsg_len, sizeof(request)));
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;	
	hdr->nlmsg_type = XFRM_MSG_NEWSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	sa = NLMSG_DATA(hdr);
	sa->family = new_dst->get_family(new_dst);
	
	if (!src->ip_equals(src, new_src))
	{
		host2xfrm(new_src, &sa->saddr);
	}
	if (!dst->ip_equals(dst, new_dst))
	{
		host2xfrm(new_dst, &sa->id.daddr);
	}
	
	rta = XFRM_RTA(out, struct xfrm_usersa_info);
	rtasize = XFRM_PAYLOAD(out, struct xfrm_usersa_info);
	pos = (u_char*)XFRM_RTA(hdr, struct xfrm_usersa_info);
	while(RTA_OK(rta, rtasize))
	{
		/* copy all attributes, but not XFRMA_ENCAP if we are disabling it */
		if (rta->rta_type != XFRMA_ENCAP || encap)
		{
			if (rta->rta_type == XFRMA_ENCAP)
			{	/* update encap tmpl */
				tmpl = (struct xfrm_encap_tmpl*)RTA_DATA(rta);
				tmpl->encap_sport = ntohs(new_src->get_port(new_src));
				tmpl->encap_dport = ntohs(new_dst->get_port(new_dst));
			}	
			memcpy(pos, rta, rta->rta_len);
			pos += rta->rta_len;
			hdr->nlmsg_len += rta->rta_len;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	if (tmpl == NULL && encap)
	{	/* add tmpl if we are enabling it */
		rta = (struct rtattr*)pos;
		rta->rta_type = XFRMA_ENCAP;
		rta->rta_len = RTA_LENGTH(sizeof(struct xfrm_encap_tmpl));
		hdr->nlmsg_len += rta->rta_len;
		tmpl = (struct xfrm_encap_tmpl*)RTA_DATA(rta);
		tmpl->encap_type = UDP_ENCAP_ESPINUDP;
		tmpl->encap_sport = ntohs(new_src->get_port(new_src));
		tmpl->encap_dport = ntohs(new_dst->get_port(new_dst));
		memset(&tmpl->encap_oa, 0, sizeof (xfrm_address_t));
	}
	
	if (netlink_send_ack(this, this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI 0x%x", spi);
		free(out);
		return FAILED;
	}
	free(out);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.query_sa.
 */
static status_t query_sa(private_kernel_interface_t *this, host_t *dst,
						 u_int32_t spi, protocol_id_t protocol,
						 u_int32_t *use_time)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *out = NULL, *hdr;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *sa = NULL;
	size_t len;
	
	DBG2(DBG_KNL, "querying SAD entry with SPI 0x%x", spi);
	memset(&request, 0, sizeof(request));
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : (protocol == PROTO_AH) ? KERNEL_AH : protocol;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send(this, this->socket_xfrm, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_NEWSA:
				{
					sa = NLMSG_DATA(hdr);
					break;
				}
				case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(hdr);
					DBG1(DBG_KNL, "querying SAD entry failed: %s (%d)",
						 strerror(-err->error), -err->error);
					break;
				}
				default:
					hdr = NLMSG_NEXT(hdr, len);
					continue;
				case NLMSG_DONE:
					break;
			}
			break;
		}
	}
	
	if (sa == NULL)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI 0x%x", spi);
		free(out);
		return FAILED;
	}
	
	*use_time = sa->curlft.use_time;
	free (out);
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.del_sa.
 */
static status_t del_sa(private_kernel_interface_t *this, host_t *dst,
					   u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "deleting SAD entry with SPI 0x%x", spi);
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
	
	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : (protocol == PROTO_AH) ? KERNEL_AH : protocol;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send_ack(this, this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete SAD entry with SPI 0x%x", spi);
		return FAILED;
	}
	DBG2(DBG_KNL, "deleted SAD entry with SPI 0x%x", spi);
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_policy.
 */
static status_t add_policy(private_kernel_interface_t *this, 
						   host_t *src, host_t *dst,
						   traffic_selector_t *src_ts,
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, protocol_id_t protocol,
						   u_int32_t reqid, bool high_prio, mode_t mode,
						   u_int16_t ipcomp)
{
	iterator_t *iterator;
	policy_entry_t *current, *policy;
	bool found = FALSE;
	unsigned char request[BUFFER_SIZE];
	struct xfrm_userpolicy_info *policy_info;
	struct nlmsghdr *hdr;
	
	/* create a policy */
	policy = malloc_thing(policy_entry_t);
	memset(policy, 0, sizeof(policy_entry_t));
	policy->sel = ts2selector(src_ts, dst_ts);
	policy->direction = direction;
	
	/* find the policy, which matches EXACTLY */
	pthread_mutex_lock(&this->mutex);
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (memcmp(&current->sel, &policy->sel, sizeof(struct xfrm_selector)) == 0 &&
			policy->direction == current->direction)
		{
			/* use existing policy */
			current->refcount++;
			DBG2(DBG_KNL, "policy %R===%R already exists, increasing "
				 "refcount", src_ts, dst_ts);
			free(policy);
			policy = current;
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!found)
	{	/* apply the new one, if we have no such policy */
		this->policies->insert_last(this->policies, policy);
		policy->refcount = 1;
	}
	
	DBG2(DBG_KNL, "adding policy %R===%R", src_ts, dst_ts);
	
	memset(&request, 0, sizeof(request));
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_UPDPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));

	policy_info = (struct xfrm_userpolicy_info*)NLMSG_DATA(hdr);
	policy_info->sel = policy->sel;
	policy_info->dir = policy->direction;
	/* calculate priority based on source selector size, small size = high prio */
	policy_info->priority = high_prio ? PRIO_HIGH : PRIO_LOW;
	policy_info->priority -= policy->sel.prefixlen_s * 10;
	policy_info->priority -= policy->sel.proto ? 2 : 0;
	policy_info->priority -= policy->sel.sport_mask ? 1 : 0;
	policy_info->action = XFRM_POLICY_ALLOW;
	policy_info->share = XFRM_SHARE_ANY;
	pthread_mutex_unlock(&this->mutex);
	
	/* policies don't expire */
	policy_info->lft.soft_byte_limit = XFRM_INF;
	policy_info->lft.soft_packet_limit = XFRM_INF;
	policy_info->lft.hard_byte_limit = XFRM_INF;
	policy_info->lft.hard_packet_limit = XFRM_INF;
	policy_info->lft.soft_add_expires_seconds = 0;
	policy_info->lft.hard_add_expires_seconds = 0;
	policy_info->lft.soft_use_expires_seconds = 0;
	policy_info->lft.hard_use_expires_seconds = 0;
	
	struct rtattr *rthdr = XFRM_RTA(hdr, struct xfrm_userpolicy_info);
	rthdr->rta_type = XFRMA_TMPL;
	rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_user_tmpl));
	
	hdr->nlmsg_len += rthdr->rta_len;
	if (hdr->nlmsg_len > sizeof(request))
	{
		return FAILED;
	}
	
	struct xfrm_user_tmpl *tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rthdr);
	
	if (ipcomp != IPCOMP_NONE)
	{
		tmpl->reqid = reqid;
		tmpl->id.proto = IPPROTO_COMP;
		tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
		tmpl->mode = mode;
		tmpl->optional = direction != POLICY_OUT;
		tmpl->family = src->get_family(src);
		
		host2xfrm(src, &tmpl->saddr);
		host2xfrm(dst, &tmpl->id.daddr);
		
		/* add an additional xfrm_user_tmpl */
		rthdr->rta_len += RTA_LENGTH(sizeof(struct xfrm_user_tmpl));
		hdr->nlmsg_len += RTA_LENGTH(sizeof(struct xfrm_user_tmpl));
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		tmpl++;
	}
	
	tmpl->reqid = reqid;
	tmpl->id.proto = (protocol == PROTO_AH) ? KERNEL_AH : KERNEL_ESP;
	tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
	tmpl->mode = mode;
	tmpl->family = src->get_family(src);
	
	host2xfrm(src, &tmpl->saddr);
	host2xfrm(dst, &tmpl->id.daddr);
	
	if (netlink_send_ack(this, this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add policy %R===%R", src_ts, dst_ts);
		return FAILED;
	}
	
	/* install a route, if:
	 * - we are NOT updating a policy
	 * - this is a forward policy (to just get one for each child)
	 * - we are in tunnel mode
	 * - we are not using IPv6 (does not work correctly yet!)
	 * - routing is not disabled via strongswan.conf
	 */
	if (policy->route == NULL && direction == POLICY_FWD &&
		mode != MODE_TRANSPORT && src->get_family(src) != AF_INET6 &&
		this->install_routes)
	{
		policy->route = malloc_thing(route_entry_t);
		if (get_address_by_ts(this, dst_ts, &policy->route->src_ip) == SUCCESS)
		{
			/* get the nexthop to src (src as we are in POLICY_FWD).*/
			policy->route->gateway = get_route(this, src, TRUE);
			policy->route->if_index = get_interface_index(this, dst);
			policy->route->dst_net = chunk_alloc(policy->sel.family == AF_INET ? 4 : 16);
			memcpy(policy->route->dst_net.ptr, &policy->sel.saddr, policy->route->dst_net.len);
			policy->route->prefixlen = policy->sel.prefixlen_s;
			
			if (manage_srcroute(this, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
								policy->route) != SUCCESS)
			{
				DBG1(DBG_KNL, "unable to install source route for %H",
					 policy->route->src_ip);
				route_entry_destroy(policy->route);
				policy->route = NULL;
			}
		}
		else
		{
			free(policy->route);
			policy->route = NULL;
		}
	}

	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.query_policy.
 */
static status_t query_policy(private_kernel_interface_t *this,
							 traffic_selector_t *src_ts, 
							 traffic_selector_t *dst_ts,
							 policy_dir_t direction, u_int32_t *use_time)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *out = NULL, *hdr;
	struct xfrm_userpolicy_id *policy_id;
	struct xfrm_userpolicy_info *policy = NULL;
	size_t len;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying policy %R===%R", src_ts, dst_ts);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel = ts2selector(src_ts, dst_ts);
	policy_id->dir = direction;
	
	if (netlink_send(this, this->socket_xfrm, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_NEWPOLICY:
				{
					policy = (struct xfrm_userpolicy_info*)NLMSG_DATA(hdr);
					break;
				}
				case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(hdr);
					DBG1(DBG_KNL, "querying policy failed: %s (%d)",
						 strerror(-err->error), -err->error);
					break;
				}
				default:
					hdr = NLMSG_NEXT(hdr, len);
					continue;
				case NLMSG_DONE:
					break;
			}
			break;
		}
	}
	
	if (policy == NULL)
	{
		DBG2(DBG_KNL, "unable to query policy %R===%R", src_ts, dst_ts);
		free(out);
		return FAILED;
	}
	*use_time = (time_t)policy->curlft.use_time;
	
	free(out);
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.del_policy.
 */
static status_t del_policy(private_kernel_interface_t *this,
						   traffic_selector_t *src_ts, 
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction)
{
	policy_entry_t *current, policy, *to_delete = NULL;
	route_entry_t *route;
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_userpolicy_id *policy_id;
	iterator_t *iterator;
	
	DBG2(DBG_KNL, "deleting policy %R===%R", src_ts, dst_ts);
	
	/* create a policy */
	memset(&policy, 0, sizeof(policy_entry_t));
	policy.sel = ts2selector(src_ts, dst_ts);
	policy.direction = direction;
	
	/* find the policy */
	iterator = this->policies->create_iterator_locked(this->policies, &this->mutex);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (memcmp(&current->sel, &policy.sel, sizeof(struct xfrm_selector)) == 0 &&
			policy.direction == current->direction)
		{
			to_delete = current;
			if (--to_delete->refcount > 0)
			{
				/* is used by more SAs, keep in kernel */
				DBG2(DBG_KNL, "policy still used by another CHILD_SA, not removed");
				iterator->destroy(iterator);
				return SUCCESS;
			}
			/* remove if last reference */
			iterator->remove(iterator);
			break;
		}
	}
	iterator->destroy(iterator);
	if (!to_delete)
	{
		DBG1(DBG_KNL, "deleting policy %R===%R failed, not found", src_ts, dst_ts);
		return NOT_FOUND;
	}
	
	memset(&request, 0, sizeof(request));
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel = to_delete->sel;
	policy_id->dir = direction;
	
	route = to_delete->route;
	free(to_delete);
	
	if (netlink_send_ack(this, this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete policy %R===%R", src_ts, dst_ts);
		return FAILED;
	}

	if (route)
	{
		if (manage_srcroute(this, RTM_DELROUTE, 0, route) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route installed with "
				 "policy %R===%R", src_ts, dst_ts);
		}		
		route_entry_destroy(route);
	}
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_kernel_interface_t *this)
{
	if (this->routing_table)
	{
		manage_rule(this, RTM_DELRULE, this->routing_table,
					this->routing_table_prio);
	}

	this->job->cancel(this->job);
	close(this->socket_xfrm_events);
	close(this->socket_xfrm);
	close(this->socket_rt_events);
	close(this->socket_rt);
	this->policies->destroy(this->policies);
	this->ifaces->destroy_function(this->ifaces, (void*)iface_entry_destroy);
	free(this);
}

/*
 * Described in header.
 */
kernel_interface_t *kernel_interface_create()
{
	private_kernel_interface_t *this = malloc_thing(private_kernel_interface_t);
	struct sockaddr_nl addr;
	
	/* public functions */
	this->public.get_spi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.get_cpi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,u_int32_t,u_int16_t*))get_cpi;
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,u_int16_t,u_int16_t,u_int16_t,u_int16_t,prf_plus_t*,mode_t,u_int16_t,bool,bool))add_sa;
	this->public.update_sa = (status_t(*)(kernel_interface_t*,u_int32_t,protocol_id_t,host_t*,host_t*,host_t*,host_t*,bool))update_sa;
	this->public.query_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t*))query_sa;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,protocol_id_t,u_int32_t,bool,mode_t,u_int16_t))add_policy;
	this->public.query_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.del_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t))del_policy;
	this->public.get_interface = (char*(*)(kernel_interface_t*,host_t*))get_interface_name;
	this->public.create_address_iterator = (iterator_t*(*)(kernel_interface_t*))create_address_iterator;
	this->public.get_source_addr = (host_t*(*)(kernel_interface_t*, host_t *dest))get_source_addr;
	this->public.add_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) add_ip;
	this->public.del_ip = (status_t(*)(kernel_interface_t*,host_t*)) del_ip;
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->policies = linked_list_create();
	this->ifaces = linked_list_create();
	this->hiter = NULL;
	this->seq = 200;
	pthread_mutex_init(&this->mutex, NULL);
	pthread_mutex_init(&this->nl_mutex, NULL);
	pthread_cond_init(&this->cond, NULL);
	timerclear(&this->last_roam);
	this->install_routes = lib->settings->get_bool(lib->settings,
					"charon.install_routes", TRUE);
	this->routing_table = lib->settings->get_int(lib->settings,
					"charon.routing_table", IPSEC_ROUTING_TABLE);
	this->routing_table_prio = lib->settings->get_int(lib->settings,
					"charon.routing_table_prio", IPSEC_ROUTING_TABLE_PRIO);
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	
	/* create and bind RT socket */
	this->socket_rt = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->socket_rt <= 0)
	{
		charon->kill(charon, "unable to create RT netlink socket");
	}
	addr.nl_groups = 0;
	if (bind(this->socket_rt, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind RT netlink socket");
	}
	
	/* create and bind RT socket for events (address/interface/route changes) */
	this->socket_rt_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->socket_rt_events <= 0)
	{
		charon->kill(charon, "unable to create RT event socket");
	}
	addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | 
					 RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_LINK;
	if (bind(this->socket_rt_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind RT event socket");
	}
	
	/* create and bind XFRM socket */ 
	this->socket_xfrm = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm <= 0)
	{
		charon->kill(charon, "unable to create XFRM netlink socket");
	}
	addr.nl_groups = 0;
	if (bind(this->socket_xfrm, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM netlink socket");
	}
	
	/* create and bind XFRM socket for ACQUIRE & EXPIRE */
	this->socket_xfrm_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm_events <= 0)
	{
		charon->kill(charon, "unable to create XFRM event socket");
	}
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(this->socket_xfrm_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM event socket");
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

