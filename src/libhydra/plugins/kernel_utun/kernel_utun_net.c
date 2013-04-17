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

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <errno.h>
#include <unistd.h>

#include "kernel_utun_net.h"
#include "kernel_utun_ipsec.h"

#include <hydra.h>
#include <utils/debug.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <processing/jobs/callback_job.h>

typedef struct private_kernel_utun_net_t private_kernel_utun_net_t;

/**
 * Private variables and functions of kernel_utun_net class.
 */
struct private_kernel_utun_net_t {

	/**
	 * Public part of the kernel_utun_net_t object.
	 */
	kernel_utun_net_t public;

	/**
	 * PF_ROUTE socket
	 */
	int pfr;

	/**
	 * sequence numbers for PF_ROUTE messages
	 */
	int seq;

	/**
	 * process id we use for all messages
	 */
	pid_t pid;

	/**
	 * To sequentially do queries on PF_ROUTE
	 */
	mutex_t *mutex;

	/**
	 * Signalled when response from kernel received
	 */
	condvar_t *condvar;

	/**
	 * Sequence number a query is waiting for
	 */
	int waiting_seq;

	/**
	 * Allocated reply message from kernel
	 */
	struct rt_msghdr *reply;
};

typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** ifaddrs to free on cleanup */
	struct ifaddrs *orig;
	/** currently enumerating ifaddr */
	struct ifaddrs *current;
	/** current host */
	host_t *host;
	/** which address types to filter */
	kernel_address_type_t which;
} addr_enumerator_t;

METHOD(enumerator_t, addr_enumerate, bool,
	addr_enumerator_t *this, host_t **addr)
{
	while (TRUE)
	{
		DESTROY_IF(this->host);
		this->host = NULL;
		if (this->current)
		{
			this->current = this->current->ifa_next;
		}
		else
		{
			this->current = this->orig;
		}
		if (!this->current)
		{
			return FALSE;
		}
		if (!this->current->ifa_addr)
		{
			return FALSE;
		}
		if (!(this->which & ADDR_TYPE_LOOPBACK) &&
			(this->current->ifa_flags & IFF_LOOPBACK))
		{	/* ignore loopback devices */
			continue;
		}
		if (!(this->which & ADDR_TYPE_DOWN) &&
			!(this->current->ifa_flags & IFF_UP))
		{	/* skip interfaces not up */
			continue;
		}
		if (!(this->which & ADDR_TYPE_VIRTUAL) &&
			strneq(this->current->ifa_name, "utun", strlen("utun")))
		{	/* skip virtual IPs on utun devices */
			continue;
		}
		this->host = host_create_from_sockaddr(this->current->ifa_addr);
		if (!this->host)
		{
			continue;
		}
		*addr = this->host;
		return TRUE;
	}
}

METHOD(enumerator_t, addr_destroy, void,
	addr_enumerator_t *this)
{
	if (this->orig)
	{
		freeifaddrs(this->orig);
	}
	DESTROY_IF(this->host);
	free(this);
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_utun_net_t *this, kernel_address_type_t which)
{
	addr_enumerator_t *enumerator;
	struct ifaddrs *ifa;

	if (getifaddrs(&ifa) != 0)
	{
		return enumerator_create_empty();
	}
	INIT(enumerator,
		.public = {
			.enumerate = (void*)_addr_enumerate,
			.destroy = _addr_destroy,
		},
		.orig = ifa,
		.which = which,
	);
	return &enumerator->public;
}

METHOD(kernel_net_t, get_interface_name, bool,
	private_kernel_utun_net_t *this, host_t* ip, char **name)
{
	struct ifaddrs *ifa, *current;
	host_t *host;
	bool found = FALSE;

	if (getifaddrs(&ifa) != 0)
	{
		return FALSE;
	}
	for (current = ifa; current; current = current->ifa_next)
	{
		if (current->ifa_addr)
		{
			host = host_create_from_sockaddr(current->ifa_addr);
			if (host)
			{
				if (ip->ip_equals(ip, host))
				{
					*name = strdup(current->ifa_name);
					found = TRUE;
				}
				host->destroy(host);
			}
		}
		if (found)
		{
			break;
		}
	}
	freeifaddrs(ifa);

	return found;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_utun_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_utun_net_t *this, host_t *virtual_ip, int prefix,
	char *iface_name)
{
	kernel_utun_ipsec_t *ipsec;

	ipsec = kernel_utun_ipsec_get();
	if (ipsec)
	{
		return ipsec->add_ip(ipsec, virtual_ip, prefix);
	}
	return FAILED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_utun_net_t *this, host_t *virtual_ip, int prefix,
	bool wait)
{
	kernel_utun_ipsec_t *ipsec;

	ipsec = kernel_utun_ipsec_get();
	if (ipsec)
	{
		return ipsec->del_ip(ipsec, virtual_ip, prefix);
	}
	return FAILED;
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
		hdr->rtm_msglen += len;
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
		hdr->rtm_msglen += sdl.sdl_len;
		hdr->rtm_addrs |= type;
	}
}

/**
 * Add or remove a route
 */
static status_t manage_route(private_kernel_utun_net_t *this, int op,
							 chunk_t dst_net, u_int8_t prefixlen,
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
			.rtm_seq = ++this->seq,
		},
	};
	host_t *dst;
	int i;

	dst = host_create_from_chunk(AF_UNSPEC, dst_net, 0);
	if (!dst)
	{
		return FAILED;
	}

	if ((dst->get_family(dst) == AF_INET && prefixlen == 32) ||
		(dst->get_family(dst) == AF_INET6 && prefixlen == 128))
	{
		msg.hdr.rtm_flags |= RTF_HOST | RTF_GATEWAY;
	}

	msg.hdr.rtm_msglen = sizeof(struct rt_msghdr);
	for (i = 0; i < RTAX_MAX; i++)
	{
		switch (i)
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
			case RTAX_GATEWAY:
				/* interface name seems to replace gateway on OS X */
				if (if_name)
				{
					add_rt_ifname(&msg.hdr, RTA_GATEWAY, if_name);
				}
				else if (gateway)
				{
					add_rt_addr(&msg.hdr, RTA_GATEWAY, gateway);
				}
				break;
			default:
				break;
		}
	}
	dst->destroy(dst);

	if (send(this->pfr, &msg, msg.hdr.rtm_msglen, 0) != msg.hdr.rtm_msglen)
	{
		DBG1(DBG_KNL, "%s PF_ROUTE route failed: %s",
			 op == RTM_ADD ? "adding" : "deleting", strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_utun_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_route(this, RTM_ADD, dst_net, prefixlen, gateway, if_name);
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_utun_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return manage_route(this, RTM_DELETE, dst_net, prefixlen, gateway, if_name);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_utun_net_t *this, host_t *dest, host_t *src)
{
	struct {
		struct rt_msghdr hdr;
		char buf[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} msg = {
		.hdr = {
			.rtm_version = RTM_VERSION,
			.rtm_type = RTM_GET,
			.rtm_pid = this->pid,
			.rtm_seq = ++this->seq,
		},
	};
	host_t *hop = NULL;
	struct sockaddr *addr;
	int i, remaining;

	msg.hdr.rtm_msglen = sizeof(struct rt_msghdr);
	for (i = 0; i < RTAX_MAX; i++)
	{
		switch (i)
		{
			case RTAX_DST:
				add_rt_addr(&msg.hdr, RTA_DST, dest);
				break;
			case RTAX_IFA:
				add_rt_addr(&msg.hdr, RTA_IFA, src);
				break;
			default:
				break;
		}
	}
	this->mutex->lock(this->mutex);

	this->waiting_seq = msg.hdr.rtm_seq;
	if (send(this->pfr, &msg, msg.hdr.rtm_msglen, 0) == msg.hdr.rtm_msglen)
	{
		while (TRUE)
		{
			if (this->condvar->timed_wait(this->condvar, this->mutex, 1000))
			{	/* timed out? */
				break;
			}
			if (msg.hdr.rtm_seq != this->reply->rtm_seq)
			{
				continue;
			}
			remaining = this->reply->rtm_msglen - sizeof(*this->reply);
			addr = (void*)this->reply + sizeof(*this->reply);
			for (i = 0; i < RTAX_MAX; i++)
			{
				if ((1 << i & this->reply->rtm_addrs) &&
					remaining >= sizeof(addr->sa_len) &&
					remaining >= addr->sa_len &&
					remaining >= sizeof(struct sockaddr))
				{
					switch (i)
					{
						case RTAX_GATEWAY:
							hop = host_create_from_sockaddr(addr);
							break;
						default:
							break;
					}
					addr = (void*)addr + addr->sa_len;
					remaining -= addr->sa_len;
				}
			}
			break;
		}
	}
	else
	{
		DBG1(DBG_KNL, "PF_ROUTE lookup failed: %s", strerror(errno));
	}
	this->mutex->unlock(this->mutex);

	return hop;
}

/**
 * Receive PF_ROUTE messages from kernel
 */
static job_requeue_t receive_events(private_kernel_utun_net_t *this)
{
	struct {
		struct rt_msghdr hdr;
		char buf[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} msg;
	int len;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	len = recv(this->pfr, &msg, sizeof(msg), 0);
	thread_cancelability(oldstate);

	if (len < 0)
	{
		switch (errno)
		{
			case EINTR:
			case EAGAIN:
				return JOB_REQUEUE_DIRECT;
			default:
				DBG1(DBG_KNL, "reading from PF_ROUTE socket failed: %s",
					 strerror(errno));
				sleep(1);
				return JOB_REQUEUE_FAIR;
		}
	}
	if (len < sizeof(msg.hdr) || len < msg.hdr.rtm_msglen ||
		msg.hdr.rtm_version != RTM_VERSION)
	{
		DBG2(DBG_KNL, "received invalid PF_ROUTE message");
		return JOB_REQUEUE_DIRECT;
	}

	this->mutex->lock(this->mutex);
	if (msg.hdr.rtm_pid == this->pid && msg.hdr.rtm_seq == this->waiting_seq)
	{
		/* seems like the message someone is waiting for, deliver */
		this->reply = realloc(this->reply, msg.hdr.rtm_msglen);
		memcpy(this->reply, &msg, msg.hdr.rtm_msglen);
		this->condvar->signal(this->condvar);
	}
	this->mutex->unlock(this->mutex);
	return JOB_REQUEUE_DIRECT;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_utun_net_t *this)
{
	if (this->pfr != -1)
	{
		close(this->pfr);
	}
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	free(this->reply);
	free(this);
}

/*
 * Described in header.
 */
kernel_utun_net_t *kernel_utun_net_create()
{
	private_kernel_utun_net_t *this;

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
		.pid = getpid(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
	);

	this->pfr = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (this->pfr < 0)
	{
		DBG1(DBG_KNL, "creating PF_ROUTE socket failed: %s", strerror(errno));
		destroy(this);
		return NULL;
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio(
				(callback_job_cb_t)receive_events, this, NULL,
				(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

	return &this->public;
}
