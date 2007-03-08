/**
 * @file kernel_interface.c
 *
 * @brief Implementation of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2006-2007 Tobias Brunner
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
 */

#include <sys/types.h>
#include <sys/socket.h>
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
#include <ifaddrs.h>

#include "kernel_interface.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <queues/jobs/delete_child_sa_job.h>
#include <queues/jobs/rekey_child_sa_job.h>
#include <queues/jobs/acquire_job.h>

/** kernel level protocol identifiers */
#define KERNEL_ESP 50
#define KERNEL_AH 51

/** default priority of installed policies */
#define PRIO_LOW 3000
#define PRIO_HIGH 2000

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
kernel_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64, 	"***", 			0}, */
	{ENCR_DES, 			"des", 			64},
	{ENCR_3DES, 		"des3_ede",		192},
/*	{ENCR_RC5, 			"***", 			0}, */
/*	{ENCR_IDEA, 		"***",			0}, */
	{ENCR_CAST, 		"cast128",		0},
	{ENCR_BLOWFISH, 	"blowfish",		0},
/*	{ENCR_3IDEA, 		"***",			0}, */
/*	{ENCR_DES_IV32, 	"***",			0}, */
	{ENCR_NULL, 		"cipher_null",	0},
	{ENCR_AES_CBC, 		"aes",			0},
/*	{ENCR_AES_CTR, 		"***",			0}, */
	{END_OF_LIST, 		NULL,			0},
};

/**
 * Algorithms for integrity protection
 */
kernel_algorithm_t integrity_algs[] = {
	{AUTH_HMAC_MD5_96, 			"md5",			128},
	{AUTH_HMAC_SHA1_96,			"sha1",			160},
	{AUTH_HMAC_SHA2_256_128,	"sha256",		256},
	{AUTH_HMAC_SHA2_384_192,	"sha384",		384},
	{AUTH_HMAC_SHA2_512_256,	"sha512",		512},
/*	{AUTH_DES_MAC,				"***",			0}, */
/*	{AUTH_KPDK_MD5,				"***",			0}, */
/*	{AUTH_AES_XCBC_96,			"***",			0}, */
	{END_OF_LIST, 				NULL,			0},
};

/**
 * Look up a kernel algorithm name and its key size
 */
char* lookup_algorithm(kernel_algorithm_t *kernel_algo, 
					   algorithm_t *ikev2_algo, u_int *key_size)
{
	while (kernel_algo->ikev2_id != END_OF_LIST)
	{
		if (ikev2_algo->algorithm == kernel_algo->ikev2_id)
		{
			/* match, evaluate key length */
			if (ikev2_algo->key_size)
			{	/* variable length */
				*key_size = ikev2_algo->key_size;
			}
			else
			{	/* fixed length */
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

typedef struct vip_entry_t vip_entry_t;

/**
 * Installed virtual ip
 */
struct vip_entry_t {
	/** Index of the interface the ip is bound to */
	u_int8_t if_index;
	
	/** The ip address */
	host_t *ip;
	
	/** Number of times this IP is used */
	u_int refcount;
};

/**
 * destroy a vip_entry_t object
 */
static void vip_entry_destroy(vip_entry_t *this)
{
	this->ip->destroy(this->ip);
	free(this);
}

typedef struct address_entry_t address_entry_t;

/**
 * an address found on the system, containg address and interface info 
 */
struct address_entry_t {

	/** address of this entry */
	host_t *host;
	
	/** interface index */
	int ifindex;
	
	/** name of the index */
	char ifname[IFNAMSIZ];
};

/**
 * destroy an address entry
 */
static void address_entry_destroy(address_entry_t *this)
{
	this->host->destroy(this->host);
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
	 * List of installed policies (kernel_entry_t)
	 */
	linked_list_t *policies;
	
	/**
	 * Mutex locks access to policies
	 */
	pthread_mutex_t policies_mutex;
	
	/**
	 * List of installed virtual IPs. (vip_entry_t)
	 */
	linked_list_t *vips;
	
	/**
	 * Mutex to lock access to vips.
	 */
	pthread_mutex_t vips_mutex;
	
	/**
	 * netlink xfrm socket to receive acquire and expire events
	 */
	int socket_xfrm_events;
	
	/**
	 * Netlink xfrm socket (IPsec)
	 */
	int socket_xfrm;
	
	/**
	 * Netlink rt socket (routing)
	 */
	int socket_rt;
	
	/**
	 * Thread receiving events from kernel
	 */
	pthread_t event_thread;
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
 * Receives events from kernel
 */
static void receive_events(private_kernel_interface_t *this)
{
	while(TRUE) 
	{
		unsigned char response[512];
		struct nlmsghdr *hdr;
		struct sockaddr_nl addr;
		socklen_t addr_len = sizeof(addr);
		int len;
		
		hdr = (struct nlmsghdr*)response;
		len = recvfrom(this->socket_xfrm_events, response, sizeof(response),
					   0, (struct sockaddr*)&addr, &addr_len);
		if (len < 0)
		{
			if (errno == EINTR)
			{
				/* interrupted, try again */
				continue;
			}
			charon->kill(charon, "unable to receive netlink events");
		}
		
		if (!NLMSG_OK(hdr, len))
		{
			/* bad netlink message */
			continue;
		}

		if (addr.nl_pid != 0)
		{
			/* not from kernel. not interested, try another one */
			continue;
		}
		
		/* we handle ACQUIRE and EXPIRE messages directly */
		if (hdr->nlmsg_type == XFRM_MSG_ACQUIRE)
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
			}
			else
			{
				DBG2(DBG_KNL, "received a XFRM_MSG_ACQUIRE");
				DBG1(DBG_KNL, "creating acquire job for CHILD_SA with reqid %d",
					 reqid);
				job = (job_t*)acquire_job_create(reqid);
				charon->job_queue->add(charon->job_queue, job);
			}
		}
		else if (hdr->nlmsg_type == XFRM_MSG_EXPIRE)
		{
			job_t *job;
			protocol_id_t protocol;
			u_int32_t spi, reqid;
			struct xfrm_user_expire *expire;
			
			expire = (struct xfrm_user_expire*)NLMSG_DATA(hdr);
			protocol = expire->state.id.proto == KERNEL_ESP ?
														PROTO_ESP : PROTO_AH;
			spi = expire->state.id.spi;
			reqid = expire->state.reqid;
			
			DBG2(DBG_KNL, "received a XFRM_MSG_EXPIRE");
			DBG1(DBG_KNL, "creating %s job for %N CHILD_SA 0x%x (reqid %d)",
				 expire->hard ? "delete" : "rekey",  protocol_id_names,
				 protocol, spi, reqid);
			if (expire->hard)
			{
				job = (job_t*)delete_child_sa_job_create(reqid, protocol, spi);
			}
			else
			{
				job = (job_t*)rekey_child_sa_job_create(reqid, protocol, spi);
			}
			charon->job_queue->add(charon->job_queue, job);
		}
	}
}

/**
 * send a netlink message and wait for a reply
 */
static status_t netlink_send(int socket, struct nlmsghdr *in,
							 struct nlmsghdr **out, size_t *out_len)
{
	int len, addr_len;
	struct sockaddr_nl addr;
	chunk_t result = chunk_empty, tmp;
	struct nlmsghdr *msg, peek;
	
	static int seq = 200;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	
	
	pthread_mutex_lock(&mutex);
	
	in->nlmsg_seq = ++seq;
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
			pthread_mutex_unlock(&mutex);
			DBG1(DBG_KNL, "error sending to netlink socket: %m");
			return FAILED;
		}
		break;
	}
	
	while (TRUE)
	{	
		char buf[1024];
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
				DBG1(DBG_IKE, "got interrupted");
				/* interrupted, try again */
				continue;
			}
			DBG1(DBG_IKE, "error reading from netlink socket: %m");
			pthread_mutex_unlock(&mutex);
			return FAILED;
		}
		if (!NLMSG_OK(msg, len))
		{
			DBG1(DBG_IKE, "received corrupted netlink message");
			pthread_mutex_unlock(&mutex);
			return FAILED;
		}
		if (msg->nlmsg_seq != seq)
		{
			DBG1(DBG_IKE, "received invalid netlink sequence number");
			if (msg->nlmsg_seq < seq)
			{
				continue;
			}
			pthread_mutex_unlock(&mutex);
			return FAILED;
		}
		
		tmp.len = len;
		result = chunk_cata("cc", result, tmp);
		
		/* NLM_F_MULTI flag does not seem to be set correctly, we use sequence
		 * numbers to detect multi header messages */
		len = recvfrom(socket, &peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT,
					   (struct sockaddr*)&addr, &addr_len);
		
		if (len == sizeof(peek) && peek.nlmsg_seq == seq)
		{
			/* seems to be multipart */
			continue;
		}
		break;
	}
	
	*out_len = result.len;
	*out = (struct nlmsghdr*)clalloc(result.ptr, result.len);
	
	pthread_mutex_unlock(&mutex);
	
	return SUCCESS;
}

/**
 * send a netlink message and wait for its acknowlegde
 */
static status_t netlink_send_ack(int socket, struct nlmsghdr *in)
{
	struct nlmsghdr *out, *hdr;
	size_t len;

	if (netlink_send(socket, in, &out, &len) != SUCCESS)
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
 * Create a list of local addresses.
 */
static linked_list_t *create_address_list(private_kernel_interface_t *this)
{
	char request[BUFFER_SIZE];
	struct nlmsghdr *out, *hdr;
	struct rtgenmsg *msg;
	size_t len;
	linked_list_t *list;
	
	DBG2(DBG_IKE, "getting local address list");
	
	list = linked_list_create();
	
	memset(&request, 0, sizeof(request));

	hdr = (struct nlmsghdr*)&request;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	hdr->nlmsg_type = RTM_GETADDR;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
	msg = (struct rtgenmsg*)NLMSG_DATA(hdr);
	msg->rtgen_family = AF_UNSPEC;
		
	if (netlink_send(this->socket_rt, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case RTM_NEWADDR:
				{
					struct ifaddrmsg* msg = (struct ifaddrmsg*)(NLMSG_DATA(hdr));
	      			struct rtattr *rta = IFA_RTA(msg);
	     			size_t rtasize = IFA_PAYLOAD (hdr);
					host_t *host = NULL;
					char *name = NULL;
					chunk_t chunk;
	     			
					while(RTA_OK(rta, rtasize))
					{
						switch (rta->rta_type)
						{
							case IFA_ADDRESS:
								chunk.ptr = RTA_DATA(rta);
								chunk.len = RTA_PAYLOAD(rta);
								host = host_create_from_chunk(msg->ifa_family,
															  chunk, 0);
								break;
							case IFA_LABEL:
								name = RTA_DATA(rta);
						}
						rta = RTA_NEXT(rta, rtasize);
					}
					
					if (host)
					{
						address_entry_t *entry;
						
						entry = malloc_thing(address_entry_t);
						entry->host = host;
						entry->ifindex = msg->ifa_index;
						if (name)
						{
							memcpy(entry->ifname, name, IFNAMSIZ);
						}
						else
						{
							strcpy(entry->ifname, "(unknown)");
						}
						list->insert_last(list, entry);
					}
					hdr = NLMSG_NEXT(hdr, len);
					continue;
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
	else
	{
		DBG1(DBG_IKE, "unable to get local address list");
	}

	return list;
}

/**
 * Implements kernel_interface_t.create_address_list.
 */
static linked_list_t *create_address_list_public(private_kernel_interface_t *this)
{
	linked_list_t *result, *list;
	address_entry_t *entry;
	
	result = linked_list_create();
	list = create_address_list(this);
	while (list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		result->insert_last(result, entry->host);
		free(entry);
	}
	list->destroy(list);
	
	return result;
}

/**
 * implementation of kernel_interface_t.get_interface_name
 */
static char *get_interface_name(private_kernel_interface_t *this, host_t* ip)
{
	linked_list_t *list;
	address_entry_t *entry;
	char *name = NULL;
	
	DBG2(DBG_IKE, "getting interface name for %H", ip);
	
	list = create_address_list(this);
	while (!name && list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		if (ip->ip_equals(ip, entry->host))
		{
			name = strdup(entry->ifname);
		}
		address_entry_destroy(entry);
	}
	list->destroy_function(list, (void*)address_entry_destroy);
	
	if (name)
	{
		DBG2(DBG_IKE, "%H is on interface %s", ip, name);
	}
	else
	{
		DBG2(DBG_IKE, "%H is not a local address", ip);
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
	address_entry_t *entry;
	host_t *host;
	int family;
	linked_list_t *list;
	bool found = FALSE;
	
	DBG2(DBG_IKE, "getting a local address in traffic selector %R", ts);
	
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
		DBG2(DBG_IKE, "using host %H", *ip);
		return SUCCESS;
	}
	host->destroy(host);
	
	list = create_address_list(this);
	while (!found && list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		if (ts->includes(ts, entry->host))
		{
			found = TRUE;
			*ip = entry->host->clone(entry->host);
		}
		address_entry_destroy(entry);
	}
	list->destroy_function(list, (void*)address_entry_destroy);
	
	if (!found)
	{
		DBG1(DBG_IKE, "no local address found in traffic selector %R", ts);
		return FAILED;
	}
	DBG2(DBG_IKE, "using host %H", *ip);
	return SUCCESS;
}

/**
 * get the interface of a local address
 */
static int get_interface_index(private_kernel_interface_t *this, host_t* ip)
{
	linked_list_t *list;
	address_entry_t *entry;
	int ifindex = 0;
	
	DBG2(DBG_IKE, "getting iface for %H", ip);
	
	list = create_address_list(this);
	while (!ifindex && list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		if (ip->ip_equals(ip, entry->host))
		{
			ifindex = entry->ifindex;
		}
		address_entry_destroy(entry);
	}
	list->destroy_function(list, (void*)address_entry_destroy);
	
	if (ifindex == 0)
	{
		DBG1(DBG_IKE, "unable to get interface for %H", ip);
	}
	return ifindex;
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

	return netlink_send_ack(this->socket_rt, hdr);
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
	 * 0.0.0.0/1 and 128.0.0.0/1 
	 * TODO: use metrics instead */
	if (route->prefixlen == 0)
	{
		route_entry_t half;
		status_t status;
		
		half.dst_net = chunk_alloca(route->dst_net.len);
		memset(half.dst_net.ptr, 0, half.dst_net.len);
		half.src_ip = route->src_ip;
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
	msg->rtm_table = RT_TABLE_MAIN;
	msg->rtm_protocol = RTPROT_STATIC;
	msg->rtm_type = RTN_UNICAST;
	msg->rtm_scope = RT_SCOPE_UNIVERSE;
	
	add_attribute(hdr, RTA_DST, route->dst_net, sizeof(request));
	chunk = route->src_ip->get_address(route->src_ip);
	add_attribute(hdr, RTA_PREFSRC, chunk, sizeof(request));
	chunk.ptr = (char*)&route->if_index;
	chunk.len = sizeof(route->if_index);
	add_attribute(hdr, RTA_OIF, chunk, sizeof(request));

	return netlink_send_ack(this->socket_rt, hdr);
}


/**
 * Implementation of kernel_interface_t.add_ip.
 */
static status_t add_ip(private_kernel_interface_t *this, 
						host_t *virtual_ip, host_t *iface_ip)
{
	int targetif;
	vip_entry_t *listed;
	iterator_t *iterator;

	DBG2(DBG_KNL, "adding virtual IP %H", virtual_ip);

	targetif = get_interface_index(this, iface_ip);
	if (targetif == 0)
	{
		DBG1(DBG_KNL, "unable to add virtual IP %H, no iface found for %H",
			 virtual_ip, iface_ip);
		return FAILED;
	}

	/* beware of deadlocks (e.g. send/receive packets while holding the lock) */
	iterator = this->vips->create_iterator_locked(this->vips, &(this->vips_mutex));
	while (iterator->iterate(iterator, (void**)&listed))
	{
		if (listed->if_index == targetif &&
			virtual_ip->ip_equals(virtual_ip, listed->ip))
		{
			listed->refcount++;
			iterator->destroy(iterator);
			DBG2(DBG_KNL, "virtual IP %H already added to iface %d reusing it",
				 virtual_ip, targetif);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);

	if (manage_ipaddr(this, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL,
					  targetif, virtual_ip) == SUCCESS)
	{
		listed = malloc_thing(vip_entry_t);
		listed->ip = virtual_ip->clone(virtual_ip);
		listed->if_index = targetif;
		listed->refcount = 1;
		this->vips->insert_last(this->vips, listed);
		DBG2(DBG_KNL, "virtual IP %H added to iface %d",
				 virtual_ip, targetif);
		return SUCCESS;
	}
	
	DBG2(DBG_KNL, "unable to add virtual IP %H to iface %d",
		 virtual_ip, targetif);
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.del_ip.
 */
static status_t del_ip(private_kernel_interface_t *this,
						host_t *virtual_ip, host_t *iface_ip)
{
	int targetif;
	vip_entry_t *listed;
	iterator_t *iterator;

	DBG2(DBG_KNL, "deleting virtual IP %H", virtual_ip);

	targetif = get_interface_index(this, iface_ip);
	if (targetif == 0)
	{
		DBG1(DBG_KNL, "unable to delete virtual IP %H, no iface found for %H",
			 virtual_ip, iface_ip);
		return FAILED;
	}

	/* beware of deadlocks (e.g. send/receive packets while holding the lock) */
	iterator = this->vips->create_iterator_locked(this->vips, &(this->vips_mutex));
	while (iterator->iterate(iterator, (void**)&listed))
	{
		if (listed->if_index == targetif &&
			virtual_ip->ip_equals(virtual_ip, listed->ip))
		{
			listed->refcount--;
			if (listed->refcount == 0)
			{
				iterator->remove(iterator);
				vip_entry_destroy(listed);
				iterator->destroy(iterator);
				return manage_ipaddr(this, RTM_DELADDR, 0, targetif, virtual_ip);
			}
			iterator->destroy(iterator);
			DBG2(DBG_KNL, "virtual IP %H used by other SAs, not deleting",
		 		 virtual_ip);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
 
	DBG2(DBG_KNL, "virtual IP %H not cached, unable to delete", virtual_ip);
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_kernel_interface_t *this, 
						host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr, *out;
	struct xfrm_userspi_info *userspi;
	u_int32_t received_spi = 0;
	size_t len;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "getting SPI for reqid %d", reqid);
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_ALLOCSPI;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userspi_info));

	userspi = (struct xfrm_userspi_info*)NLMSG_DATA(hdr);
	host2xfrm(src, &userspi->info.saddr);
	host2xfrm(dst, &userspi->info.id.daddr);
	userspi->info.id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	userspi->info.mode = TRUE; /* tunnel mode */
	userspi->info.reqid = reqid;
	userspi->info.family = src->get_family(src);
	userspi->min = 0xc0000000;
	userspi->max = 0xcFFFFFFF;
	
	if (netlink_send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
		DBG1(DBG_KNL, "unable to get SPI for reqid %d", reqid);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "got SPI 0x%x for reqid %d", received_spi, reqid);
	
	*spi = received_spi;
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_kernel_interface_t *this,
					   host_t *src, host_t *dst, u_int32_t spi,
					   protocol_id_t protocol, u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   algorithm_t *enc_alg, algorithm_t *int_alg,
					   prf_plus_t *prf_plus, natt_conf_t *natt, mode_t mode,
					   bool replace)
{
	unsigned char request[BUFFER_SIZE];
	char *alg_name;
	u_int key_size;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_info *sa;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "adding SAD entry with SPI 0x%x", spi);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	
	sa = (struct xfrm_usersa_info*)NLMSG_DATA(hdr);
	host2xfrm(src, &sa->saddr);
	host2xfrm(dst, &sa->id.daddr);
	sa->id.spi = spi;
	sa->id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa->family = src->get_family(src);
	sa->mode = mode;
	sa->replay_window = 32;
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
	
	if (enc_alg->algorithm != ENCR_UNDEFINED)
	{
		rthdr->rta_type = XFRMA_ALG_CRYPT;
		alg_name = lookup_algorithm(encryption_algs, enc_alg, &key_size);
		if (alg_name == NULL)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
				 encryption_algorithm_names, enc_alg->algorithm);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
			 encryption_algorithm_names, enc_alg->algorithm, key_size);
		
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + key_size);
		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
		algo->alg_key_len = key_size;
		strcpy(algo->alg_name, alg_name);
		prf_plus->get_bytes(prf_plus, key_size / 8, algo->alg_key);
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	if (int_alg->algorithm  != AUTH_UNDEFINED)
	{
		rthdr->rta_type = XFRMA_ALG_AUTH;
		alg_name = lookup_algorithm(integrity_algs, int_alg, &key_size);
		if (alg_name == NULL)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!", 
				 integrity_algorithm_names, int_alg->algorithm);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using integrity algorithm %N with key size %d",
			 integrity_algorithm_names, int_alg->algorithm, key_size);
		
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + key_size);
		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
		algo->alg_key_len = key_size;
		strcpy(algo->alg_name, alg_name);
		prf_plus->get_bytes(prf_plus, key_size / 8, algo->alg_key);
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	/* TODO: add IPComp here */
	
	if (natt)
	{
		rthdr->rta_type = XFRMA_ENCAP;
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_encap_tmpl));

		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}

		struct xfrm_encap_tmpl* encap = (struct xfrm_encap_tmpl*)RTA_DATA(rthdr);
		encap->encap_type = UDP_ENCAP_ESPINUDP;
		encap->encap_sport = htons(natt->sport);
		encap->encap_dport = htons(natt->dport);
		memset(&encap->encap_oa, 0, sizeof (xfrm_address_t));
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
	
	if (netlink_send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unalbe to add SAD entry with SPI 0x%x", spi);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(private_kernel_interface_t *this,
						  host_t *src, host_t *dst, 
						  host_t *new_src, host_t *new_dst, 
						  host_diff_t src_changes, host_diff_t dst_changes,
						  u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr, *out = NULL;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *sa = NULL;
	size_t len;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying SAD entry with SPI 0x%x", spi);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
		DBG1(DBG_KNL, "unable to update SAD entry with SPI 0x%x", spi);
		free(out);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "updating SAD entry with SPI 0x%x", spi);
	
	hdr = out;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;	
	hdr->nlmsg_type = XFRM_MSG_UPDSA;
	
	if (src_changes & HOST_DIFF_ADDR)
	{
		host2xfrm(new_src, &sa->saddr);
	}

	if (dst_changes & HOST_DIFF_ADDR)
	{
		hdr->nlmsg_type = XFRM_MSG_NEWSA;
		host2xfrm(new_dst, &sa->id.daddr);
	}
	
	if (src_changes & HOST_DIFF_PORT || dst_changes & HOST_DIFF_PORT)
	{
		struct rtattr *rtattr = XFRM_RTA(hdr, struct xfrm_usersa_info);
		size_t rtsize = XFRM_PAYLOAD(hdr, struct xfrm_usersa_info);
		while (RTA_OK(rtattr, rtsize))
		{
			if (rtattr->rta_type == XFRMA_ENCAP)
			{
				struct xfrm_encap_tmpl* encap;
				encap = (struct xfrm_encap_tmpl*)RTA_DATA(rtattr);
				encap->encap_sport = ntohs(new_src->get_port(new_src));
				encap->encap_dport = ntohs(new_dst->get_port(new_dst));
				break;
			}
			rtattr = RTA_NEXT(rtattr, rtsize);
		}
	}
	if (netlink_send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unalbe to update SAD entry with SPI 0x%x", spi);
		free(out);
		return FAILED;
	}
	free(out);
	
	if (dst_changes & HOST_DIFF_ADDR)
	{
		return this->public.del_sa(&this->public, dst, spi, protocol);
	}
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
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (netlink_send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unalbe to delete SAD entry with SPI 0x%x", spi);
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
						   bool update)
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
	pthread_mutex_lock(&this->policies_mutex);
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (memcmp(&current->sel, &policy->sel, sizeof(struct xfrm_selector)) == 0 &&
			policy->direction == current->direction)
		{
			free(policy);
			/* use existing policy */
			if (!update)
			{
				current->refcount++;
				DBG2(DBG_KNL, "policy %R===%R already exists, increasing ",
					 "refcount", src_ts, dst_ts);
				if (!high_prio)
				{
					/* if added policy is for a ROUTED child_sa, do not
					 * overwrite existing INSTALLED policy */
					iterator->destroy(iterator);
					pthread_mutex_unlock(&this->policies_mutex);
					return SUCCESS;
				}
			}
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
	pthread_mutex_unlock(&this->policies_mutex);
	
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

	rthdr->rta_len = sizeof(struct xfrm_user_tmpl);
	rthdr->rta_len = RTA_LENGTH(rthdr->rta_len);

	hdr->nlmsg_len += rthdr->rta_len;
	if (hdr->nlmsg_len > sizeof(request))
	{
		return FAILED;
	}
	
	struct xfrm_user_tmpl *tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rthdr);
	tmpl->reqid = reqid;
	tmpl->id.proto = (protocol == PROTO_AH) ? KERNEL_AH : KERNEL_ESP;
	tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
	tmpl->mode = mode;
	tmpl->family = src->get_family(src);
	
	host2xfrm(src, &tmpl->saddr);
	host2xfrm(dst, &tmpl->id.daddr);
	
	if (netlink_send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add policy %R===%R", src_ts, dst_ts);
		return FAILED;
	}
	
	if (direction == POLICY_FWD && mode != MODE_TRANSPORT &&
		src->get_family(src) != AF_INET6)
	{
		policy->route = malloc_thing(route_entry_t);
		if (get_address_by_ts(this, dst_ts, &policy->route->src_ip) == SUCCESS)
		{
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
	
	if (netlink_send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
	pthread_mutex_lock(&this->policies_mutex);
	iterator = this->policies->create_iterator(this->policies, TRUE);
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
				pthread_mutex_unlock(&this->policies_mutex);
				return SUCCESS;
			}
			/* remove if last reference */
			iterator->remove(iterator);
			break;
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&this->policies_mutex);
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
	
	if (netlink_send_ack(this->socket_xfrm, hdr) != SUCCESS)
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
	pthread_cancel(this->event_thread);
	pthread_join(this->event_thread, NULL);
	close(this->socket_xfrm_events);
	close(this->socket_xfrm);
	close(this->socket_rt);
	this->vips->destroy(this->vips);
	this->policies->destroy(this->policies);
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
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,algorithm_t*,algorithm_t*,prf_plus_t*,natt_conf_t*,mode_t,bool))add_sa;
	this->public.update_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t,host_t*,host_t*,host_diff_t,host_diff_t))update_sa;
	this->public.query_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t*))query_sa;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,protocol_id_t,u_int32_t,bool,mode_t,bool))add_policy;
	this->public.query_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.del_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t))del_policy;

	this->public.get_interface = (char*(*)(kernel_interface_t*,host_t*))get_interface_name;
	this->public.create_address_list = (linked_list_t*(*)(kernel_interface_t*))create_address_list_public;
	this->public.add_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) add_ip;
	this->public.del_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) del_ip;
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->vips = linked_list_create();
	this->policies = linked_list_create();
	pthread_mutex_init(&this->policies_mutex,NULL);
	pthread_mutex_init(&this->vips_mutex,NULL);
	
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;
	
	/* create and bind XFRM socket */
	this->socket_xfrm = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm <= 0)
	{
		charon->kill(charon, "unable to create XFRM netlink socket");
	}
	
	if (bind(this->socket_xfrm, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM netlink socket");
	}
	
	/* create and bind RT socket */
	this->socket_rt = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->socket_rt <= 0)
	{
		charon->kill(charon, "unable to create RT netlink socket");
	}
	
	if (bind(this->socket_rt, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind RT netlink socket");
	}
	
	/* create and bind XFRM socket for ACQUIRE & EXPIRE */
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	this->socket_xfrm_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm_events <= 0)
	{
		charon->kill(charon, "unable to create XFRM event socket");
	}
	
	if (bind(this->socket_xfrm_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM event socket");
	}
	
	/* create a thread receiving ACQUIRE & EXPIRE events */
	if (pthread_create(&this->event_thread, NULL,
					   (void*(*)(void*))receive_events, this))
	{
		charon->kill(charon, "unable to create xfrm event dispatcher thread");
	}
	
	return &this->public;
}

/* vim: set ts=4 sw=4 noet: */
