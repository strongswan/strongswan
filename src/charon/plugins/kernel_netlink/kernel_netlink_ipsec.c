/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2008 Andreas Steffen
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdint.h>
#include <linux/ipsec.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/udp.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kernel_netlink_ipsec.h"
#include "kernel_netlink_shared.h"

#include <daemon.h>
#include <utils/mutex.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/acquire_job.h>
#include <processing/jobs/migrate_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/delete_child_sa_job.h>
#include <processing/jobs/update_sa_job.h>

/** required for Linux 2.6.26 kernel and later */
#ifndef XFRM_STATE_AF_UNSPEC
#define XFRM_STATE_AF_UNSPEC	32
#endif

/** from linux/in.h */
#ifndef IP_IPSEC_POLICY
#define IP_IPSEC_POLICY 16
#endif

/** default priority of installed policies */
#define PRIO_LOW 3000
#define PRIO_HIGH 2000

/**
 * Create ORable bitfield of XFRM NL groups
 */
#define XFRMNLGRP(x) (1<<(XFRMNLGRP_##x-1))

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
 * Mapping of IKEv2 kernel identifier to linux crypto API names
 */
struct kernel_algorithm_t {
	/**
	 * Identifier specified in IKEv2
	 */
	int ikev2;
	
	/**
	 * Name of the algorithm in linux crypto API
	 */
	char *name;
};

ENUM(xfrm_attr_type_names, XFRMA_UNSPEC, XFRMA_KMADDRESS,
	"XFRMA_UNSPEC",
	"XFRMA_ALG_AUTH",
	"XFRMA_ALG_CRYPT",
	"XFRMA_ALG_COMP",
	"XFRMA_ENCAP",
	"XFRMA_TMPL",
	"XFRMA_SA",
	"XFRMA_POLICY",
	"XFRMA_SEC_CTX",
	"XFRMA_LTIME_VAL",
	"XFRMA_REPLAY_VAL",
	"XFRMA_REPLAY_THRESH",
	"XFRMA_ETIMER_THRESH",
	"XFRMA_SRCADDR",
	"XFRMA_COADDR",
	"XFRMA_LASTUSED",
	"XFRMA_POLICY_TYPE",
	"XFRMA_MIGRATE",
	"XFRMA_ALG_AEAD",
	"XFRMA_KMADDRESS"
);

#define END_OF_LIST -1

/**
 * Algorithms for encryption
 */
static kernel_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64, 			"***"				}, */
	{ENCR_DES, 					"des" 				},
	{ENCR_3DES, 				"des3_ede"			},
/*	{ENCR_RC5, 					"***" 				}, */
/*	{ENCR_IDEA, 				"***"				}, */
	{ENCR_CAST, 				"cast128"			},
	{ENCR_BLOWFISH, 			"blowfish"			},
/*	{ENCR_3IDEA, 				"***"				}, */
/*	{ENCR_DES_IV32, 			"***"				}, */
	{ENCR_NULL, 				"cipher_null"		},
	{ENCR_AES_CBC,	 			"aes"				},
/*	{ENCR_AES_CTR, 				"***"				}, */
	{ENCR_AES_CCM_ICV8,			"rfc4309(ccm(aes))"	},
	{ENCR_AES_CCM_ICV12,		"rfc4309(ccm(aes))"	},
	{ENCR_AES_CCM_ICV16,		"rfc4309(ccm(aes))"	},
	{ENCR_AES_GCM_ICV8,			"rfc4106(gcm(aes))"	},
	{ENCR_AES_GCM_ICV12,		"rfc4106(gcm(aes))"	},
	{ENCR_AES_GCM_ICV16,		"rfc4106(gcm(aes))"	},
	{END_OF_LIST, 				NULL				},
};

/**
 * Algorithms for integrity protection
 */
static kernel_algorithm_t integrity_algs[] = {
	{AUTH_HMAC_MD5_96, 			"md5"				},
	{AUTH_HMAC_SHA1_96,			"sha1"				},
	{AUTH_HMAC_SHA2_256_128,	"sha256"			},
	{AUTH_HMAC_SHA2_384_192,	"sha384"			},
	{AUTH_HMAC_SHA2_512_256,	"sha512"			},
/*	{AUTH_DES_MAC,				"***"				}, */
/*	{AUTH_KPDK_MD5,				"***"				}, */
	{AUTH_AES_XCBC_96,			"xcbc(aes)"			},
	{END_OF_LIST, 				NULL				},
};

/**
 * Algorithms for IPComp
 */
static kernel_algorithm_t compression_algs[] = {
/*	{IPCOMP_OUI, 				"***"				}, */
	{IPCOMP_DEFLATE,			"deflate"			},
	{IPCOMP_LZS,				"lzs"				},
	{IPCOMP_LZJH,				"lzjh"				},
	{END_OF_LIST, 				NULL				},
};

/**
 * Look up a kernel algorithm name and its key size
 */
static char* lookup_algorithm(kernel_algorithm_t *list, int ikev2)
{
	while (list->ikev2 != END_OF_LIST)
	{
		if (list->ikev2 == ikev2)
		{
			return list->name;
		}
		list++;
	}
	return NULL;
}

typedef struct route_entry_t route_entry_t;

/**
 * installed routing entry
 */
struct route_entry_t {
	/** Name of the interface the route is bound to */
	char *if_name;
	
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
	free(this->if_name);
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
	
	/** parameters of installed policy */
	struct xfrm_selector sel;
	
	/** associated route installed for this policy */
	route_entry_t *route;
	
	/** by how many CHILD_SA's this policy is used */
	u_int refcount;
};

typedef struct private_kernel_netlink_ipsec_t private_kernel_netlink_ipsec_t;

/**
 * Private variables and functions of kernel_netlink class.
 */
struct private_kernel_netlink_ipsec_t {
	/**
	 * Public part of the kernel_netlink_t object.
	 */
	kernel_netlink_ipsec_t public;
	
	/**
	 * mutex to lock access to various lists
	 */
	mutex_t *mutex;
	
	/**
	 * List of installed policies (policy_entry_t)
	 */
	linked_list_t *policies;
		 
	/**
	 * job receiving netlink events
	 */
	callback_job_t *job;
	
	/**
	 * Netlink xfrm socket (IPsec)
	 */
	netlink_socket_t *socket_xfrm;
	
	/**
	 * netlink xfrm socket to receive acquire and expire events
	 */
	int socket_xfrm_events;
	
	/**
	 * whether to install routes along policies
	 */
	bool install_routes;
};

/**
 * convert a IKEv2 specific protocol identifier to the kernel one
 */
static u_int8_t proto_ike2kernel(protocol_id_t proto)
{
	switch (proto)
	{
		case PROTO_ESP:
			return IPPROTO_ESP;
		case PROTO_AH:
			return IPPROTO_AH;
		default:
			return proto;
	}
}

/**
 * reverse of ike2kernel
 */
static protocol_id_t proto_kernel2ike(u_int8_t proto)
{
	switch (proto)
	{
		case IPPROTO_ESP:
			return PROTO_ESP;
		case IPPROTO_AH:
			return PROTO_AH;
		default:
			return proto;
	}
}

/**
 * convert a host_t to a struct xfrm_address
 */
static void host2xfrm(host_t *host, xfrm_address_t *xfrm)
{
	chunk_t chunk = host->get_address(host);
	memcpy(xfrm, chunk.ptr, min(chunk.len, sizeof(xfrm_address_t)));	
}

/**
 * convert a struct xfrm_address to a host_t
 */
static host_t* xfrm2host(int family, xfrm_address_t *xfrm, u_int16_t port)
{
	chunk_t chunk;
	
	switch (family)
	{
		case AF_INET:
			chunk = chunk_create((u_char*)&xfrm->a4, sizeof(xfrm->a4));
			break;
		case AF_INET6:
			chunk = chunk_create((u_char*)&xfrm->a6, sizeof(xfrm->a6));
			break;
		default:
			return NULL;
	}
	return host_create_from_chunk(family, chunk, ntohs(port));
}

/**
 * convert a traffic selector address range to subnet and its mask.
 */
static void ts2subnet(traffic_selector_t* ts, 
					  xfrm_address_t *net, u_int8_t *mask)
{
	host_t *net_host;
	chunk_t net_chunk;
	
	ts->to_subnet(ts, &net_host, mask);
	net_chunk = net_host->get_address(net_host);
	memcpy(net, net_chunk.ptr, net_chunk.len);
	net_host->destroy(net_host);
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
	sel.family = (src->get_type(src) == TS_IPV4_ADDR_RANGE) ? AF_INET : AF_INET6;
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
 * convert a xfrm_selector to a src|dst traffic_selector 
 */
static traffic_selector_t* selector2ts(struct xfrm_selector *sel, bool src)
{
	int family;
	chunk_t addr;
	u_int8_t prefixlen;
	u_int16_t port, port_mask;
	host_t *host;
	traffic_selector_t *ts;

	if (src)
	{
		addr.ptr = (u_char*)&sel->saddr;
		prefixlen = sel->prefixlen_s;
		port = sel->sport;
		port_mask = sel->sport_mask;
	}
    else
	{
		addr.ptr = (u_char*)&sel->daddr;
		prefixlen = sel->prefixlen_d;
		port = sel->dport;
		port_mask = sel->dport_mask;
	}

	/* The Linux 2.6 kernel does not set the selector's family field,
     * so as a kludge we additionally test the prefix length. 
	 */
	if (sel->family == AF_INET || sel->prefixlen_s == 32)
	{
		family = AF_INET;
		addr.len = 4;
	}
	else if (sel->family == AF_INET6 || sel->prefixlen_s == 128)
	{
		family = AF_INET6;
		addr.len = 16;
	}
	else
	{
		return NULL;
	}
	host = host_create_from_chunk(family, addr, 0);
	port = (port_mask == 0) ? 0 : ntohs(port); 

	ts = traffic_selector_create_from_subnet(host, prefixlen, sel->proto, port);
	host->destroy(host); 		
	return ts;
}

/**
 * process a XFRM_MSG_ACQUIRE from kernel
 */
static void process_acquire(private_kernel_netlink_ipsec_t *this, struct nlmsghdr *hdr)
{
	u_int32_t reqid = 0;
	int proto = 0;
	traffic_selector_t *src_ts, *dst_ts;
	struct xfrm_user_acquire *acquire;
	struct rtattr *rta;
	size_t rtasize;
	job_t *job;
	
	acquire = (struct xfrm_user_acquire*)NLMSG_DATA(hdr);
	rta = XFRM_RTA(hdr, struct xfrm_user_acquire);
	rtasize = XFRM_PAYLOAD(hdr, struct xfrm_user_acquire);

	DBG2(DBG_KNL, "received a XFRM_MSG_ACQUIRE");

	while (RTA_OK(rta, rtasize))
	{
		DBG2(DBG_KNL, "  %N", xfrm_attr_type_names, rta->rta_type);

		if (rta->rta_type == XFRMA_TMPL)
		{
			struct xfrm_user_tmpl* tmpl;

			tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rta);
			reqid = tmpl->reqid;
			proto = tmpl->id.proto;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	switch (proto)
	{
		case 0:
		case IPPROTO_ESP:
		case IPPROTO_AH:
			break;
		default:
			/* acquire for AH/ESP only, not for IPCOMP */
			return;
	}
	src_ts = selector2ts(&acquire->sel, TRUE);
	dst_ts = selector2ts(&acquire->sel, FALSE);
	DBG1(DBG_KNL, "creating acquire job for policy %R === %R with reqid {%u}",
					src_ts, dst_ts, reqid);
	job = (job_t*)acquire_job_create(reqid, src_ts, dst_ts);
	charon->processor->queue_job(charon->processor, job);
}

/**
 * process a XFRM_MSG_EXPIRE from kernel
 */
static void process_expire(private_kernel_netlink_ipsec_t *this, struct nlmsghdr *hdr)
{
	job_t *job;
	protocol_id_t protocol;
	u_int32_t spi, reqid;
	struct xfrm_user_expire *expire;
	
	expire = (struct xfrm_user_expire*)NLMSG_DATA(hdr);
	protocol = proto_kernel2ike(expire->state.id.proto);
	spi = expire->state.id.spi;
	reqid = expire->state.reqid;
	
	DBG2(DBG_KNL, "received a XFRM_MSG_EXPIRE");
	
	if (protocol != PROTO_ESP && protocol != PROTO_AH)
	{
		DBG2(DBG_KNL, "ignoring XFRM_MSG_EXPIRE for SA with SPI %.8x and reqid {%u} "
					  "which is not a CHILD_SA", ntohl(spi), reqid);
		return;
	}
	
	DBG1(DBG_KNL, "creating %s job for %N CHILD_SA with SPI %.8x and reqid {%d}",
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
 * process a XFRM_MSG_MIGRATE from kernel
 */
static void process_migrate(private_kernel_netlink_ipsec_t *this, struct nlmsghdr *hdr)
{
	traffic_selector_t *src_ts, *dst_ts;
	host_t *local = NULL, *remote = NULL;
	host_t *old_src = NULL, *old_dst = NULL;
	host_t *new_src = NULL, *new_dst = NULL;
	struct xfrm_userpolicy_id *policy_id;
	struct rtattr *rta;
	size_t rtasize;
	u_int32_t reqid = 0;
	policy_dir_t dir;
	job_t *job;

	policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	rta     = XFRM_RTA(hdr, struct xfrm_userpolicy_id);
	rtasize = XFRM_PAYLOAD(hdr, struct xfrm_userpolicy_id);

	DBG2(DBG_KNL, "received a XFRM_MSG_MIGRATE");
	
	src_ts = selector2ts(&policy_id->sel, TRUE);
	dst_ts = selector2ts(&policy_id->sel, FALSE);
	dir = (policy_dir_t)policy_id->dir;

	DBG2(DBG_KNL, "  policy: %R === %R %N, index %u", src_ts, dst_ts,
				   policy_dir_names, dir, policy_id->index);

	while (RTA_OK(rta, rtasize))
	{
		DBG2(DBG_KNL, "  %N", xfrm_attr_type_names, rta->rta_type);
		if (rta->rta_type == XFRMA_KMADDRESS)
		{
			struct xfrm_user_kmaddress *kmaddress;

			kmaddress = (struct xfrm_user_kmaddress*)RTA_DATA(rta);
			local  = xfrm2host(kmaddress->family, &kmaddress->local, 0);
			remote = xfrm2host(kmaddress->family, &kmaddress->remote, 0);
			DBG2(DBG_KNL, "  kmaddress: %H...%H", local, remote);
		}
		else if (rta->rta_type == XFRMA_MIGRATE)
		{
			struct xfrm_user_migrate *migrate;
			protocol_id_t proto;

			migrate = (struct xfrm_user_migrate*)RTA_DATA(rta);
			old_src = xfrm2host(migrate->old_family, &migrate->old_saddr, 0);
			old_dst = xfrm2host(migrate->old_family, &migrate->old_daddr, 0);
			new_src = xfrm2host(migrate->new_family, &migrate->new_saddr, 0);
			new_dst = xfrm2host(migrate->new_family, &migrate->new_daddr, 0);
			proto = proto_kernel2ike(migrate->proto);
			reqid = migrate->reqid;
			DBG2(DBG_KNL, "  migrate %N %H...%H to %H...%H, reqid {%u}",
							 protocol_id_names, proto, old_src, old_dst,
							 new_src, new_dst, reqid);
			DESTROY_IF(old_src);
			DESTROY_IF(old_dst);
			DESTROY_IF(new_src);
			DESTROY_IF(new_dst);
		}
		rta = RTA_NEXT(rta, rtasize);
	}

	if (src_ts && dst_ts)
	{
		DBG1(DBG_KNL, "creating migrate job for policy %R === %R %N with reqid {%u}",
					   src_ts, dst_ts, policy_dir_names, dir, reqid, local);
		job = (job_t*)migrate_job_create(reqid, src_ts, dst_ts, dir,
										 local, remote);
		charon->processor->queue_job(charon->processor, job);
	}
	else
	{
		DESTROY_IF(src_ts);
		DESTROY_IF(dst_ts);
		DESTROY_IF(local);
		DESTROY_IF(remote);
	}
}

/**
 * process a XFRM_MSG_MAPPING from kernel
 */
static void process_mapping(private_kernel_netlink_ipsec_t *this,
							struct nlmsghdr *hdr)
{
	job_t *job;
	u_int32_t spi, reqid;
	struct xfrm_user_mapping *mapping;
	host_t *host;
	
	mapping = (struct xfrm_user_mapping*)NLMSG_DATA(hdr);
	spi = mapping->id.spi;
	reqid = mapping->reqid;
	
	DBG2(DBG_KNL, "received a XFRM_MSG_MAPPING");
	
	if (proto_kernel2ike(mapping->id.proto) == PROTO_ESP)
	{
		host = xfrm2host(mapping->id.family, &mapping->new_saddr,
						 mapping->new_sport);
		if (host)
		{
			DBG1(DBG_KNL, "NAT mappings of ESP CHILD_SA with SPI %.8x and "
				"reqid {%u} changed, queuing update job", ntohl(spi), reqid);
			job = (job_t*)update_sa_job_create(reqid, host);
			charon->processor->queue_job(charon->processor, job);
		}
	}
}

/**
 * Receives events from kernel
 */
static job_requeue_t receive_events(private_kernel_netlink_ipsec_t *this)
{
	char response[1024];
	struct nlmsghdr *hdr = (struct nlmsghdr*)response;
	struct sockaddr_nl addr;
	socklen_t addr_len = sizeof(addr);
	int len, oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	len = recvfrom(this->socket_xfrm_events, response, sizeof(response), 0,
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
		switch (hdr->nlmsg_type)
		{
			case XFRM_MSG_ACQUIRE:
				process_acquire(this, hdr);
				break;
			case XFRM_MSG_EXPIRE:
				process_expire(this, hdr);
				break;
			case XFRM_MSG_MIGRATE:
				process_migrate(this, hdr);
				break;
			case XFRM_MSG_MAPPING:
				process_mapping(this, hdr);
				break;
			default:
				break;
		}
		hdr = NLMSG_NEXT(hdr, len);
	}
	return JOB_REQUEUE_DIRECT;
}

/**
 * Get an SPI for a specific protocol from the kernel.
 */
static status_t get_spi_internal(private_kernel_netlink_ipsec_t *this,
		host_t *src, host_t *dst, u_int8_t proto, u_int32_t min, u_int32_t max,
		u_int32_t reqid, u_int32_t *spi)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
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
	
	if (this->socket_xfrm->send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
static status_t get_spi(private_kernel_netlink_ipsec_t *this, 
						host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	DBG2(DBG_KNL, "getting SPI for reqid {%u}", reqid);
	
	if (get_spi_internal(this, src, dst, proto_ike2kernel(protocol),
			0xc0000000, 0xcFFFFFFF, reqid, spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get SPI for reqid {%u}", reqid);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "got SPI %.8x for reqid {%u}", ntohl(*spi), reqid);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.get_cpi.
 */
static status_t get_cpi(private_kernel_netlink_ipsec_t *this, 
						host_t *src, host_t *dst, 
						u_int32_t reqid, u_int16_t *cpi)
{
	u_int32_t received_spi = 0;

	DBG2(DBG_KNL, "getting CPI for reqid {%u}", reqid);
	
	if (get_spi_internal(this, src, dst,
			IPPROTO_COMP, 0x100, 0xEFFF, reqid, &received_spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get CPI for reqid {%u}", reqid);
		return FAILED;
	}
	
	*cpi = htons((u_int16_t)ntohl(received_spi));
	
	DBG2(DBG_KNL, "got CPI %.4x for reqid {%u}", ntohs(*cpi), reqid);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_kernel_netlink_ipsec_t *this,
					   host_t *src, host_t *dst, u_int32_t spi,
					   protocol_id_t protocol, u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   u_int16_t enc_alg, chunk_t enc_key,
					   u_int16_t int_alg, chunk_t int_key,
					   ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
					   bool encap, bool inbound)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	char *alg_name;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_info *sa;
	u_int16_t icv_size = 64;	
	
	/* if IPComp is used, we install an additional IPComp SA. if the cpi is 0
	 * we are in the recursive call below */
	if (ipcomp != IPCOMP_NONE && cpi != 0)
	{
		add_sa(this, src, dst, htonl(ntohs(cpi)), IPPROTO_COMP, reqid, 0, 0,
 			   ENCR_UNDEFINED, chunk_empty, AUTH_UNDEFINED, chunk_empty,
 			   mode, ipcomp, 0, FALSE, inbound);
		ipcomp = IPCOMP_NONE;
	}
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "adding SAD entry with SPI %.8x and reqid {%u}",
		 ntohl(spi), reqid);
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = inbound ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	
	sa = (struct xfrm_usersa_info*)NLMSG_DATA(hdr);
	host2xfrm(src, &sa->saddr);
	host2xfrm(dst, &sa->id.daddr);
	sa->id.spi = spi;
	sa->id.proto = proto_ike2kernel(protocol);
	sa->family = src->get_family(src);
	sa->mode = mode;
	if (mode == MODE_TUNNEL)
	{
		sa->flags |= XFRM_STATE_AF_UNSPEC;
	}
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
		case ENCR_AES_CCM_ICV16:
		case ENCR_AES_GCM_ICV16:
			icv_size += 32;
			/* FALL */
		case ENCR_AES_CCM_ICV12:
		case ENCR_AES_GCM_ICV12:
			icv_size += 32;
			/* FALL */
		case ENCR_AES_CCM_ICV8:
		case ENCR_AES_GCM_ICV8:
		{
			rthdr->rta_type = XFRMA_ALG_AEAD;
			alg_name = lookup_algorithm(encryption_algs, enc_alg);
			if (alg_name == NULL)
			{
				DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
					 encryption_algorithm_names, enc_alg);
				return FAILED;
			}
			DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
				 encryption_algorithm_names, enc_alg, enc_key.len * 8);
			
			rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo_aead) + enc_key.len);
			hdr->nlmsg_len += rthdr->rta_len;
			if (hdr->nlmsg_len > sizeof(request))
			{
				return FAILED;
			}
			
			struct xfrm_algo_aead* algo = (struct xfrm_algo_aead*)RTA_DATA(rthdr);
			algo->alg_key_len = enc_key.len * 8;
			algo->alg_icv_len = icv_size;
			strcpy(algo->alg_name, alg_name);
			memcpy(algo->alg_key, enc_key.ptr, enc_key.len);
			
			rthdr = XFRM_RTA_NEXT(rthdr);
			break;
		}
		default:
		{
			rthdr->rta_type = XFRMA_ALG_CRYPT;
			alg_name = lookup_algorithm(encryption_algs, enc_alg);
			if (alg_name == NULL)
			{
				DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
					 encryption_algorithm_names, enc_alg);
				return FAILED;
			}
			DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
				 encryption_algorithm_names, enc_alg, enc_key.len * 8);
			
			rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + enc_key.len);
			hdr->nlmsg_len += rthdr->rta_len;
			if (hdr->nlmsg_len > sizeof(request))
			{
				return FAILED;
			}
			
			struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
			algo->alg_key_len = enc_key.len * 8;
			strcpy(algo->alg_name, alg_name);
			memcpy(algo->alg_key, enc_key.ptr, enc_key.len);
			
			rthdr = XFRM_RTA_NEXT(rthdr);
			break;
		}
	}
		
	if (int_alg  != AUTH_UNDEFINED)
	{
		rthdr->rta_type = XFRMA_ALG_AUTH;
		alg_name = lookup_algorithm(integrity_algs, int_alg);
		if (alg_name == NULL)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!", 
				 integrity_algorithm_names, int_alg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using integrity algorithm %N with key size %d",
			 integrity_algorithm_names, int_alg, int_key.len * 8);
		
		rthdr->rta_len = RTA_LENGTH(sizeof(struct xfrm_algo) + int_key.len);
		hdr->nlmsg_len += rthdr->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		struct xfrm_algo* algo = (struct xfrm_algo*)RTA_DATA(rthdr);
		algo->alg_key_len = int_key.len * 8;
		strcpy(algo->alg_name, alg_name);
		memcpy(algo->alg_key, int_key.ptr, int_key.len);
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}
	
	if (ipcomp != IPCOMP_NONE)
	{
		rthdr->rta_type = XFRMA_ALG_COMP;
		alg_name = lookup_algorithm(compression_algs, ipcomp);
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
	
	if (this->socket_xfrm->send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Get the replay state (i.e. sequence numbers) of an SA.
 */
static status_t get_replay_state(private_kernel_netlink_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol, host_t *dst,
						  struct xfrm_replay_state *replay)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr, *out = NULL;
	struct xfrm_aevent_id *out_aevent = NULL, *aevent_id;
	size_t len;
	struct rtattr *rta;
	size_t rtasize;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying replay state from SAD entry with SPI %.8x", ntohl(spi));

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETAE;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_aevent_id));
	
	aevent_id = (struct xfrm_aevent_id*)NLMSG_DATA(hdr);
	aevent_id->flags = XFRM_AE_RVAL;
	
	host2xfrm(dst, &aevent_id->sa_id.daddr);
	aevent_id->sa_id.spi = spi;
	aevent_id->sa_id.proto = proto_ike2kernel(protocol);
	aevent_id->sa_id.family = dst->get_family(dst);
	
	if (this->socket_xfrm->send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
	{
		hdr = out;
		while (NLMSG_OK(hdr, len))
		{
			switch (hdr->nlmsg_type)
			{
				case XFRM_MSG_NEWAE:
				{
					out_aevent = NLMSG_DATA(hdr);
					break;
				}
				case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(hdr);
					DBG1(DBG_KNL, "querying replay state from SAD entry failed: %s (%d)",
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
	
	if (out_aevent == NULL)
	{
		DBG1(DBG_KNL, "unable to query replay state from SAD entry with SPI %.8x",
					  ntohl(spi));
		free(out);
		return FAILED;
	}
	
	rta = XFRM_RTA(out, struct xfrm_aevent_id);
	rtasize = XFRM_PAYLOAD(out, struct xfrm_aevent_id);
	while(RTA_OK(rta, rtasize))
	{
		if (rta->rta_type == XFRMA_REPLAY_VAL &&
			RTA_PAYLOAD(rta) == sizeof(struct xfrm_replay_state))
		{
			memcpy(replay, RTA_DATA(rta), RTA_PAYLOAD(rta));
			free(out);
			return SUCCESS;
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	
	DBG1(DBG_KNL, "unable to query replay state from SAD entry with SPI %.8x",
				  ntohl(spi));
	free(out);
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.del_sa.
 */
static status_t del_sa(private_kernel_netlink_ipsec_t *this, host_t *dst,
					   u_int32_t spi, protocol_id_t protocol, u_int16_t cpi)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	
	/* if IPComp was used, we first delete the additional IPComp SA */
	if (cpi)
	{
		del_sa(this, dst, htonl(ntohs(cpi)), IPPROTO_COMP, 0);
	}
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "deleting SAD entry with SPI %.8x", ntohl(spi));
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
	
	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = proto_ike2kernel(protocol);
	sa_id->family = dst->get_family(dst);
	
	if (this->socket_xfrm->send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	DBG2(DBG_KNL, "deleted SAD entry with SPI %.8x", ntohl(spi));
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(private_kernel_netlink_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol, u_int16_t cpi,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst,
						  bool encap, bool new_encap)
{
	unsigned char request[NETLINK_BUFFER_SIZE], *pos;
	struct nlmsghdr *hdr, *out = NULL;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *out_sa = NULL, *sa;
	size_t len;
	struct rtattr *rta;
	size_t rtasize;
	struct xfrm_encap_tmpl* tmpl = NULL;
	bool got_replay_state = FALSE;
	struct xfrm_replay_state replay;
	
	/* if IPComp is used, we first update the IPComp SA */
	if (cpi)
	{
		update_sa(this, htonl(ntohs(cpi)), IPPROTO_COMP, 0,
				  src, dst, new_src, new_dst, FALSE, FALSE);
	}
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying SAD entry with SPI %.8x for update", ntohl(spi));
	
	/* query the existing SA first */
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
	
	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = proto_ike2kernel(protocol);
	sa_id->family = dst->get_family(dst);
	
	if (this->socket_xfrm->send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
	if (out_sa == NULL)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI %.8x", ntohl(spi));
		free(out);
		return FAILED;
	}
	
	/* try to get the replay state */
	if (get_replay_state(this, spi, protocol, dst, &replay) == SUCCESS)
	{
		got_replay_state = TRUE;
	}
	
	/* delete the old SA (without affecting the IPComp SA) */
	if (del_sa(this, dst, spi, protocol, 0) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete old SAD entry with SPI %.8x", ntohl(spi));
		free(out);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "updating SAD entry with SPI %.8x from %#H..%#H to %#H..%#H",
		 ntohl(spi), src, dst, new_src, new_dst);
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
			pos += RTA_ALIGN(rta->rta_len);
			hdr->nlmsg_len += RTA_ALIGN(rta->rta_len);
		}
		rta = RTA_NEXT(rta, rtasize);
	}
	
	rta = (struct rtattr*)pos;
	if (tmpl == NULL && encap)
	{	/* add tmpl if we are enabling it */
		rta->rta_type = XFRMA_ENCAP;
		rta->rta_len = RTA_LENGTH(sizeof(struct xfrm_encap_tmpl));
		
		hdr->nlmsg_len += rta->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		
		tmpl = (struct xfrm_encap_tmpl*)RTA_DATA(rta);
		tmpl->encap_type = UDP_ENCAP_ESPINUDP;
		tmpl->encap_sport = ntohs(new_src->get_port(new_src));
		tmpl->encap_dport = ntohs(new_dst->get_port(new_dst));
		memset(&tmpl->encap_oa, 0, sizeof (xfrm_address_t));
		
		rta = XFRM_RTA_NEXT(rta);
	}
	
	if (got_replay_state)
	{	/* copy the replay data if available */
		rta->rta_type = XFRMA_REPLAY_VAL;
		rta->rta_len = RTA_LENGTH(sizeof(struct xfrm_replay_state));
		
		hdr->nlmsg_len += rta->rta_len;
		if (hdr->nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		memcpy(RTA_DATA(rta), &replay, sizeof(replay));
		
		rta = XFRM_RTA_NEXT(rta);
	}
	
	if (this->socket_xfrm->send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI %.8x", ntohl(spi));
		free(out);
		return FAILED;
	}
	free(out);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_policy.
 */
static status_t add_policy(private_kernel_netlink_ipsec_t *this, 
						   host_t *src, host_t *dst,
						   traffic_selector_t *src_ts,
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, u_int32_t spi,
						   protocol_id_t protocol, u_int32_t reqid,
						   ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
						   bool routed)
{
	iterator_t *iterator;
	policy_entry_t *current, *policy;
	bool found = FALSE;
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct xfrm_userpolicy_info *policy_info;
	struct nlmsghdr *hdr;
	
	/* create a policy */
	policy = malloc_thing(policy_entry_t);
	memset(policy, 0, sizeof(policy_entry_t));
	policy->sel = ts2selector(src_ts, dst_ts);
	policy->direction = direction;
	
	/* find the policy, which matches EXACTLY */
	this->mutex->lock(this->mutex);
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (memeq(&current->sel, &policy->sel, sizeof(struct xfrm_selector)) &&
			policy->direction == current->direction)
		{
			/* use existing policy */
			current->refcount++;
			DBG2(DBG_KNL, "policy %R === %R %N already exists, increasing "
						  "refcount", src_ts, dst_ts,
						   policy_dir_names, direction);
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
	
	DBG2(DBG_KNL, "adding policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);
	
	memset(&request, 0, sizeof(request));
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = found ? XFRM_MSG_UPDPOLICY : XFRM_MSG_NEWPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));

	policy_info = (struct xfrm_userpolicy_info*)NLMSG_DATA(hdr);
	policy_info->sel = policy->sel;
	policy_info->dir = policy->direction;
	/* calculate priority based on source selector size, small size = high prio */
	policy_info->priority = routed ? PRIO_LOW : PRIO_HIGH;
	policy_info->priority -= policy->sel.prefixlen_s * 10;
	policy_info->priority -= policy->sel.proto ? 2 : 0;
	policy_info->priority -= policy->sel.sport_mask ? 1 : 0;
	policy_info->action = XFRM_POLICY_ALLOW;
	policy_info->share = XFRM_SHARE_ANY;
	this->mutex->unlock(this->mutex);
	
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
	tmpl->id.proto = proto_ike2kernel(protocol);
	tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
	tmpl->mode = mode;
	tmpl->family = src->get_family(src);
	
	host2xfrm(src, &tmpl->saddr);
	host2xfrm(dst, &tmpl->id.daddr);
	
	if (this->socket_xfrm->send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
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
		route_entry_t *route = malloc_thing(route_entry_t);
		
		if (charon->kernel_interface->get_address_by_ts(charon->kernel_interface,
				dst_ts, &route->src_ip) == SUCCESS)
		{
			/* get the nexthop to src (src as we are in POLICY_FWD).*/
			route->gateway = charon->kernel_interface->get_nexthop(
									charon->kernel_interface, src);
			route->if_name = charon->kernel_interface->get_interface(
									charon->kernel_interface, dst);
			route->dst_net = chunk_alloc(policy->sel.family == AF_INET ? 4 : 16);
			memcpy(route->dst_net.ptr, &policy->sel.saddr, route->dst_net.len);
			route->prefixlen = policy->sel.prefixlen_s;
			
			if (route->if_name)
			{			
				switch (charon->kernel_interface->add_route(
									charon->kernel_interface, route->dst_net,
									route->prefixlen, route->gateway,
									route->src_ip, route->if_name))
				{
					default:
						DBG1(DBG_KNL, "unable to install source route for %H",
							 route->src_ip);
						/* FALL */
					case ALREADY_DONE:
						/* route exists, do not uninstall */
						route_entry_destroy(route);
						break;
					case SUCCESS:
						/* cache the installed route */
						policy->route = route;
						break;
				}
			}
			else
			{
				route_entry_destroy(route);
			}
		}
		else
		{
			free(route);
		}
	}
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.query_policy.
 */
static status_t query_policy(private_kernel_netlink_ipsec_t *this,
							 traffic_selector_t *src_ts, 
							 traffic_selector_t *dst_ts,
							 policy_dir_t direction, u_int32_t *use_time)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *out = NULL, *hdr;
	struct xfrm_userpolicy_id *policy_id;
	struct xfrm_userpolicy_info *policy = NULL;
	size_t len;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "querying policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel = ts2selector(src_ts, dst_ts);
	policy_id->dir = direction;
	
	if (this->socket_xfrm->send(this->socket_xfrm, hdr, &out, &len) == SUCCESS)
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
		DBG2(DBG_KNL, "unable to query policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
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
static status_t del_policy(private_kernel_netlink_ipsec_t *this,
						   traffic_selector_t *src_ts, 
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, bool unrouted)
{
	policy_entry_t *current, policy, *to_delete = NULL;
	route_entry_t *route;
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_userpolicy_id *policy_id;
	enumerator_t *enumerator;
	
	DBG2(DBG_KNL, "deleting policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);
	
	/* create a policy */
	memset(&policy, 0, sizeof(policy_entry_t));
	policy.sel = ts2selector(src_ts, dst_ts);
	policy.direction = direction;
	
	/* find the policy */
	this->mutex->lock(this->mutex);
	enumerator = this->policies->create_enumerator(this->policies);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (memeq(&current->sel, &policy.sel, sizeof(struct xfrm_selector)) &&
			policy.direction == current->direction)
		{
			to_delete = current;
			if (--to_delete->refcount > 0)
			{
				/* is used by more SAs, keep in kernel */
				DBG2(DBG_KNL, "policy still used by another CHILD_SA, not removed");
				this->mutex->unlock(this->mutex);
				enumerator->destroy(enumerator);
				return SUCCESS;
			}
			/* remove if last reference */
			this->policies->remove_at(this->policies, enumerator);
			break;
		}
	}
	this->mutex->unlock(this->mutex);
	enumerator->destroy(enumerator);
	if (!to_delete)
	{
		DBG1(DBG_KNL, "deleting policy %R === %R %N failed, not found", src_ts,
					   dst_ts, policy_dir_names, direction);
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
	
	if (this->socket_xfrm->send_ack(this->socket_xfrm, hdr) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
		return FAILED;
	}

	if (route)
	{
		if (charon->kernel_interface->del_route(charon->kernel_interface,
				route->dst_net, route->prefixlen, route->gateway,
				route->src_ip, route->if_name) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route installed with "
						  "policy %R === %R %N", src_ts, dst_ts,
						   policy_dir_names, direction);
		}		
		route_entry_destroy(route);
	}
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_kernel_netlink_ipsec_t *this)
{
	this->job->cancel(this->job);
	close(this->socket_xfrm_events);
	this->socket_xfrm->destroy(this->socket_xfrm);
	this->policies->destroy(this->policies);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Add bypass policies for IKE on the sockets used by charon
 */
static bool add_bypass_policies()
{
	int fd, family, port;
	enumerator_t *sockets;
	bool status = TRUE;
	
	/* we open an AF_KEY socket to autoload the af_key module. Otherwise
	 * setsockopt(IPSEC_POLICY) won't work. */
	fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd == 0)
	{
		DBG1(DBG_KNL, "could not open AF_KEY socket");
		return FALSE;
	}
	close(fd);
	
	sockets = charon->socket->create_enumerator(charon->socket);
	while (sockets->enumerate(sockets, &fd, &family, &port))
	{
		struct sadb_x_policy policy;
		u_int sol, ipsec_policy;
		
		switch (family)
		{
			case AF_INET:
				sol = SOL_IP;
				ipsec_policy = IP_IPSEC_POLICY;
				break;
			case AF_INET6:
				sol = SOL_IPV6;
				ipsec_policy = IPV6_IPSEC_POLICY;
				break;
			default:
				continue;
		}
		
		memset(&policy, 0, sizeof(policy));
		policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
		policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
		policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	
		policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
		if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
		{
			DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s",
				 strerror(errno));
			status = FALSE;
			break;
		}
		policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
		if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
		{
			DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s", 
				 strerror(errno));
			status = FALSE;
			break;
		}
	}
	sockets->destroy(sockets);
	return status;
}

/*
 * Described in header.
 */
kernel_netlink_ipsec_t *kernel_netlink_ipsec_create()
{
	private_kernel_netlink_ipsec_t *this = malloc_thing(private_kernel_netlink_ipsec_t);
	struct sockaddr_nl addr;
	
	/* public functions */
	this->public.interface.get_spi = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.interface.get_cpi = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,u_int32_t,u_int16_t*))get_cpi;
	this->public.interface.add_sa  = (status_t(*)(kernel_ipsec_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,u_int16_t,chunk_t,u_int16_t,chunk_t,ipsec_mode_t,u_int16_t,u_int16_t,bool,bool))add_sa;
	this->public.interface.update_sa = (status_t(*)(kernel_ipsec_t*,u_int32_t,protocol_id_t,u_int16_t,host_t*,host_t*,host_t*,host_t*,bool,bool))update_sa;
	this->public.interface.del_sa = (status_t(*)(kernel_ipsec_t*,host_t*,u_int32_t,protocol_id_t,u_int16_t))del_sa;
	this->public.interface.add_policy = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t,protocol_id_t,u_int32_t,ipsec_mode_t,u_int16_t,u_int16_t,bool))add_policy;
	this->public.interface.query_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.interface.del_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,bool))del_policy;
	this->public.interface.destroy = (void(*)(kernel_ipsec_t*)) destroy;

	/* private members */
	this->policies = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	this->install_routes = lib->settings->get_bool(lib->settings,
					"charon.install_routes", TRUE);
	
	/* add bypass policies on the sockets used by charon */
	if (!add_bypass_policies())
	{
		charon->kill(charon, "unable to add bypass policies on sockets");
	}
	
	this->socket_xfrm = netlink_socket_create(NETLINK_XFRM);
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	
	/* create and bind XFRM socket for ACQUIRE, EXPIRE, MIGRATE & MAPPING */
	this->socket_xfrm_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm_events <= 0)
	{
		charon->kill(charon, "unable to create XFRM event socket");
	}
	addr.nl_groups = XFRMNLGRP(ACQUIRE) | XFRMNLGRP(EXPIRE) |
					 XFRMNLGRP(MIGRATE) | XFRMNLGRP(MAPPING);
	if (bind(this->socket_xfrm_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM event socket");
	}
	
	this->job = callback_job_create((callback_job_cb_t)receive_events,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}
