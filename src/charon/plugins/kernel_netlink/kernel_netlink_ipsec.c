/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kernel_netlink_ipsec.h"
#include "kernel_netlink_shared.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/acquire_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/delete_child_sa_job.h>
#include <processing/jobs/update_sa_job.h>

/** required for Linux 2.6.26 kernel and later */
#ifndef XFRM_STATE_AF_UNSPEC
#define XFRM_STATE_AF_UNSPEC	32
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
	pthread_mutex_t mutex;
	
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
 * process a XFRM_MSG_ACQUIRE from kernel
 */
static void process_acquire(private_kernel_netlink_ipsec_t *this, struct nlmsghdr *hdr)
{
	u_int32_t reqid = 0;
	int proto = 0;
	job_t *job;
	struct rtattr *rtattr = XFRM_RTA(hdr, struct xfrm_user_acquire);
	size_t rtsize = XFRM_PAYLOAD(hdr, struct xfrm_user_tmpl);
	
	if (RTA_OK(rtattr, rtsize))
	{
		if (rtattr->rta_type == XFRMA_TMPL)
		{
			struct xfrm_user_tmpl* tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rtattr);
			reqid = tmpl->reqid;
			proto = tmpl->id.proto;
		}
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
	if (reqid == 0)
	{
		DBG1(DBG_KNL, "received a XFRM_MSG_ACQUIRE, but no reqid found");
		return;
	}
	DBG2(DBG_KNL, "received a XFRM_MSG_ACQUIRE");
	DBG1(DBG_KNL, "creating acquire job for CHILD_SA with reqid {%d}", reqid);
	job = (job_t*)acquire_job_create(reqid);
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
		DBG2(DBG_KNL, "ignoring XFRM_MSG_EXPIRE for SA with SPI %.8x and reqid {%d} "
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
				"reqid {%d} changed, queuing update job", ntohl(spi), reqid);
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
	DBG2(DBG_KNL, "getting SPI for reqid {%d}", reqid);
	
	if (get_spi_internal(this, src, dst, proto_ike2kernel(protocol),
			0xc0000000, 0xcFFFFFFF, reqid, spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get SPI for reqid {%d}", reqid);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "got SPI %.8x for reqid {%d}", ntohl(*spi), reqid);
	
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

	DBG2(DBG_KNL, "getting CPI for reqid {%d}", reqid);
	
	if (get_spi_internal(this, src, dst,
			IPPROTO_COMP, 0x100, 0xEFFF, reqid, &received_spi) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to get CPI for reqid {%d}", reqid);
		return FAILED;
	}
	
	*cpi = htons((u_int16_t)ntohl(received_spi));
	
	DBG2(DBG_KNL, "got CPI %.4x for reqid {%d}", ntohs(*cpi), reqid);
	
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_kernel_netlink_ipsec_t *this,
					   host_t *src, host_t *dst, u_int32_t spi,
					   protocol_id_t protocol, u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   u_int16_t enc_alg, u_int16_t enc_size,
					   u_int16_t int_alg, u_int16_t int_size,
					   prf_plus_t *prf_plus, ipsec_mode_t mode,
					   u_int16_t ipcomp, bool encap,
					   bool replace)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	char *alg_name;
	/* additional 4 octets KEYMAT required for AES-GCM as of RFC4106 8.1. */
	u_int16_t add_keymat = 32; 
	struct nlmsghdr *hdr;
	struct xfrm_usersa_info *sa;
	
	memset(&request, 0, sizeof(request));
	
	DBG2(DBG_KNL, "adding SAD entry with SPI %.8x and reqid {%d}", ntohl(spi), reqid);

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
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
		if (rta->rta_type == XFRMA_REPLAY_VAL)
		{
			memcpy(replay, RTA_DATA(rta), rta->rta_len);
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
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(private_kernel_netlink_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst, bool encap)
{
	unsigned char request[NETLINK_BUFFER_SIZE], *pos;
	struct nlmsghdr *hdr, *out = NULL;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *out_sa = NULL, *sa;
	size_t len;
	struct rtattr *rta;
	size_t rtasize;
	struct xfrm_encap_tmpl* tmpl = NULL;
	bool got_replay_state;
	struct xfrm_replay_state replay;
	
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
	got_replay_state = (get_replay_state(
						this, spi, protocol, dst, &replay) == SUCCESS);
	
	/* delete the old SA */
	if (this->public.interface.del_sa(&this->public.interface, dst, spi, protocol) != SUCCESS)
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
 * Implementation of kernel_interface_t.del_sa.
 */
static status_t del_sa(private_kernel_netlink_ipsec_t *this, host_t *dst,
					   u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	
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
 * Implementation of kernel_interface_t.add_policy.
 */
static status_t add_policy(private_kernel_netlink_ipsec_t *this, 
						   host_t *src, host_t *dst,
						   traffic_selector_t *src_ts,
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, protocol_id_t protocol,
						   u_int32_t reqid, bool high_prio, ipsec_mode_t mode,
						   u_int16_t ipcomp)
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
	pthread_mutex_lock(&this->mutex);
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
			
			switch (charon->kernel_interface->add_route(charon->kernel_interface,
					route->dst_net, route->prefixlen, route->gateway,
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
						   policy_dir_t direction)
{
	policy_entry_t *current, policy, *to_delete = NULL;
	route_entry_t *route;
	unsigned char request[NETLINK_BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct xfrm_userpolicy_id *policy_id;
	iterator_t *iterator;
	
	DBG2(DBG_KNL, "deleting policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);
	
	/* create a policy */
	memset(&policy, 0, sizeof(policy_entry_t));
	policy.sel = ts2selector(src_ts, dst_ts);
	policy.direction = direction;
	
	/* find the policy */
	iterator = this->policies->create_iterator_locked(this->policies, &this->mutex);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (memeq(&current->sel, &policy.sel, sizeof(struct xfrm_selector)) &&
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
	free(this);
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
	this->public.interface.add_sa  = (status_t(*)(kernel_ipsec_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,u_int16_t,u_int16_t,u_int16_t,u_int16_t,prf_plus_t*,ipsec_mode_t,u_int16_t,bool,bool))add_sa;
	this->public.interface.update_sa = (status_t(*)(kernel_ipsec_t*,u_int32_t,protocol_id_t,host_t*,host_t*,host_t*,host_t*,bool))update_sa;
	this->public.interface.del_sa = (status_t(*)(kernel_ipsec_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
	this->public.interface.add_policy = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,protocol_id_t,u_int32_t,bool,ipsec_mode_t,u_int16_t))add_policy;
	this->public.interface.query_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.interface.del_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t))del_policy;
	this->public.interface.destroy = (void(*)(kernel_ipsec_t*)) destroy;

	/* private members */
	this->policies = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	this->install_routes = lib->settings->get_bool(lib->settings,
					"charon.install_routes", TRUE);
	
	this->socket_xfrm = netlink_socket_create(NETLINK_XFRM);
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	
	/* create and bind XFRM socket for ACQUIRE & EXPIRE */
	this->socket_xfrm_events = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket_xfrm_events <= 0)
	{
		charon->kill(charon, "unable to create XFRM event socket");
	}
	addr.nl_groups = XFRMNLGRP(ACQUIRE) | XFRMNLGRP(EXPIRE) | XFRMNLGRP(MAPPING);
	if (bind(this->socket_xfrm_events, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind XFRM event socket");
	}
	
	this->job = callback_job_create((callback_job_cb_t)receive_events,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}
