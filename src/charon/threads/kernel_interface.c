/**
 * @file kernel_interface.c
 *
 * @brief Implementation of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2003 Herbert Xu.
 * 
 * Contains modified parts from pluto.
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
#include <linux/udp.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "kernel_interface.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <queues/jobs/delete_child_sa_job.h>
#include <queues/jobs/rekey_child_sa_job.h>


#define KERNEL_ESP 50
#define KERNEL_AH 51

#define SPD_PRIORITY 1024

#define BUFFER_SIZE 1024

/* returns a pointer to the first rtattr following the nlmsghdr *nlh and the 'usual' netlink data x like 'struct xfrm_usersa_info' */
#define XFRM_RTA(nlh, x) ((struct rtattr*)(NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(x))))
/* returns a pointer to the next rtattr following rta.
 * !!! do not use this to parse messages. use RTA_NEXT and RTA_OK instead !!! */
#define XFRM_RTA_NEXT(rta) ((struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
/* returns the total size of attached rta data (after 'usual' netlink data x like 'struct xfrm_usersa_info') */
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
	{AUTH_HMAC_MD5_96, 	"md5",			128},
	{AUTH_HMAC_SHA1_96,	"sha1",			160},
/*	{AUTH_DES_MAC,		"***",			0}, */
/*	{AUTH_KPDK_MD5,		"***",			0}, */
/*	{AUTH_AES_XCBC_96,	"***",			0}, */
	{END_OF_LIST, 		NULL,			0},
};

/**
 * Look up a kernel algorithm name and its key size
 */
char* lookup_algorithm(kernel_algorithm_t *kernel_algo, algorithm_t *ikev2_algo, u_int *key_size)
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

typedef struct private_kernel_interface_t private_kernel_interface_t;

 /**
 * @brief Private Variables and Functions of kernel_interface class.
 *
 */
struct private_kernel_interface_t {
	/**
	 * Public part of the kernel_interface_t object.
	 */
	kernel_interface_t public;
	
	/**
	 * Netlink communication socket.
	 */
	int socket;
	
	/**
	 * Process id of kernel thread
	 */
	pid_t pid;
	
	/**
	 * Sequence number for messages.
	 */
	u_int32_t seq;
	
	/** 
	 * List of responded messages.
	 */
	linked_list_t *responses;
	
	/**
	 * Thread which receives messages.
	 */
	pthread_t thread;
	
	/**
	 * Mutex locks access to replies list.
	 */
	pthread_mutex_t mutex;
	
	/**
	 * Condvar allows signaling of threads waiting for a reply.
	 */
	pthread_cond_t condvar;
	
	/**
	 * Logger for XFRM stuff
	 */
	logger_t *logger;
	
	/**
	 * Function for the thread, receives messages.
	 */
	void (*receive_messages) (private_kernel_interface_t *this);
	
	/**
	 * Sends a netlink_message_t down to the kernel and wait for reply.
	 */
	status_t (*send_message) (private_kernel_interface_t *this, struct nlmsghdr *request, struct nlmsghdr **response);
};

/**
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_kernel_interface_t *this, 
						host_t *src, host_t *dest, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;

	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "getting spi");
	
	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_ALLOCSPI;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userspi_info));

	struct xfrm_userspi_info *userspi = (struct xfrm_userspi_info*)NLMSG_DATA(hdr);
	userspi->info.saddr = src->get_xfrm_addr(src);
	userspi->info.id.daddr = dest->get_xfrm_addr(dest);
	userspi->info.id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	userspi->info.mode = TRUE; /* tunnel mode */
	userspi->info.reqid = reqid;
	userspi->info.family = src->get_family(src);
	userspi->min = 0xc0000000;
	userspi->max = 0xcFFFFFFF;
	
	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type == NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	else if (response->nlmsg_type != XFRM_MSG_NEWSA)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got a unknown reply");
		status = FAILED;
	}
	else if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got an invalid reply");
		status = FAILED;
	}
	else
	{
		*spi = ((struct xfrm_usersa_info*)NLMSG_DATA(response))->id.spi;
		this->logger->log(this->logger, CONTROL|LEVEL1, "SPI is 0x%x", *spi);
	}
	free(response);
	
	return status;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_kernel_interface_t *this,
					   host_t *me, host_t *other,
					   u_int32_t spi, protocol_id_t protocol,
					   u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   algorithm_t *enc_alg, algorithm_t *int_alg,
					   prf_plus_t *prf_plus, natt_conf_t *natt,
					   bool replace)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	char *alg_name;
	size_t key_size;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "adding SA");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	
	struct xfrm_usersa_info *sa = (struct xfrm_usersa_info*)NLMSG_DATA(hdr);
	sa->saddr = me->get_xfrm_addr(me);
	sa->id.daddr = other->get_xfrm_addr(other);
	
	sa->id.spi = spi;
	sa->id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa->family = me->get_family(me);
	sa->mode = TRUE; /* tunnel mode */
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
			this->logger->log(this->logger, ERROR, "Algorithm %s not supported by kernel!", 
							  mapping_find(encryption_algorithm_m, enc_alg->algorithm));
			return FAILED;
		}
		this->logger->log(this->logger, CONTROL|LEVEL2, "  using encryption algorithm %s with key size %d",
						  mapping_find(encryption_algorithm_m, enc_alg->algorithm), key_size);
		
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
			this->logger->log(this->logger, ERROR, "Algorithm %s not supported by kernel!", 
							  mapping_find(integrity_algorithm_m, int_alg->algorithm));
			return FAILED;
		}
		this->logger->log(this->logger, CONTROL|LEVEL2, "  using integrity algorithm %s with key size %d",
						  mapping_find(integrity_algorithm_m, int_alg->algorithm), key_size);
		
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
		encap->encap_sport = ntohs(natt->sport);
		encap->encap_dport = ntohs(natt->dport);
		memset(&encap->encap_oa, 0, sizeof (xfrm_address_t));
		/* encap_oa could probably be derived from the 
		 * traffic selectors [rfc4306, p39]. In the netlink kernel implementation 
		 * pluto does the same as we do here but it uses encap_oa in the 
		 * pfkey implementation. BUT as /usr/src/linux/net/key/af_key.c indicates 
		 * the kernel ignores it anyway
		 *   -> does that mean that NAT-T encap doesn't work in transport mode?
		 * No. The reason the kernel ignores NAT-OA is that it recomputes 
		 * (or, rather, just ignores) the checksum. If packets pass
		 * the IPSec checks it marks them "checksum ok" so OA isn't needed. */
		
		rthdr = XFRM_RTA_NEXT(rthdr);
	}

	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWSA got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

static status_t update_sa_hosts(
		private_kernel_interface_t *this,
		host_t *src, host_t *dst,
		host_t *new_src, host_t *new_dst, 
		int src_changes, int dst_changes,
		u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *update, *response;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "getting SA");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	struct xfrm_usersa_id *sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	sa_id->daddr = dst->get_xfrm_addr(dst);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);

	if (this->send_message(this, hdr, &update) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (update->nlmsg_type == NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETSA got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(update))->error));
		free(update);
		return FAILED;
	}
	else if (update->nlmsg_type != XFRM_MSG_NEWSA)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETSA got a unknown reply");
		free(update);
		return FAILED;
	}
	else if (update->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETSA got an invalid reply");
		free(update);
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "updating SA");
	update->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;	
	update->nlmsg_type = XFRM_MSG_UPDSA;
	
	struct xfrm_usersa_info *sa = (struct xfrm_usersa_info*)NLMSG_DATA(update);
	if (src_changes & HOST_DIFF_ADDR)
	{
		sa->saddr = new_src->get_xfrm_addr(new_src);
	}

	if (dst_changes & HOST_DIFF_ADDR)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "destination address changed! replacing SA");	
		
		update->nlmsg_type = XFRM_MSG_NEWSA;
		sa->id.daddr = new_dst->get_xfrm_addr(new_dst);		
	}
	
	if (src_changes & HOST_DIFF_PORT || dst_changes & HOST_DIFF_PORT)
	{
		struct rtattr *rthdr = XFRM_RTA(update, struct xfrm_usersa_info);
		size_t rtsize = XFRM_PAYLOAD(update, struct xfrm_usersa_info);
		while (RTA_OK(rthdr, rtsize))
		{
			if (rthdr->rta_type == XFRMA_ENCAP)
			{
				struct xfrm_encap_tmpl* encap = (struct xfrm_encap_tmpl*)RTA_DATA(rthdr);
				encap->encap_sport = ntohs(new_src->get_port(new_src));
				encap->encap_dport = ntohs(new_dst->get_port(new_dst));
				break;
			}
			rthdr = RTA_NEXT(rthdr, rtsize);
		}
	}
	
	if (this->send_message(this, update, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		free(update);
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_XXXSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_XXXSA got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	else if (dst_changes & HOST_DIFF_ADDR)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "deleting old SA");
		status = this->public.del_sa(&this->public, dst, spi, protocol);
	}

	free(update);
	free(response);
	return status;
}
	
static status_t del_sa(	private_kernel_interface_t *this,
						host_t *dst,
						u_int32_t spi,
						protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "deleting SA");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	struct xfrm_usersa_id *sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	sa_id->daddr = dst->get_xfrm_addr(dst);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_DELSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_DELSA got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

/**
 * Implementation of kernel_interface_t.add_policy.
 */
static status_t add_policy(private_kernel_interface_t *this, 
						  host_t *me, host_t *other, 
						  host_t *src, host_t *dst,
						  u_int8_t src_hostbits, u_int8_t dst_hostbits,
						  int direction, int upper_proto,
						  protocol_id_t protocol,
						  u_int32_t reqid)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "adding policy");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_UPDPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));

	struct xfrm_userpolicy_info *policy = (struct xfrm_userpolicy_info*)NLMSG_DATA(hdr);
	
	policy->sel.sport = htons(src->get_port(src));
	policy->sel.sport_mask = (policy->sel.sport) ? ~0 : 0;
	policy->sel.saddr = src->get_xfrm_addr(src);
	policy->sel.prefixlen_s = src_hostbits;
	
	policy->sel.dport = htons(dst->get_port(dst));
	policy->sel.dport_mask = (policy->sel.dport) ? ~0 : 0;
	policy->sel.daddr = dst->get_xfrm_addr(dst);
	policy->sel.prefixlen_d = dst_hostbits;
	
	policy->sel.proto = upper_proto;
	policy->sel.family = src->get_family(src);
	
	policy->dir = direction;
	policy->priority = SPD_PRIORITY;
	policy->action = XFRM_POLICY_ALLOW;
	policy->share = XFRM_SHARE_ANY;
	
	/* policies currently don't expire */
	policy->lft.soft_byte_limit = XFRM_INF;
	policy->lft.soft_packet_limit = XFRM_INF;
	policy->lft.hard_byte_limit = XFRM_INF;
	policy->lft.hard_packet_limit = XFRM_INF;
	policy->lft.soft_add_expires_seconds = 0;
	policy->lft.hard_add_expires_seconds = 0;
	policy->lft.soft_use_expires_seconds = 0;
	policy->lft.hard_use_expires_seconds = 0;
	
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
	tmpl->id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
	tmpl->mode = TRUE;
	
	tmpl->saddr = me->get_xfrm_addr(me);
	tmpl->id.daddr = other->get_xfrm_addr(other);
	
	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWPOLICY not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWPOLICY got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

static status_t query_policy(private_kernel_interface_t *this,
					host_t *me, host_t *other, 
					host_t *src, host_t *dst,
					u_int8_t src_hostbits, u_int8_t dst_hostbits,
					int direction, int upper_proto,
					time_t *use_time)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "querying policy");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	struct xfrm_userpolicy_id *policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel.sport = htons(src->get_port(src));
	policy_id->sel.sport_mask = (policy_id->sel.sport) ? ~0 : 0;
	policy_id->sel.saddr = src->get_xfrm_addr(src);
	policy_id->sel.prefixlen_s = src_hostbits;
	
	policy_id->sel.dport = htons(dst->get_port(dst));
	policy_id->sel.dport_mask = (policy_id->sel.dport) ? ~0 : 0;
	policy_id->sel.daddr = dst->get_xfrm_addr(dst);
	policy_id->sel.prefixlen_d = dst_hostbits;
	
	policy_id->sel.proto = upper_proto;
	policy_id->sel.family = src->get_family(src);
	
	policy_id->dir = direction;

	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type == NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETPOLICY got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		free(response);
		return FAILED;
	}
	else if (response->nlmsg_type != XFRM_MSG_NEWPOLICY)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETPOLICY got an unknown reply");
		free(response);
		return FAILED;
	}
	else if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info)))
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_GETPOLICY got an invalid reply");
		free(response);
		return FAILED;
	}

	struct xfrm_userpolicy_info *policy = (struct xfrm_userpolicy_info*)NLMSG_DATA(response);

	*use_time = (time_t)policy->curlft.use_time;
	
	free(response);
	return status;
}

/**
 * Implementation of kernel_interface_t.del_policy.
 */
static status_t del_policy(private_kernel_interface_t *this, 
						   host_t *me, host_t *other, 
						   host_t *src, host_t *dst,
						   u_int8_t src_hostbits, u_int8_t dst_hostbits,
						   int direction, int upper_proto)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "deleting policy");

	struct nlmsghdr *hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	struct xfrm_userpolicy_id *policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel.sport = htons(src->get_port(src));
	policy_id->sel.sport_mask = (policy_id->sel.sport) ? ~0 : 0;
	policy_id->sel.saddr = src->get_xfrm_addr(src);
	policy_id->sel.prefixlen_s = src_hostbits;
	
	policy_id->sel.dport = htons(dst->get_port(dst));
	policy_id->sel.dport_mask = (policy_id->sel.dport) ? ~0 : 0;
	policy_id->sel.daddr = dst->get_xfrm_addr(dst);
	policy_id->sel.prefixlen_d = dst_hostbits;
	
	policy_id->sel.proto = upper_proto;
	policy_id->sel.family = src->get_family(src);
	
	policy_id->dir = direction;

	if (this->send_message(this, hdr, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_DELPOLICY not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_DELPOLICY got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

/**
 * Implementation of private_kernel_interface_t.send_message.
 */
static status_t send_message(private_kernel_interface_t *this, struct nlmsghdr *request, struct nlmsghdr **response)
{
	size_t length;
	struct sockaddr_nl addr;
	
	request->nlmsg_seq = ++this->seq;
	request->nlmsg_pid = 0;
	
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;
	
	length = sendto(this->socket,(void *)request, request->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr));
	
	if (length < 0)
	{
		return FAILED;
	}
	else if (length != request->nlmsg_len)
	{
		return FAILED;
	}
	
	pthread_mutex_lock(&(this->mutex));
	
	while (TRUE)
	{
		iterator_t *iterator; 
		bool found = FALSE;
		/* search list, break if found */
		iterator = this->responses->create_iterator(this->responses, TRUE);
		while (iterator->has_next(iterator))
		{
			struct nlmsghdr *listed_response;
			iterator->current(iterator, (void**)&listed_response);
			if (listed_response->nlmsg_seq == request->nlmsg_seq)
			{
				/* matches our request, this is the reply */
				*response = listed_response;
				iterator->remove(iterator);
				found = TRUE;
				break;
			}
		}
		iterator->destroy(iterator);
		
		if (found)
		{
			break;
		}
		/* TODO: we should time out, if something goes wrong!??? */
		pthread_cond_wait(&(this->condvar), &(this->mutex));
	}
	
	pthread_mutex_unlock(&(this->mutex));
	
	return SUCCESS;
}

/**
 * Implementation of private_kernel_interface_t.receive_messages.
 */
static void receive_messages(private_kernel_interface_t *this)
{
	while(TRUE) 
	{
		unsigned char response[BUFFER_SIZE];
		struct nlmsghdr *hdr, *listed_response;
		while (TRUE)
		{
			struct sockaddr_nl addr;
			socklen_t addr_length;
			size_t length;
			
			addr_length = sizeof(addr);
			
			length = recvfrom(this->socket, &response, sizeof(response), 0, (struct sockaddr*)&addr, &addr_length);
			if (length < 0)
			{
				if (errno == EINTR)
				{
					/* interrupted, try again */
					continue;
				}
				charon->kill(charon, "receiving from netlink socket failed");
			}
			if (!NLMSG_OK((struct nlmsghdr *)response, length))
			{
				/* bad netlink message */
				continue;
			}
			if (addr.nl_pid != 0)
			{
				/* not from kernel. not interested, try another one */
				continue;
			}
			/* good message, handle it */
			break;
		}
		
		/* we handle ACQUIRE and EXPIRE messages directly
		 */
		hdr = (struct nlmsghdr*)response;
		if (hdr->nlmsg_type == XFRM_MSG_ACQUIRE)
		{
			this->logger->log(this->logger, CONTROL,
							  "Received a XFRM_MSG_ACQUIRE. Ignored");
		}
		else if (hdr->nlmsg_type == XFRM_MSG_EXPIRE)
		{
			job_t *job;
			protocol_id_t protocol;
			u_int32_t spi;
			struct xfrm_user_expire *expire;
			
			expire = (struct xfrm_user_expire*)NLMSG_DATA(hdr);
			protocol = expire->state.id.proto == KERNEL_ESP ?
						PROTO_ESP : PROTO_AH;
			spi = expire->state.id.spi;
			
			this->logger->log(this->logger, CONTROL|LEVEL1,
							  "Received a XFRM_MSG_EXPIRE");
			this->logger->log(this->logger, CONTROL,
							  "creating %s job for %s CHILD_SA 0x%x",
							  expire->hard ? "delete" : "rekey",
							  mapping_find(protocol_id_m, protocol), ntohl(spi));
			if (expire->hard)
			{
				job = (job_t*)delete_child_sa_job_create(protocol, spi);
			}
			else
			{
				job = (job_t*)rekey_child_sa_job_create(protocol, spi);
			}
			charon->job_queue->add(charon->job_queue, job);
		}
		/* NLMSG_ERROR is sent back for acknowledge (or on error), an
		 * XFRM_MSG_NEWSA is returned when we alloc spis and when
		 * updating SAs.
		 * XFRM_MSG_NEWPOLICY is returned when we query a policy.
		 * list these responses for the sender
		 */
		else if (hdr->nlmsg_type == NLMSG_ERROR ||
			 hdr->nlmsg_type == XFRM_MSG_NEWSA ||
			 hdr->nlmsg_type == XFRM_MSG_NEWPOLICY)
		{
			/* add response to queue */
			listed_response = malloc(hdr->nlmsg_len);
			memcpy(listed_response, &response, hdr->nlmsg_len);
			
			pthread_mutex_lock(&(this->mutex));
			this->responses->insert_last(this->responses, (void*)listed_response);
			pthread_mutex_unlock(&(this->mutex));
			/* signal ALL waiting threads */
			pthread_cond_broadcast(&(this->condvar));
		}
		/* we are not interested in anything other.
		 * anyway, move on to the next message */
		continue;
	}
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_kernel_interface_t *this)
{	
	pthread_cancel(this->thread);
	pthread_join(this->thread, NULL);
	close(this->socket);
	this->responses->destroy(this->responses);
	free(this);
}

/*
 * Described in header.
 */
kernel_interface_t *kernel_interface_create()
{
	struct sockaddr_nl addr;
	private_kernel_interface_t *this = malloc_thing(private_kernel_interface_t);
	
	/* public functions */
	this->public.get_spi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,algorithm_t*,algorithm_t*,prf_plus_t*,natt_conf_t*,bool))add_sa;
	this->public.update_sa_hosts = (status_t(*)(kernel_interface_t*,host_t*,host_t*,host_t*,host_t*,int,int,u_int32_t,protocol_id_t))update_sa_hosts;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*, host_t*,host_t*,host_t*,u_int8_t,u_int8_t,int,int,protocol_id_t,u_int32_t))add_policy;
	this->public.query_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,host_t*,host_t*,u_int8_t,u_int8_t,int,int,time_t*))query_policy;
	this->public.del_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,host_t*,host_t*,u_int8_t,u_int8_t,int,int))del_policy;
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->receive_messages = receive_messages;
	this->send_message = send_message;
	this->pid = getpid();
	this->responses = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, XFRM);
	pthread_mutex_init(&(this->mutex),NULL);
	pthread_cond_init(&(this->condvar),NULL);
	this->seq = 0;
	
	/* open netlink socket */
	this->socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket <= 0)
	{
		this->responses->destroy(this->responses);
		free(this);
		charon->kill(charon, "Unable to create netlink socket");	
	}
	
	/* bind the socket and reqister for ACQUIRE & EXPIRE */
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		this->responses->destroy(this->responses);
		close(this->socket);
		free(this);
		charon->kill(charon, "Unable to bind netlink socket");	
	}
	
	if (pthread_create(&(this->thread), NULL, (void*(*)(void*))this->receive_messages, this) != 0)
	{
		this->responses->destroy(this->responses);
		close(this->socket);
		free(this);
		charon->kill(charon, "Unable to create netlink thread");
	}
	
	return (&this->public);
}
