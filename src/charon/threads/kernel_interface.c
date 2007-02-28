/**
 * @file kernel_interface.c
 *
 * @brief Implementation of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
 * Copyright (C) 2006-2007 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
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

typedef struct rt_refcount_t rt_refcount_t;

struct rt_refcount_t {
	/** Index of the interface the route is bound to */
	int if_index;

	/** Source ip of the route */
	host_t *src_ip;

	/** Destination net */
	chunk_t dst_net;

	/** Destination net prefixlen */
	u_int8_t prefixlen;
};

typedef struct kernel_policy_t kernel_policy_t;

/**
 * Installed kernel policy. 
 */
struct kernel_policy_t {
	
	/** direction of this policy: in, out, forward */
	u_int8_t direction;
	
	/** reqid of the policy */
	u_int32_t reqid;
	
	/** parameters of installed policy */
	struct xfrm_selector sel;
	
	/** associated route installed for this policy */
	rt_refcount_t *route;
	
	/** by how many CHILD_SA's this policy is used */
	u_int refcount;
};

typedef struct vip_refcount_t vip_refcount_t;

/**
 * Reference counter for for virtual ips.
 */
struct vip_refcount_t {
	/** Index of the interface the ip is bound to */
	u_int8_t if_index;
	
	/** The ip address */
	host_t *ip;
	
	/** Number of times this ip is used */
	u_int refcount;
};

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
	 * List of installed policies (kernel_policy_t)
	 */
	linked_list_t *policies;
	
	/**
	 * Mutex locks access to policies list.
	 */
	pthread_mutex_t pol_mutex;
	
	/**
	 * Netlink communication socket for XFRM IPsec.
	 */
	int xfrm_socket;

	/**
	 * Netlink communication socket for routing & addresses.
	 */
	int rt_socket;
	
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
	 * Thread which receives xfrm messages.
	 */
	pthread_t xfrm_thread;

	/**
	 * Thread which receives rt messages.
	 */
	pthread_t rt_thread;
	
	/**
	 * Mutex locks access to replies list.
	 */
	pthread_mutex_t rep_mutex;
	
	/**
	 * Condvar allows signaling of threads waiting for a reply.
	 */
	pthread_cond_t condvar;
	
	/**
	 * List of reference counter objects for all virtual ips.
	 */
	linked_list_t *vips;

	/**
	 * Mutex to lock access to vip list.
	 */
	pthread_mutex_t vip_mutex;
};

/**
 * Sends a message down to the kernel and waits for its response
 */
static status_t send_message(private_kernel_interface_t *this,
							 struct nlmsghdr *request,
							 struct nlmsghdr **response,
							 int socket)
{
	size_t length;
	struct sockaddr_nl addr;
	
	request->nlmsg_seq = ++this->seq;
	request->nlmsg_pid = getpid();
	
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;

	/*
	// set timeout to 10 secs
	struct timespec tm;
	tm.tv_sec = 10;
	 */
	
	length = sendto(socket,(void *)request, request->nlmsg_len, 0, 
					(struct sockaddr *)&addr, sizeof(addr));
	DBG2(DBG_IKE, "%d bytes sent to kernel", length);
	
	if (length < 0)
	{
		DBG1(DBG_IKE,"0 byte could be sent");
		return FAILED;
	}
	else if (length != request->nlmsg_len)
	{
		DBG1(DBG_IKE,"Request length %d does not match the sent bytes %d",
				request->nlmsg_len, length);
		return FAILED;
	}
	
	pthread_mutex_lock(&(this->rep_mutex));
	
	while (TRUE)
	{
		iterator_t *iterator;
		struct nlmsghdr *listed_response;
		bool found = FALSE;
		
		/* search list, break if found */
		iterator = this->responses->create_iterator(this->responses, TRUE);
		while (iterator->iterate(iterator, (void**)&listed_response))
		{
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
		//if(pthread_cond_timedwait(&(this->condvar), &(this->rep_mutex), &tm) == ETIMEDOUT)
		//	return FAILED;
		pthread_cond_wait(&(this->condvar), &(this->rep_mutex));
	}
	
	pthread_mutex_unlock(&(this->rep_mutex));
	
	return SUCCESS;
}

/**
 * Reads from a netlink socket and returns the message in a buffer.
 */
static void netlink_package_receiver(int socket, unsigned char *response, int response_size)
{
	while (TRUE)
	{
		struct sockaddr_nl addr;
		socklen_t addr_length;
		size_t length;
		addr_length = sizeof(addr);
		
		length = recvfrom(socket, response, response_size, 0, (struct sockaddr*)&addr, &addr_length);
		if (length < 0)
		{
			if (errno == EINTR)
			{
				/* interrupted, try again */
				continue;
			}
			charon->kill(charon, "receiving from netlink socket failed\n");
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
		return;
	}
}

/**
 * Takes a Netlink package from the response buffer and writes it to this->responses.
 * Then it signals all waiting threads.
 */
static void add_to_package_list(private_kernel_interface_t *this, unsigned char *response)
{
	struct nlmsghdr *hdr = (struct nlmsghdr*)response;
	/* add response to queue */
	struct nlmsghdr *listed_response = malloc(hdr->nlmsg_len);
	memcpy(listed_response, response, hdr->nlmsg_len);
	
	pthread_mutex_lock(&(this->rep_mutex));
	this->responses->insert_last(this->responses, (void*)listed_response);
	pthread_mutex_unlock(&(this->rep_mutex));
	/* signal ALL waiting threads */
	pthread_cond_broadcast(&(this->condvar));
}

/**
 * Receives packages from this->xfrm_socket and puts them to this->package_list
 */
static void receive_xfrm_messages(private_kernel_interface_t *this)
{
	while(TRUE) 
	{
		unsigned char response[BUFFER_SIZE];
		struct nlmsghdr *hdr;
		netlink_package_receiver(this->xfrm_socket, response, sizeof(response));
		
		/* we handle ACQUIRE and EXPIRE messages directly */
		hdr = (struct nlmsghdr*)response;
		if (hdr->nlmsg_type == XFRM_MSG_ACQUIRE)
		{
			u_int32_t reqid = 0;
			job_t *job;
			struct rtattr *rthdr = XFRM_RTA(hdr, struct xfrm_user_acquire);
			size_t rtsize = XFRM_PAYLOAD(hdr, struct xfrm_user_tmpl);
			if (RTA_OK(rthdr, rtsize))
			{
				if (rthdr->rta_type == XFRMA_TMPL)
				{
					struct xfrm_user_tmpl* tmpl = (struct xfrm_user_tmpl*)RTA_DATA(rthdr);
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
							  expire->hard ? "delete" : "rekey",
							  protocol_id_names, protocol, ntohl(spi),
							  reqid);
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
		/* NLMSG_ERROR is sent back for acknowledge (or on error).
		 * XFRM_MSG_NEWSA is returned when we alloc spis and when
		 * updating SAs.
		 * XFRM_MSG_NEWPOLICY is returned when we query a policy.
		 */
		else if (hdr->nlmsg_type == NLMSG_ERROR
					|| hdr->nlmsg_type == XFRM_MSG_NEWSA
					|| hdr->nlmsg_type == XFRM_MSG_NEWPOLICY)
		{
			add_to_package_list(this, response);
		}
		/* we are not interested in anything other.
		 * anyway, move on to the next message
		 */
		continue;
	}
}

/**
 * Receives packages from this->rt_socket and puts them to this->package_list
 */
static void receive_rt_messages(private_kernel_interface_t *this)
{
	while(TRUE)
	{
		unsigned char response[BUFFER_SIZE];
		struct nlmsghdr *hdr;
		netlink_package_receiver(this->rt_socket,response,BUFFER_SIZE);
		
		hdr = (struct nlmsghdr*)response;
		/* NLMSG_ERROR is sent back for acknowledge (or on error).
		 * RTM_NEWROUTE is returned when we add a route.
		 */
		if (hdr->nlmsg_type == NLMSG_ERROR ||
			hdr->nlmsg_type == RTM_NEWROUTE)
		{
			add_to_package_list(this, response);
		}
		/* we are not interested in anything other.
		 * anyway, move on to the next message.
		 */
		continue;
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
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_kernel_interface_t *this, 
						host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	struct nlmsghdr *hdr;
	struct xfrm_userspi_info *userspi;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	DBG2(DBG_KNL, "getting spi");
	
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
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type == NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_ALLOCSPI got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	else if (response->nlmsg_type != XFRM_MSG_NEWSA)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_ALLOCSPI got a unknown reply");
		status = FAILED;
	}
	else if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_ALLOCSPI got an invalid reply");
		status = FAILED;
	}
	else
	{
		*spi = ((struct xfrm_usersa_info*)NLMSG_DATA(response))->id.spi;
		DBG2(DBG_KNL, "SPI is 0x%x", *spi);
	}
	free(response);
	
	return status;
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
	struct nlmsghdr *response;
	char *alg_name;
	u_int key_size;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_info *sa;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	DBG2(DBG_KNL, "adding SA");

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
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_NEWSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_NEWSA got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

/**
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(
		private_kernel_interface_t *this,
		host_t *src, host_t *dst,
		host_t *new_src, host_t *new_dst, 
		host_diff_t src_changes, host_diff_t dst_changes,
		u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *update, *response;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	DBG2(DBG_KNL, "getting SA");

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (send_message(this, hdr, &update, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (update->nlmsg_type == NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETSA got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(update))->error));
		free(update);
		return FAILED;
	}
	else if (update->nlmsg_type != XFRM_MSG_NEWSA)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETSA got a unknown reply");
		free(update);
		return FAILED;
	}
	else if (update->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETSA got an invalid reply");
		free(update);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "updating SA");
	update->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;	
	update->nlmsg_type = XFRM_MSG_UPDSA;
	
	struct xfrm_usersa_info *sa = (struct xfrm_usersa_info*)NLMSG_DATA(update);
	if (src_changes & HOST_DIFF_ADDR)
	{
		host2xfrm(new_src, &sa->saddr);
	}

	if (dst_changes & HOST_DIFF_ADDR)
	{
		DBG2(DBG_KNL, "destination address changed! replacing SA");	
		
		update->nlmsg_type = XFRM_MSG_NEWSA;
		host2xfrm(new_dst, &sa->id.daddr);
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
	
	if (send_message(this, update, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		free(update);
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_XXXSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_XXXSA got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	else if (dst_changes & HOST_DIFF_ADDR)
	{
		DBG2(DBG_KNL, "deleting old SA");
		status = this->public.del_sa(&this->public, dst, spi, protocol);
	}
	
	free(update);
	free(response);
	return status;
}

/**
 * Implementation of kernel_interface_t.query_sa.
 */
static status_t query_sa(private_kernel_interface_t *this, host_t *dst,
						 u_int32_t spi, protocol_id_t protocol, u_int32_t *use_time)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_usersa_info *sa_info;
	
	DBG2(DBG_KNL, "querying SA");
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
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != XFRM_MSG_NEWSA)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETSA not acknowledged");
		free(response);
		return FAILED;
	}
	else if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETSA got an invalid reply");
		free(response);
		return FAILED;
	}
	
	sa_info = (struct xfrm_usersa_info*)NLMSG_DATA(response);
	*use_time = sa_info->curlft.use_time;
	
	free(response);
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.del_sa.
 */
static status_t del_sa(private_kernel_interface_t *this, host_t *dst,
					   u_int32_t spi, protocol_id_t protocol)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	struct nlmsghdr *hdr;
	struct xfrm_usersa_id *sa_id;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	DBG2(DBG_KNL, "deleting SA");
	
	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_type = XFRM_MSG_DELSA;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
	
	sa_id = (struct xfrm_usersa_id*)NLMSG_DATA(hdr);
	host2xfrm(dst, &sa_id->daddr);
	sa_id->spi = spi;
	sa_id->proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	sa_id->family = dst->get_family(dst);
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_DELSA not acknowledged");
		status = FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_DELSA got an error: %s",
						  strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		status = FAILED;
	}
	
	free(response);
	return status;
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
 * Tries to find an ip address of a local interface that is included in the
 * supplied traffic selector.
 */
static status_t find_addr_by_ts(traffic_selector_t *ts, host_t **ip)
{
	host_t *try = NULL;

#ifdef HAVE_GETIFADDRS
	struct ifaddrs *list;
	struct ifaddrs *cur;

	if (getifaddrs(&list) < 0)
	{
		return FAILED;
	}

	for (cur = list; cur != NULL; cur = cur->ifa_next)
	{
		if (!(cur->ifa_flags & IFF_UP) || !cur->ifa_addr)
		{
			/* ignore interfaces which are down or have no address assigned */
			continue;
		}

		try = host_create_from_sockaddr(cur->ifa_addr);

		if (try && ts->includes(ts, try))
		{
			if (ip)
			{
				*ip = try;
			}
			freeifaddrs(list);
			return SUCCESS;
		}

		DESTROY_IF(try);
	}
	freeifaddrs(list);
	return FAILED;
#else /* !HAVE_GETIFADDRS */

	/* only IPv4 supported yet */
	if (ts->get_type != TS_IPV4_ADDR_RANGE)
	{
		return FAILED;
	}

	int skt = socket(PF_INET, SOCK_DGRAM, 0);
	struct ifconf conf;
	struct ifreq reqs[16];

	conf.ifc_len = sizeof(reqs);
	conf.ifc_req = reqs;

	if (ioctl(skt, SIOCGIFCONF, &conf) == -1)
	{
		DBG1(DBG_NET, "checking address using ioctl() failed: %m");
		close(skt);
		return FAILED;
	}
	close(skt);

	while (conf.ifc_len >= sizeof(struct ifreq))
	{
		/* only IPv4 supported yet */
		if (conf.ifc_req->ifr_addr.sa_family != AF_INET)
		{
			continue;
		}

		try = host_create_from_sockaddr(conf.ifc_req->ifr_addr);

		if (try && ts->includes(ts, try))
		{
			if (ip)
			{
				*ip = try;
			}
			
			return SUCCESS;
		}

		DESTROY_IF(try);

		conf.ifc_len -= sizeof(struct ifreq);
		conf.ifc_req++;
	}
	return FAILED;
#endif /* HAVE_GETIFADDRS */
}

/**
 * forward declarations
 */
static status_t manage_srcroute(private_kernel_interface_t*,int,int,rt_refcount_t*);
static int get_iface(private_kernel_interface_t*,host_t*);
static void rt_refcount_destroy(rt_refcount_t*);

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
	kernel_policy_t *current, *policy;
	bool found = FALSE;
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	struct xfrm_userpolicy_info *policy_info;
	struct nlmsghdr *hdr;
	
	/* create a policy */
	policy = malloc_thing(kernel_policy_t);
	memset(policy, 0, sizeof(kernel_policy_t));
	policy->sel = ts2selector(src_ts, dst_ts);
	policy->direction = direction;
	
	/* find the policy, which matches EXACTLY */
	pthread_mutex_lock(&this->pol_mutex);
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
				DBG2(DBG_KNL, "policy already exists, increasing refcount");
				if (!high_prio)
				{
					/* if added policy is for a ROUTED child_sa, do not
					 * overwrite existing INSTALLED policy */
					iterator->destroy(iterator);
					pthread_mutex_unlock(&this->pol_mutex);
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
	
	DBG2(DBG_KNL, "adding policy");
	
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
	pthread_mutex_unlock(&this->pol_mutex);
	
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
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_UPDPOLICY not acknowledged");
		free(response);
		return FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_UPDPOLICY got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		free(response);
		return FAILED;
	}
	
	
	if (direction == POLICY_FWD)
	{
		policy->route = malloc_thing(rt_refcount_t);
		if (find_addr_by_ts(dst_ts, &policy->route->src_ip) == SUCCESS)
		{
			policy->route->if_index = get_iface(this, src);
			policy->route->dst_net = chunk_alloc(policy->sel.family == AF_INET ? 4 : 16);
			memcpy(policy->route->dst_net.ptr, &policy->sel.saddr, policy->route->dst_net.len);
			policy->route->prefixlen = policy->sel.prefixlen_s;
			
			if (manage_srcroute(this, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
								policy->route) != SUCCESS)
			{
				DBG1(DBG_KNL, "error installing route");
				rt_refcount_destroy(policy->route);
				policy->route = NULL;
			}
		}
		else
		{
			free(policy->route);
			policy->route = NULL;
		}
	}

	free(response);
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
	struct nlmsghdr *response;
	struct nlmsghdr *hdr;
	struct xfrm_userpolicy_id *policy_id;
	struct xfrm_userpolicy_info *policy;
	
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	DBG2(DBG_KNL, "querying policy");

	hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = XFRM_MSG_GETPOLICY;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));

	policy_id = (struct xfrm_userpolicy_id*)NLMSG_DATA(hdr);
	policy_id->sel = ts2selector(src_ts, dst_ts);
	policy_id->dir = direction;

	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type == NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETPOLICY got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		free(response);
		return FAILED;
	}
	else if (response->nlmsg_type != XFRM_MSG_NEWPOLICY)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETPOLICY got an unknown reply");
		free(response);
		return FAILED;
	}
	else if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info)))
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_GETPOLICY got an invalid reply");
		free(response);
		return FAILED;
	}

	policy = (struct xfrm_userpolicy_info*)NLMSG_DATA(response);

	*use_time = (time_t)policy->curlft.use_time;
	
	free(response);
	return status;
}

/**
 * Implementation of kernel_interface_t.del_policy.
 */
static status_t del_policy(private_kernel_interface_t *this,
						   traffic_selector_t *src_ts, 
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction)
{
	kernel_policy_t *current, policy, *to_delete = NULL;
	rt_refcount_t *route;
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *response;
	struct nlmsghdr *hdr;
	struct xfrm_userpolicy_id *policy_id;
	iterator_t *iterator;
	
	DBG2(DBG_KNL, "deleting policy");
	
	/* create a policy */
	memset(&policy, 0, sizeof(kernel_policy_t));
	policy.sel = ts2selector(src_ts, dst_ts);
	policy.direction = direction;
	
	/* find the policy */
	pthread_mutex_lock(&this->pol_mutex);
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
				DBG2(DBG_KNL, "is used by other SAs, not removed");
				iterator->destroy(iterator);
				pthread_mutex_unlock(&this->pol_mutex);
				return SUCCESS;
			}
			/* remove if last reference */
			iterator->remove(iterator);
			break;
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&this->pol_mutex);
	if (!to_delete)
	{
		DBG1(DBG_KNL, "no such policy found");
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
	
	if (send_message(this, hdr, &response, this->xfrm_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (response->nlmsg_type != NLMSG_ERROR)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_DELPOLICY not acknowledged");
		free(response);
		return FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request XFRM_MSG_DELPOLICY got an error: %s",
			 strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error));
		free(response);
		return FAILED;
	}

	if (route)
	{
		if (manage_srcroute(this, RTM_DELROUTE, 0, route) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route");
		}		
		rt_refcount_destroy(route);
	}
	
	free(response);
	return SUCCESS;
}

/**
 * Sends an RT_NETLINK request to the kernel. 
 */
static status_t send_rtrequest(private_kernel_interface_t *this, struct nlmsghdr *hdr)
{
	struct nlmsghdr *response;

	if (send_message(this, hdr, &response, this->rt_socket) != SUCCESS)
	{
		DBG1(DBG_KNL, "netlink communication failed");
		return FAILED;
	}
	else if (((struct nlmsgerr*)NLMSG_DATA(response))->error)
	{
		DBG1(DBG_KNL, "netlink request got an error: %s (%d)",
			strerror(-((struct nlmsgerr*)NLMSG_DATA(response))->error),
			-((struct nlmsgerr*)NLMSG_DATA(response))->error);
		free(response);
		return FAILED;
	}

	free(response);
	return SUCCESS;
}

/**
 * Creates an rtattr and adds it to the netlink message.
 */
static status_t add_rtattr(struct nlmsghdr *hdr, int max_len,
					int rta_type, void *data, int data_len)
{
	struct rtattr *rta;
	
	if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(data_len) > max_len)
	{
		DBG1(DBG_KNL, "netlink message exceeded bound of %d", max_len);
		return FAILED;
	}
	
	rta = (struct rtattr*)(((char*)hdr) + NLMSG_ALIGN(hdr->nlmsg_len));

	rta->rta_type = rta_type;
	rta->rta_len = RTA_LENGTH(data_len);
	memcpy(RTA_DATA(rta), data, data_len);
	
	hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + rta->rta_len;
	return SUCCESS;
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

	DBG2(DBG_KNL, "adding virtual IP %H to interface %d", ip, if_index);
	
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
	
	if (add_rtattr(hdr, sizeof(request), IFA_LOCAL,
				   chunk.ptr, chunk.len) != SUCCESS)
	{
		return FAILED;
	}

	return send_rtrequest(this, hdr);
}

static int get_iface(private_kernel_interface_t *this, host_t* ip)
{
	unsigned char request[BUFFER_SIZE];
	struct nlmsghdr *hdr;
	struct rtmsg *msg;
	struct rtattr* rta;
	chunk_t chunk;
	int ifindex = 0;

	DBG2(DBG_KNL, "getting interface for %H", ip);
	
	memset(&request, 0, sizeof(request));
	
	chunk = ip->get_address(ip);
    
    hdr = (struct nlmsghdr*)request;
	hdr->nlmsg_flags = NLM_F_REQUEST;
	hdr->nlmsg_type = RTM_GETROUTE; 
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	
	msg = (struct rtmsg*)NLMSG_DATA(hdr);
	msg->rtm_family = ip->get_family(ip);
	msg->rtm_table = 0;
	msg->rtm_protocol = 0;
	msg->rtm_scope = 0;
	msg->rtm_type = 0;
	msg->rtm_src_len = 0;
	msg->rtm_dst_len = 8 * chunk.len;
	msg->rtm_tos = 0;
	msg->rtm_flags = RT_TABLE_UNSPEC | RTPROT_UNSPEC;

	if (add_rtattr(hdr, sizeof(request), RTA_DST,
				   chunk.ptr, chunk.len) != SUCCESS)
	{
		return 0;
	}

	if(send_message(this, hdr, &hdr, this->rt_socket) != SUCCESS)
	{
		return 0;
	}
	rta = (struct rtattr*)(NLMSG_DATA(hdr) + NLMSG_LENGTH(sizeof(struct rtmsg)));

	while(RTA_OK(rta, hdr->nlmsg_len))
	{
		if(rta->rta_type == RTA_OIF)
		{
			ifindex = *((int*)RTA_DATA(rta));
			break;
		}
		rta = RTA_NEXT(rta, hdr->nlmsg_len);
	}
	free(hdr);
	if (ifindex == 0)
	{
		DBG1(DBG_KNL, "address %H not reachable, unable to get interface", ip);
	}
	return ifindex;
}

/**
 * Manages source routes in the routing table.
 * By setting the appropriate nlmsg_type, the route will be set or unset.
 */
static status_t manage_srcroute(private_kernel_interface_t *this,
					int nlmsg_type, int flags, rt_refcount_t *route)
{
	struct nlmsghdr *hdr;
	struct rtmsg *msg;
	unsigned char request[BUFFER_SIZE];
	chunk_t src;
	
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

	src = route->src_ip->get_address(route->src_ip);

	if (add_rtattr(hdr, sizeof(request), RTA_DST,
				   route->dst_net.ptr, route->dst_net.len) != SUCCESS)
	{
		return FAILED;
	}

	if (add_rtattr(hdr, sizeof(request), RTA_PREFSRC,
				   src.ptr, src.len) != SUCCESS)
	{
		return FAILED;
	}

	if (add_rtattr(hdr, sizeof(request), RTA_OIF,
				   &route->if_index, sizeof(route->if_index)) != SUCCESS)
	{
		return FAILED;
	}

	return send_rtrequest(this, hdr);
}

/**
 * destroy an rt_refcount object
 */
static void rt_refcount_destroy(rt_refcount_t *this)
{
	this->src_ip->destroy(this->src_ip);
	chunk_free(&this->dst_net);
	free(this);
}

/**
 * destroy a vip_refcount object
 */
static void vip_refcount_destroy(vip_refcount_t *this)
{
	this->ip->destroy(this->ip);
	free(this);
}

/**
 * Implementation of kernel_interface_t.add_ip.
 */
static status_t add_ip(private_kernel_interface_t *this, 
						host_t *virtual_ip, host_t *dst_ip)
{
	int targetif;
	vip_refcount_t *listed;
	iterator_t *iterator;

	DBG2(DBG_KNL, "adding ip addr: %H", virtual_ip);

	targetif = get_iface(this, dst_ip);
	if (targetif == 0)
	{
		return FAILED;
	}

	/* beware of deadlocks (e.g. send/receive packets while holding the lock) */
	iterator = this->vips->create_iterator_locked(this->vips, &(this->vip_mutex));
	while (iterator->iterate(iterator, (void**)&listed))
	{
		if (listed->if_index == targetif &&
			virtual_ip->ip_equals(virtual_ip, listed->ip))
		{
			listed->refcount++;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);

	if (manage_ipaddr(this, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL,
				targetif, virtual_ip) == SUCCESS)
	{
		listed = malloc_thing(vip_refcount_t);
		listed->ip = virtual_ip->clone(virtual_ip);
		listed->if_index = targetif;
		listed->refcount = 1;
		this->vips->insert_last(this->vips, listed);
		return SUCCESS;
	}
	
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.del_ip.
 */
static status_t del_ip(private_kernel_interface_t *this,
						host_t *virtual_ip, host_t *dst_ip)
{
	int targetif;
	vip_refcount_t *listed;
	iterator_t *iterator;

	DBG2(DBG_KNL, "deleting ip addr: %H", virtual_ip);

	targetif = get_iface(this, dst_ip);
	if (targetif == 0)
	{
		return FAILED;
	}

	/* beware of deadlocks (e.g. send/receive packets while holding the lock) */
	iterator = this->vips->create_iterator_locked(this->vips, &(this->vip_mutex));
	while (iterator->iterate(iterator, (void**)&listed))
	{
		if (listed->if_index == targetif &&
			virtual_ip->ip_equals(virtual_ip, listed->ip))
		{
			listed->refcount--;
			if (listed->refcount == 0)
			{
				iterator->remove(iterator);
				vip_refcount_destroy(listed);
				iterator->destroy(iterator);
				return manage_ipaddr(this, RTM_DELADDR, 0, targetif, virtual_ip);
			}
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
 
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_kernel_interface_t *this)
{
	pthread_cancel(this->xfrm_thread);
	pthread_join(this->xfrm_thread, NULL);
	pthread_cancel(this->rt_thread);
	pthread_join(this->rt_thread, NULL);
	close(this->xfrm_socket);
	close(this->rt_socket);
	this->vips->destroy_function(this->vips, (void*)vip_refcount_destroy);
	this->responses->destroy(this->responses);
	this->policies->destroy(this->policies);
	free(this);
}

/*
 * Described in header.
 */
kernel_interface_t *kernel_interface_create()
{
	struct sockaddr_nl addr_xfrm;
	struct sockaddr_nl addr_rt;
	private_kernel_interface_t *this = malloc_thing(private_kernel_interface_t);
	
	/* public functions */
	this->public.get_spi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,algorithm_t*,algorithm_t*,prf_plus_t*,natt_conf_t*,mode_t,bool))add_sa;
	this->public.update_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t,host_t*,host_t*,host_diff_t,host_diff_t))update_sa;
	this->public.query_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t*))query_sa;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,protocol_id_t,u_int32_t,bool,mode_t,bool))add_policy;
	this->public.query_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.del_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t))del_policy;
	this->public.add_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) add_ip;
	this->public.del_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) del_ip;
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->pid = getpid();
	this->responses = linked_list_create();
	this->vips = linked_list_create();
	this->policies = linked_list_create();
	pthread_mutex_init(&(this->rep_mutex),NULL);
	pthread_mutex_init(&(this->pol_mutex),NULL);
	pthread_mutex_init(&(this->vip_mutex),NULL);
	pthread_cond_init(&(this->condvar),NULL);
	this->seq = 0;
	
	/* open xfrm netlink socket */
	this->xfrm_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->xfrm_socket <= 0)
	{
		DBG1(DBG_KNL, "Unable to create xfrm netlink socket");
		goto kill;
	}
	
	/* bind the xfrm socket and reqister for ACQUIRE & EXPIRE */
	addr_xfrm.nl_family = AF_NETLINK;
	addr_xfrm.nl_pid = getpid();
	addr_xfrm.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(this->xfrm_socket, (struct sockaddr*)&addr_xfrm, sizeof(addr_xfrm)))
	{
		DBG1(DBG_KNL, "Unable to bind xfrm netlink socket");
		goto kill_xfrm;
	}
	
	if (pthread_create(&this->xfrm_thread, NULL,
					   (void*(*)(void*))receive_xfrm_messages, this))
	{
		DBG1(DBG_KNL, "Unable to create xfrm netlink thread");
		goto kill_xfrm;
	}

	/* open rt netlink socket */
	this->rt_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (this->rt_socket <= 0)
	{
		DBG1(DBG_KNL, "Unable to create rt netlink socket");
		goto kill_xfrm_all;
	}

	/* bind the socket_rt */
	addr_rt.nl_family = AF_NETLINK;
	addr_rt.nl_pid = getpid();
	addr_rt.nl_groups = 0;
	if (bind(this->rt_socket, (struct sockaddr*)&addr_rt, sizeof(addr_rt)))
	{
		DBG1(DBG_KNL, "Unable to bind rt netlink socket");
		goto kill_rt;
	}
	
	if (pthread_create(&this->rt_thread, NULL, 
					   (void*(*)(void*))receive_rt_messages, this))
	{
		DBG1(DBG_KNL, "Unable to create rt netlink thread");
		goto kill_rt;
	}

	return &this->public;

kill_rt:
	close(this->rt_socket);
kill_xfrm_all:
	pthread_cancel(this->xfrm_thread);
	pthread_join(this->xfrm_thread, NULL);
kill_xfrm:
	close(this->xfrm_socket);
kill:
	this->responses->destroy(this->responses);
	this->policies->destroy(this->policies);
	this->vips->destroy(this->vips);
	free(this);
	charon->kill(charon, "Unable to create kernel_interface");
	return NULL;
}

/* vim: set ts=4 sw=4 noet: */

