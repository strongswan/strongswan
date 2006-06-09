/**
 * @file kernel_interface.c
 *
 * @brief Implementation of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#define XFRM_DATA_LENGTH 1024


typedef struct xfrm_data_t xfrm_data_t;

/**
 * Lenght/Type/data struct for userdata in xfrm
 * We dont use the "I-don't-know-where-they-come-from"-structs
 * used in the kernel.
 */
struct xfrm_data_t {
	/**
	 * length of the data
	 */
	u_int16_t length;
	
	/**
	 * type of data 
	 */
	u_int16_t type;
	
	/**
	 * and the data itself, for different purposes
	 */
	union {
		/** algorithm */
		struct xfrm_algo algo;
		/** policy tmpl */
		struct xfrm_user_tmpl tmpl[2];
	};
};


typedef struct netlink_message_t netlink_message_t;

/**
 * Representation of ANY netlink message used
 */
struct netlink_message_t {
	
	/**
	 * header of the netlink message 
	 */
	struct nlmsghdr hdr;

	union {
		/** error message */
		struct nlmsgerr e;
		/** message for spi allocation */
		struct xfrm_userspi_info spi;
		/** message for SA manipulation */
		struct xfrm_usersa_id sa_id;
		/** message for SA installation */
		struct xfrm_usersa_info sa;
		/** message for policy manipulation */
		struct xfrm_userpolicy_id policy_id;
		/** message for policy installation */
		struct xfrm_userpolicy_info policy;
		/** expire message sent from kernel */
		struct xfrm_user_expire expire;
	};
	u_int8_t data[XFRM_DATA_LENGTH];
};

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
	status_t (*send_message) (private_kernel_interface_t *this, netlink_message_t *request, netlink_message_t **response);
};

/**
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_kernel_interface_t *this, 
						host_t *src, host_t *dest, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	netlink_message_t request, *response;
	status_t status = SUCCESS;
	
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "getting spi");
	
	memset(&request, 0, sizeof(request));
	request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.spi)));
	request.hdr.nlmsg_flags = NLM_F_REQUEST;
	request.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
	request.spi.info.saddr = src->get_xfrm_addr(src);
	request.spi.info.id.daddr = dest->get_xfrm_addr(dest);
	request.spi.info.mode = TRUE; /* tunnel mode */
	request.spi.info.reqid = reqid;
	request.spi.info.id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	request.spi.info.family = PF_INET;
	request.spi.min = 0xc0000000;
	request.spi.max = 0xcFFFFFFF;
	
	if (this->send_message(this, &request, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->hdr.nlmsg_type == NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got an error: %s",
						  strerror(-response->e.error));
		status = FAILED;
	}
	else if (response->hdr.nlmsg_type != XFRM_MSG_NEWSA)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got a unknown reply");
		status = FAILED;
	}
	else if (response->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(response->sa)))
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_ALLOCSPI got an invalid reply");
		status = FAILED;
	}
	else
	{
		*spi = response->sa.id.spi;
	}
	free(response);
	
	return status;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(	private_kernel_interface_t *this,
						host_t *me,
						host_t *other,
						u_int32_t spi,
						int protocol,
						u_int32_t reqid,
						u_int64_t expire_soft,
						u_int64_t expire_hard,
						algorithm_t *enc_alg,
						algorithm_t *int_alg,
						prf_plus_t *prf_plus,
						bool replace)
{
	netlink_message_t request, *response;
	status_t status = SUCCESS;
	int key_size;
	char *alg_name;
	
	memset(&request, 0, sizeof(request));
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "adding SA");
	
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request.hdr.nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
	
	request.sa.saddr = me->get_xfrm_addr(me);
	request.sa.id.daddr = other->get_xfrm_addr(other);
	
	request.sa.id.spi = spi;
	request.sa.id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	request.sa.family = me->get_family(me);
	request.sa.mode = TRUE; /* tunnel mode */
	request.sa.replay_window = 32;
	request.sa.reqid = reqid;
	/* we currently do not expire SAs by volume/packet count */
	request.sa.lft.soft_byte_limit = XFRM_INF;
	request.sa.lft.hard_byte_limit = XFRM_INF;
	request.sa.lft.soft_packet_limit = XFRM_INF;
	request.sa.lft.hard_packet_limit = XFRM_INF;
	/* we use lifetimes since added, not since used */
	request.sa.lft.soft_add_expires_seconds = expire_soft;
	request.sa.lft.hard_add_expires_seconds = expire_hard;
	request.sa.lft.soft_use_expires_seconds = 0;
	request.sa.lft.hard_use_expires_seconds = 0;
	
	request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.sa)));
	
	if (enc_alg->algorithm != ENCR_UNDEFINED)
	{
		xfrm_data_t *data = (xfrm_data_t*)(((u_int8_t*)&request) + request.hdr.nlmsg_len);
		
		data->type = XFRMA_ALG_CRYPT;
		alg_name = lookup_algorithm(encryption_algs, enc_alg, &key_size);
		if (alg_name == NULL)
		{
			this->logger->log(this->logger, ERROR, "Algorithm %s not supported by kernel!", 
							  mapping_find(encryption_algorithm_m, enc_alg->algorithm));
			return FAILED;
		}
		this->logger->log(this->logger, CONTROL|LEVEL2, "using key size %d", key_size);
		data->length = 4 + sizeof(data->algo) + key_size;
		data->algo.alg_key_len = key_size;
		request.hdr.nlmsg_len += data->length;
		if (request.hdr.nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		strcpy(data->algo.alg_name, alg_name);
		prf_plus->get_bytes(prf_plus, key_size / 8, data->algo.alg_key);
	}
	
	if (int_alg->algorithm  != AUTH_UNDEFINED)
	{
		xfrm_data_t *data = (xfrm_data_t*)(((u_int8_t*)&request) + request.hdr.nlmsg_len);
		
		data->type = XFRMA_ALG_AUTH;
		alg_name = lookup_algorithm(integrity_algs, int_alg, &key_size);
		if (alg_name == NULL)
		{
			this->logger->log(this->logger, ERROR, "Algorithm %s not supported by kernel!", 
							  mapping_find(integrity_algorithm_m, int_alg->algorithm));
			return FAILED;
		}
		this->logger->log(this->logger, CONTROL|LEVEL2, "using key size %d", key_size);
		data->length = 4 + sizeof(data->algo) + key_size;
		data->algo.alg_key_len = key_size;
		request.hdr.nlmsg_len += data->length;
		if (request.hdr.nlmsg_len > sizeof(request))
		{
			return FAILED;
		}
		strcpy(data->algo.alg_name, alg_name);
		prf_plus->get_bytes(prf_plus, key_size / 8, data->algo.alg_key);
	}
	
	/* TODO: add IPComp here*/
	
	if (this->send_message(this, &request, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->hdr.nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWSA not acknowledged");
		status = FAILED;
	}
	else if (response->e.error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWSA received error: %s",
						  strerror(-response->e.error));
		status = FAILED;
	}
	
	free(response);
	return status;
}

static status_t del_sa(	private_kernel_interface_t *this,
						host_t *dst,
						u_int32_t spi,
						protocol_id_t protocol)
{
	netlink_message_t request, *response;
	memset(&request, 0, sizeof(request));
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "deleting SA");
	
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request.hdr.nlmsg_type = XFRM_MSG_DELSA;
	
	request.sa_id.daddr = dst->get_xfrm_addr(dst);
	
	request.sa_id.spi = spi;
	request.sa_id.proto = (protocol == PROTO_ESP) ? KERNEL_ESP : KERNEL_AH;
	request.sa_id.family = dst->get_family(dst);
	
	request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.sa_id)));
	
	if (this->send_message(this, &request, &response) != SUCCESS)
	{
		return FAILED;
	}
	else if (response->hdr.nlmsg_type != NLMSG_ERROR)
	{
		status = FAILED;
	}
	else if (response->e.error)
	{
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
						  bool ah, bool esp,
						  u_int32_t reqid)
{
	netlink_message_t request, *response;
	status_t status = SUCCESS;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "adding policy");
	
	memset(&request, 0, sizeof(request));
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	request.policy.sel.sport = htons(src->get_port(src));
	request.policy.sel.dport = htons(dst->get_port(dst));
	request.policy.sel.sport_mask = (request.policy.sel.sport) ? ~0 : 0;
	request.policy.sel.dport_mask = (request.policy.sel.dport) ? ~0 : 0;
	request.policy.sel.saddr = src->get_xfrm_addr(src);
	request.policy.sel.daddr = dst->get_xfrm_addr(dst);
	request.policy.sel.prefixlen_s = src_hostbits;
	request.policy.sel.prefixlen_d = dst_hostbits;
	request.policy.sel.proto = upper_proto;
	request.policy.sel.family = src->get_family(src);

	request.hdr.nlmsg_type = XFRM_MSG_UPDPOLICY;
	request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.policy)));
	request.policy.dir = direction;
	request.policy.priority = SPD_PRIORITY;
	request.policy.action = XFRM_POLICY_ALLOW;
	request.policy.share = XFRM_SHARE_ANY;
	
	/* policies currently don't expire */
	request.policy.lft.soft_byte_limit = XFRM_INF;
	request.policy.lft.soft_packet_limit = XFRM_INF;
	request.policy.lft.hard_byte_limit = XFRM_INF;
	request.policy.lft.hard_packet_limit = XFRM_INF;
	request.sa.lft.soft_add_expires_seconds = 0;
	request.sa.lft.hard_add_expires_seconds = 0;
	request.sa.lft.soft_use_expires_seconds = 0;
	request.sa.lft.hard_use_expires_seconds = 0;
	
	if (esp || ah)
	{
		xfrm_data_t *data;
		int tmpl_pos = 0;
		data = (xfrm_data_t*)(((u_int8_t*)&request) + request.hdr.nlmsg_len);
		data->type = XFRMA_TMPL;
		if (esp)
		{
			data->tmpl[tmpl_pos].reqid = reqid;
			data->tmpl[tmpl_pos].id.proto = KERNEL_ESP;
			data->tmpl[tmpl_pos].aalgos = data->tmpl[tmpl_pos].ealgos = data->tmpl[tmpl_pos].calgos = ~0;
			data->tmpl[tmpl_pos].mode = TRUE;
			
			data->tmpl[tmpl_pos].saddr = me->get_xfrm_addr(me);
			data->tmpl[tmpl_pos].id.daddr = me->get_xfrm_addr(other);
			
			tmpl_pos++;
		}	
		if (ah)
		{
			data->tmpl[tmpl_pos].reqid = reqid;
			data->tmpl[tmpl_pos].id.proto = KERNEL_AH;
			data->tmpl[tmpl_pos].aalgos = data->tmpl[tmpl_pos].ealgos = data->tmpl[tmpl_pos].calgos = ~0;
			data->tmpl[tmpl_pos].mode = TRUE;
			
			data->tmpl[tmpl_pos].saddr = me->get_xfrm_addr(me);
			data->tmpl[tmpl_pos].id.daddr = other->get_xfrm_addr(other);
			
			tmpl_pos++;
		}
		data->length = 4 + sizeof(struct xfrm_user_tmpl) * tmpl_pos;
		request.hdr.nlmsg_len += data->length;
	}
	
	if (this->send_message(this, &request, &response) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "netlink communication failed");
		return FAILED;
	}
	else if (response->hdr.nlmsg_type != NLMSG_ERROR)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWPOLICY not acknowledged");
		status = FAILED;
	}
	else if (response->e.error)
	{
		this->logger->log(this->logger, ERROR, "netlink request XFRM_MSG_NEWPOLICY received error: %s",
						  strerror(-response->e.error));
		status = FAILED;
	}
	
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
	netlink_message_t request, *response;
	status_t status = SUCCESS;
	
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "deleting policy");
	
	memset(&request, 0, sizeof(request));
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	request.policy_id.sel.sport = htons(src->get_port(src));
	request.policy_id.sel.dport = htons(dst->get_port(dst));
	request.policy_id.sel.sport_mask = (request.policy.sel.sport) ? ~0 : 0;
	request.policy_id.sel.dport_mask = (request.policy.sel.dport) ? ~0 : 0;
	request.policy_id.sel.saddr = src->get_xfrm_addr(src);
	request.policy_id.sel.daddr = dst->get_xfrm_addr(dst);
	request.policy_id.sel.prefixlen_s = src_hostbits;
	request.policy_id.sel.prefixlen_d = dst_hostbits;
	request.policy_id.sel.proto = upper_proto;
	request.policy_id.sel.family = src->get_family(src);
	
	request.policy_id.dir = direction;

	request.hdr.nlmsg_type = XFRM_MSG_DELPOLICY;
	request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.policy_id)));
	
	if (this->send_message(this, &request, &response) != SUCCESS)
	{
		return FAILED;
	}
	else if (response->hdr.nlmsg_type != NLMSG_ERROR)
	{
		status = FAILED;
	}
	else if (response->e.error)
	{
		status = FAILED;
	}
	
	free(response);
	return status;
}

/**
 * Implementation of private_kernel_interface_t.send_message.
 */
static status_t send_message(private_kernel_interface_t *this, netlink_message_t *request, netlink_message_t **response)
{
	size_t length;
	struct sockaddr_nl addr;
	
	request->hdr.nlmsg_seq = ++this->seq;
	request->hdr.nlmsg_pid = this->pid;
	
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;
	
	length = sendto(this->socket,(void *)request, request->hdr.nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr));
	
	if (length < 0)
	{
		return FAILED;
	}
	else if (length != request->hdr.nlmsg_len)
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
			netlink_message_t *listed_response;
			iterator->current(iterator, (void**)&listed_response);
			if (listed_response->hdr.nlmsg_seq == request->hdr.nlmsg_seq)
			{
				/* matches our request, this is the reply */
				*response = listed_response;
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
		netlink_message_t response, *listed_response;
		while (TRUE)
		{
			struct sockaddr_nl addr;
			socklen_t addr_length;
			size_t length;
			
			addr_length = sizeof(addr);
			
			response.hdr.nlmsg_type = XFRM_MSG_NEWSA;
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
			if (!NLMSG_OK(&response.hdr, length))
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
		if (response.hdr.nlmsg_type == XFRM_MSG_ACQUIRE)
		{
			this->logger->log(this->logger, CONTROL,
							  "Received a XFRM_MSG_ACQUIRE. Ignored");
		}
		else if (response.hdr.nlmsg_type == XFRM_MSG_EXPIRE)
		{
			job_t *job;
			this->logger->log(this->logger, CONTROL|LEVEL1,
							  "Received a XFRM_MSG_EXPIRE");
			if (response.expire.hard)
			{
				this->logger->log(this->logger, CONTROL|LEVEL0,
								  "creating delete job for CHILD_SA with reqid %d",
								  response.expire.state.reqid);
				job = (job_t*)delete_child_sa_job_create(
						response.expire.state.reqid);
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL0,
								  "creating rekey job for CHILD_SA with reqid %d",
								  response.expire.state.reqid);
				job = (job_t*)rekey_child_sa_job_create(
						response.expire.state.reqid);
			}
			charon->job_queue->add(charon->job_queue, job);
		}
		/* NLMSG_ERROR is send back for acknowledge (or on error), an
		 * XFRM_MSG_NEWSA is returned when we alloc spis.
		 * list these responses for the sender
		 */
		else if (response.hdr.nlmsg_type == NLMSG_ERROR ||
				 response.hdr.nlmsg_type == XFRM_MSG_NEWSA)
		{
			/* add response to queue */
			listed_response = malloc(sizeof(response));
			memcpy(listed_response, &response, sizeof(response));
			
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
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,algorithm_t*,algorithm_t*,prf_plus_t*,bool))add_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*, host_t*,host_t*,host_t*,u_int8_t,u_int8_t,int,int,bool,bool,u_int32_t))add_policy;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,u_int32_t,protocol_id_t))del_sa;
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
