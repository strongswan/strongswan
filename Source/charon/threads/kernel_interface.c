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
#include <linux/xfrm.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "kernel_interface.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>


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
		struct nlmsgerr e;
		struct xfrm_userspi_info spi;			    
		struct {
			struct xfrm_usersa_info sa;
			u_int8_t data[512];
		};
	};
};

typedef struct netlink_algo_t netlink_algo_t;

/**
 * Add length and type to xfrm_algo
 */
struct netlink_algo_t {
	u_int16_t length;
	u_int16_t type;
	struct xfrm_algo algo;
};

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
 	 * Function for the thread, receives messages.
 	 */
 	void (*receive_messages) (private_kernel_interface_t *this);
 	
 	/**
 	 * Sends a netlink_message_t down to the kernel and wait for reply.
 	 */
 	status_t (*send_message) (private_kernel_interface_t *this, netlink_message_t *request, netlink_message_t **response);
};

mapping_t kernel_encryption_algs_m[] = {
	{ENCR_DES_IV64, ""},
	{ENCR_DES, "des"},
	{ENCR_3DES, "des3_ede"},
	{ENCR_RC5, ""},
	{ENCR_IDEA, "idea"},
	{ENCR_CAST, "cast128"},
	{ENCR_BLOWFISH, "blowfish"},
	{ENCR_3IDEA, ""},
	{ENCR_DES_IV32, ""},
	{ENCR_NULL, ""},
	{ENCR_AES_CBC, "aes"},
	{ENCR_AES_CTR, ""},
	{MAPPING_END, NULL}
};

mapping_t kernel_integrity_algs_m[] = {
	{AUTH_HMAC_MD5_96, "md5"},
	{AUTH_HMAC_SHA1_96, "sha1"},
	{AUTH_DES_MAC, ""},
	{AUTH_KPDK_MD5, ""},
	{AUTH_AES_XCBC_96, ""},
	{MAPPING_END, NULL}
};


static status_t get_spi(private_kernel_interface_t *this, host_t *src, host_t *dest, protocol_id_t protocol, bool tunnel_mode, u_int32_t *spi)
{
	netlink_message_t request, *response;
	
    memset(&request, 0, sizeof(request));
    request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.spi)));
    request.hdr.nlmsg_flags = NLM_F_REQUEST;
    request.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
	request.spi.info.saddr = src->get_xfrm_addr(src);
	request.spi.info.id.daddr = dest->get_xfrm_addr(dest);
    request.spi.info.mode = tunnel_mode;
    request.spi.info.id.proto = protocol;
    request.spi.info.family = PF_INET;
    request.spi.min = 100;
    request.spi.max = 200;

   	if (this->send_message(this, &request, &response) != SUCCESS)
   	{
   		return FAILED;
   	}
    
    if (response->hdr.nlmsg_type == NLMSG_ERROR)
    {
    	return FAILED;
    }
    
    if (response->hdr.nlmsg_type != XFRM_MSG_NEWSA)
    {
    	return FAILED;
    }
    else if (response->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(response->sa)))
    {
		return FAILED;
    }
	
	*spi = response->sa.id.spi;
	allocator_free(response);

    return SUCCESS;
}

static status_t add_sa(	private_kernel_interface_t *this,
						host_t *me, 
						host_t *other, 
						u_int32_t spi, 
						int protocol, 
						bool tunnel_mode,
						encryption_algorithm_t enc_alg,
						size_t enc_size,
						chunk_t enc_key,
						integrity_algorithm_t int_alg,
						size_t int_size,
						chunk_t int_key,
						bool replace)
{
    netlink_message_t request, *response;
	POS;
    memset(&request, 0, sizeof(request));
    
    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.hdr.nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;

    request.sa.saddr = me->get_xfrm_addr(me);
    request.sa.id.daddr = other->get_xfrm_addr(other);

    request.sa.id.spi = spi;
    request.sa.id.proto = protocol;
    request.sa.family = me->get_family(me);
    request.sa.mode = tunnel_mode;
    request.sa.replay_window = 0; //sa->replay_window; ???
    request.sa.reqid = 0; //sa->reqid; ???
    request.sa.lft.soft_byte_limit = XFRM_INF;
    request.sa.lft.soft_packet_limit = XFRM_INF;
    request.sa.lft.hard_byte_limit = XFRM_INF;
    request.sa.lft.hard_packet_limit = XFRM_INF;

    request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.sa)));

    if (enc_alg != ENCR_UNDEFINED)
    {
		netlink_algo_t *nla = (netlink_algo_t*)(((u_int8_t*)&request) + request.hdr.nlmsg_len);
    	
    	nla->type = XFRMA_ALG_CRYPT;
    	nla->length = sizeof(netlink_algo_t) + enc_size;
		nla->algo.alg_key_len = enc_size * 8;
		
		strcpy(nla->algo.alg_name, mapping_find(kernel_encryption_algs_m, enc_alg));
		memcpy(nla->algo.alg_key, enc_key.ptr, enc_key.len);

		request.hdr.nlmsg_len += nla->length;
    }

    if (int_alg != AUTH_UNDEFINED)
    {
		netlink_algo_t *nla = (netlink_algo_t*)(((u_int8_t*)&request) + request.hdr.nlmsg_len);
		
		nla->type = XFRMA_ALG_AUTH;
    	nla->length = sizeof(netlink_algo_t) + int_size;
		nla->algo.alg_key_len = int_size * 8;
		strcpy(nla->algo.alg_name, mapping_find(kernel_integrity_algs_m, int_alg));
		memcpy(nla->algo.alg_key, int_key.ptr, int_key.len);

		request.hdr.nlmsg_len += nla->length;
    }
    
	/* add IPComp */
    
    if (this->send_message(this, &request, &response) != SUCCESS)
    {
    	allocator_free(response);
    	return FAILED;	
    }
	
    allocator_free(response);
    return SUCCESS;
}


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
		/* we should time out, if something goes wrong */
		pthread_cond_wait(&(this->condvar), &(this->mutex));
	}
	
	pthread_mutex_unlock(&(this->mutex));
	
	return SUCCESS;
}


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
			break;
		}
		
		/* got a valid message.
		 * requests are handled on our own, 
		 * responses are listed for the requesters
		 */
		if (response.hdr.nlmsg_flags & NLM_F_REQUEST)
		{
			/* handle request */	
		}
		else
		{
			/* add response to queue */			
			listed_response = allocator_alloc(sizeof(response));
			memcpy(listed_response, &response, sizeof(response));

			pthread_mutex_lock(&(this->mutex));
			this->responses->insert_last(this->responses, (void*)listed_response);
			pthread_mutex_unlock(&(this->mutex));
			/* signal ALL waiting threads */
			pthread_cond_broadcast(&(this->condvar));
		}
		/* get the next one */
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
	allocator_free(this);
}

/*
 * Described in header.
 */
kernel_interface_t *kernel_interface_create()
{
	private_kernel_interface_t *this = allocator_alloc_thing(private_kernel_interface_t);
	
	/* public functions */
	this->public.get_spi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,protocol_id_t,bool,u_int32_t*))get_spi;
	
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,int,bool,encryption_algorithm_t,size_t,chunk_t,integrity_algorithm_t,size_t,chunk_t,bool))add_sa;
	
	
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->receive_messages = receive_messages;
	this->send_message = send_message;
	this->pid = getpid();
	this->responses = linked_list_create();
	pthread_mutex_init(&(this->mutex),NULL);
	pthread_cond_init(&(this->condvar),NULL);
	this->seq = 0;
	this->socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (this->socket <= 0)
	{
		allocator_free(this);
		charon->kill(charon, "Unable to create netlink socket");	
	}
	
	if (pthread_create(&(this->thread), NULL, (void*(*)(void*))this->receive_messages, this) != 0)
	{
		close(this->socket);
		allocator_free(this);
		charon->kill(charon, "Unable to create netlink thread");
	}
	
	charon->logger_manager->enable_logger_level(charon->logger_manager, TESTER, FULL);
	return (&this->public);
}
