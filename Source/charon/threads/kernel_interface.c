/**
 * @file kernel_interface.c
 *
 * @brief Implementation of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <pthread.h>

#include "kernel_interface.h"

#include <utils/allocator.h>
#include <utils/linked_list.h>
#include <network/host.h>
#include <encoding/payloads/proposal_substructure.h>


typedef struct netlink_message_t netlink_message_t;

struct netlink_message_t {
	
	/**
	 * header of the netlink message 
	 */
	struct nlmsghdr hdr;

	union {
		struct nlmsgerr e;
		struct xfrm_userspi_info spi;			    
		struct xfrm_usersa_info sa;
	};
	
	u_int8_t data[];
};


typedef struct private_kernel_interface_t private_kernel_interface_t;

 /**
 * @brief Private Variables and Functions of kernel_interface class
 *
 */
struct private_kernel_interface_t {
	/**
	 * Public part of the kernel_interface_t object
	 */
 	kernel_interface_t public;
 	
 	/**
 	 * netlink communication socket
 	 */
 	int socket;
 	
 	/**
 	 * since we use multiple threads, we can't call
 	 * getpid multiple times. The pid is set once.
 	 */
 	pid_t pid;
 	
 	/**
 	 * sequence number for messages
 	 */
 	u_int32_t seq;
 	
 	/** 
 	 * list of replies messages
 	 */
 	linked_list_t *replies;
 	
 	/**
 	 * Function for the thread, receives messages
 	 */
 	void (*receive_messages) (private_kernel_interface_t *this);
 	
 	/**
 	 * Sends a netlink_message_t down to the kernel
 	 */
 	void (*send_message) (private_kernel_interface_t *this, netlink_message_t *request, netlink_message_t *response);
};


//static u_int32_t get_spi(private_kernel_interface_t *this, host_t *src, host_t *dest, protocol_id_t protocol, bool tunnel_mode)
//{
//	netlink_message_t request, response;
//	
//    memset(&request, 0, sizeof(request));
//    request.hdr.nlmsg_flags = NLM_F_REQUEST;
//    request.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
//	request.spi.info.saddr = src->get_xfrm_addr(src);
//	request.spi.info.id.daddr = dest->get_xfrm_addr(dest);
//    request.spi.info.mode = tunnel_mode;
//    request.spi.info.id.proto = protocol;
//    request.spi.info.family = src->get_family(src);
//    request.spi.min = 0;
//    request.spi.max = 50000;
//    request.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request.spi)));
//
//    this->send_message(this, &request, &response);
//
//    if (response.hdr.nlmsg_type == NLMSG_ERROR)
//    {
//		/* error handling */
//    }
//    else if (response.hdr.nlmsg_len < NLMSG_LENGTH(sizeof(response.sa)))
//    {
//		/* error handling */
//    }
//
//    return response.sa.id.spi;
//}
//
//
//
//static status_t send_message(private_kernel_interface_t *this, netlink_message_t *request, netlink_message_t *response)
//{
//	size_t length;
//	ssize_t r;
//	
//	length = request->hdr.nlmsg_len;
//	
//	
//	
//
//
//    size_t len;
//    ssize_t r;
//
//
//
//    request->hdr.nlmsg_seq = ++this->seq;
//	length = request->hdr.nlmsg_len;
//	
//    do {
//		r = write(netlinkfd, hdr, len);
//    } while (r < 0 && errno == EINTR);
//    
//    if (r < 0)
//    {
//		return FAILED;
//    }
//    else if ((size_t)r != len)
//    {
//		return FAILED;
//    }
//    
//    
//    /* wait for receiver thread */
//
//    return TRUE;
//}
//
//
//static void receive_messages(private_kernel_interface_t *this)
//{
//	while(TRUE) 
//	{
//		netlink_message_t *response;
//		
//		
//		socklen_t addr_length;
//    	struct sockaddr_nl addr;
//		size_t length;
//
//		addr_length = sizeof(addr);
//		length = recvfrom(netlinkfd, &rsp, sizeof(rsp), 0, (struct sockaddr*)&addr, &addr_length);
//		if (r < 0)
//		{
//			if (errno == EINTR)
//	    	{
//				continue;
//	    	}
//	    	return FAILED;
//		}
//		else if ((size_t) r < sizeof(rsp.n))
//		{
//			/* not enought bytes for header */
//			continue;
//		}
//		else if (addr.nl_pid != 0)
//		{
//			/* not interested */
//		    continue;
//		}
//		else if (rsp.n.nlmsg_seq != seq)
//		{
//		    DBG(DBG_KLIPS,
//			DBG_log("netlink: ignoring out of sequence (%u/%u) message %s"
//			    , rsp.n.nlmsg_seq, seq
//			    , sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)));
//		    continue;
//		}
//		break;
//    }
//
//    if (rsp.n.nlmsg_len > (size_t) r)
//    {
//		return FALSE;
//    }
//    else if (rsp.n.nlmsg_type != NLMSG_ERROR
//    && (rbuf && rsp.n.nlmsg_type != rbuf->nlmsg_type))
//    {
//	loglog(RC_LOG_SERIOUS
//	    , "netlink recvfrom() of response to our %s message"
//	      " for %s %s was of wrong type (%s)"
//	    , sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
//	    , description, text_said
//	    , sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));
//	return FALSE;
//    }
//    else if (rbuf)
//    {
//	if ((size_t) r > rbuf_len)
//	{
//	    loglog(RC_LOG_SERIOUS
//		, "netlink recvfrom() of response to our %s message"
//		  " for %s %s was too long: %ld > %lu"
//		, sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
//		, description, text_said
//		, (long)r, (unsigned long)rbuf_len);
//	    return FALSE;
//	}
//	memcpy(rbuf, &rsp, r);
//	return TRUE;
//    }
//    else if (rsp.n.nlmsg_type == NLMSG_ERROR && rsp.e.error)
//    {
//	loglog(RC_LOG_SERIOUS
//	    , "ERROR: netlink response for %s %s included errno %d: %s"
//	    , description, text_said
//	    , -rsp.e.error
//	    , strerror(-rsp.e.error));
//	return FALSE;
//    }	
//}



 /**
 * implements kernel_interface_t.destroy
 */
static void destroy (private_kernel_interface_t *this)
{	
	allocator_free(this);
}

/*
 * Documented in header
 */
kernel_interface_t *kernel_interface_create()
{
	private_kernel_interface_t *this = allocator_alloc_thing(private_kernel_interface_t);
	
	/* public functions */
	this->public.destroy = (void(*)(kernel_interface_t*)) destroy;

	/* private members */
	this->socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	
	return (&this->public);
}
