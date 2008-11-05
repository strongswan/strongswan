/*
 * Copyright (C) 2008 Tobias Brunner
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

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <unistd.h>

#include "kernel_netlink_shared.h"

#include <daemon.h>
#include <utils/mutex.h>

typedef struct private_netlink_socket_t private_netlink_socket_t;

/**
 * Private variables and functions of netlink_socket_t class.
 */
struct private_netlink_socket_t {
	/**
	 * public part of the netlink_socket_t object.
	 */
	netlink_socket_t public;
	
	/**
	 * mutex to lock access to netlink socket
	 */
	mutex_t *mutex;

	/**
	 * current sequence number for netlink request
	 */
	int seq;
	
	/**
	 * netlink socket 
	 */
	int socket;
};

/**
 * Implementation of netlink_socket_t.send
 */
static status_t netlink_send(private_netlink_socket_t *this, struct nlmsghdr *in,
			  struct nlmsghdr **out, size_t *out_len)
{
	int len, addr_len;
	struct sockaddr_nl addr;
	chunk_t result = chunk_empty, tmp;
	struct nlmsghdr *msg, peek;
	
	this->mutex->lock(this->mutex);
	
	in->nlmsg_seq = ++this->seq;
	in->nlmsg_pid = getpid();
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;

	while (TRUE)
	{
		len = sendto(this->socket, in, in->nlmsg_len, 0, 
					 (struct sockaddr*)&addr, sizeof(addr));
		
		if (len != in->nlmsg_len)
		{	
			if (errno == EINTR)
			{
				/* interrupted, try again */
				continue;
			}
			this->mutex->unlock(this->mutex);
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
		
		len = recvfrom(this->socket, tmp.ptr, tmp.len, 0,
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
			this->mutex->unlock(this->mutex);
			free(result.ptr);
			return FAILED;
		}
		if (!NLMSG_OK(msg, len))
		{
			DBG1(DBG_KNL, "received corrupted netlink message");
			this->mutex->unlock(this->mutex);
			free(result.ptr);
			return FAILED;
		}
		if (msg->nlmsg_seq != this->seq)
		{
			DBG1(DBG_KNL, "received invalid netlink sequence number");
			if (msg->nlmsg_seq < this->seq)
			{
				continue;
			}
			this->mutex->unlock(this->mutex);
			free(result.ptr);
			return FAILED;
		}
		
		tmp.len = len;
		result.ptr = realloc(result.ptr, result.len + tmp.len);
		memcpy(result.ptr + result.len, tmp.ptr, tmp.len);
		result.len += tmp.len;
		
		/* NLM_F_MULTI flag does not seem to be set correctly, we use sequence
		 * numbers to detect multi header messages */
		len = recvfrom(this->socket, &peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT,
					   (struct sockaddr*)&addr, &addr_len);
		
		if (len == sizeof(peek) && peek.nlmsg_seq == this->seq)
		{
			/* seems to be multipart */
			continue;
		}
		break;
	}
	
	*out_len = result.len;
	*out = (struct nlmsghdr*)result.ptr;
	
	this->mutex->unlock(this->mutex);
	
	return SUCCESS;
}

/**
 * Implementation of netlink_socket_t.send_ack.
 */
static status_t netlink_send_ack(private_netlink_socket_t *this, struct nlmsghdr *in)
{
	struct nlmsghdr *out, *hdr;
	size_t len;

	if (netlink_send(this, in, &out, &len) != SUCCESS)
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
					if (-err->error == EEXIST)
					{	/* do not report existing routes */
						free(out);
						return ALREADY_DONE;
					}
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
	DBG1(DBG_KNL, "netlink request not acknowledged");
	free(out);
	return FAILED;
}

/**
 * Implementation of netlink_socket_t.destroy.
 */
static void destroy(private_netlink_socket_t *this)
{
	close(this->socket);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Described in header.
 */
netlink_socket_t *netlink_socket_create(int protocol) {
	private_netlink_socket_t *this = malloc_thing(private_netlink_socket_t);
	struct sockaddr_nl addr;
	
	/* public functions */
	this->public.send = (status_t(*)(netlink_socket_t*,struct nlmsghdr*, struct nlmsghdr**, size_t*))netlink_send;
	this->public.send_ack = (status_t(*)(netlink_socket_t*,struct nlmsghdr*))netlink_send_ack;
	this->public.destroy = (void(*)(netlink_socket_t*))destroy;

	/* private members */
	this->seq = 200;
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	
	this->socket = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (this->socket <= 0)
	{
		charon->kill(charon, "unable to create netlink socket");
	}
	
	addr.nl_groups = 0;
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)))
	{
		charon->kill(charon, "unable to bind netlink socket");
	}
	
	return &this->public;
}

/**
 * Described in header.
 */
void netlink_add_attribute(struct nlmsghdr *hdr, int rta_type, chunk_t data,
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
