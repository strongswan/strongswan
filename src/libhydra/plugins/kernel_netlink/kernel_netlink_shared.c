/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <unistd.h>

#include "kernel_netlink_shared.h"

#include <utils/debug.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <collections/array.h>
#include <collections/hashtable.h>

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
	 * mutex to lock access entries
	 */
	mutex_t *mutex;

	/**
	 * Netlink request entries currently active, uintptr_t seq => entry_t
	 */
	hashtable_t *entries;

	/**
	 * Current sequence number for Netlink requests
	 */
	refcount_t seq;

	/**
	 * netlink socket
	 */
	int socket;

	/**
	 * Enum names for Netlink messages
	 */
	enum_name_t *names;
};

/**
 * Request entry the answer for a waiting thread is collected in
 */
typedef struct {
	/** Condition variable thread is waiting */
	condvar_t *condvar;
	/** Array of hdrs in a multi-message response, as struct nlmsghdr* */
	array_t *hdrs;
	/** All response messages received? */
	bool complete;
} entry_t;

/**
 * Clean up a thread waiting entry
 */
static void destroy_entry(entry_t *entry)
{
	entry->condvar->destroy(entry->condvar);
	array_destroy_function(entry->hdrs, (void*)free, NULL);
	free(entry);
}

/**
 * Write a Netlink message to socket
 */
static bool write_msg(private_netlink_socket_t *this, struct nlmsghdr *msg)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};
	int len;

	while (TRUE)
	{
		len = sendto(this->socket, msg, msg->nlmsg_len, 0,
					 (struct sockaddr*)&addr, sizeof(addr));
		if (len != msg->nlmsg_len)
		{
			if (errno == EINTR)
			{
				continue;
			}
			DBG1(DBG_KNL, "netlink write error: %s", strerror(errno));
			return FALSE;
		}
		return TRUE;
	}
}

/**
 * Read a single Netlink message from socket
 */
static size_t read_msg(private_netlink_socket_t *this,
					   char buf[4096], size_t buflen, bool block)
{
	ssize_t len;

	len = recv(this->socket, buf, buflen, block ? 0 : MSG_DONTWAIT);
	if (len == buflen)
	{
		DBG1(DBG_KNL, "netlink response exceeds buffer size");
		return 0;
	}
	if (len < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
		{
			DBG1(DBG_KNL, "netlink read error: %s", strerror(errno));
		}
		return 0;
	}
	return len;
}

/**
 * Queue received response message
 */
static bool queue(private_netlink_socket_t *this, struct nlmsghdr *buf)
{
	struct nlmsghdr *hdr;
	entry_t *entry;
	uintptr_t seq;

	seq = (uintptr_t)buf->nlmsg_seq;

	this->mutex->lock(this->mutex);
	entry = this->entries->get(this->entries, (void*)seq);
	if (entry)
	{
		hdr = malloc(buf->nlmsg_len);
		memcpy(hdr, buf, buf->nlmsg_len);
		array_insert(entry->hdrs, ARRAY_TAIL, hdr);
		if (hdr->nlmsg_type == NLMSG_DONE || !(hdr->nlmsg_flags & NLM_F_MULTI))
		{
			entry->complete = TRUE;
			entry->condvar->signal(entry->condvar);
		}
	}
	else
	{
		DBG1(DBG_KNL, "received unknown netlink seq %u, ignored", seq);
	}
	this->mutex->unlock(this->mutex);

	return entry != NULL;
}

/**
 * Read and queue response message, optionally blocking
 */
static void read_and_queue(private_netlink_socket_t *this, bool block)
{
	struct nlmsghdr *hdr;
	union {
		struct nlmsghdr hdr;
		char bytes[4096];
	} buf;
	size_t len;

	len = read_msg(this, buf.bytes, sizeof(buf.bytes), block);
	if (len)
	{
		hdr = &buf.hdr;
		while (NLMSG_OK(hdr, len))
		{
			if (!queue(this, hdr))
			{
				break;
			}
			hdr = NLMSG_NEXT(hdr, len);
		}
	}
}

CALLBACK(watch, bool,
	private_netlink_socket_t *this, int fd, watcher_event_t event)
{
	if (event == WATCHER_READ)
	{
		read_and_queue(this, FALSE);
	}
	return TRUE;
}

METHOD(netlink_socket_t, netlink_send, status_t,
	private_netlink_socket_t *this, struct nlmsghdr *in, struct nlmsghdr **out,
	size_t *out_len)
{
	struct nlmsghdr *hdr;
	chunk_t result = {};
	entry_t *entry;
	uintptr_t seq;

	seq = ref_get(&this->seq);
	in->nlmsg_seq = seq;
	in->nlmsg_pid = getpid();

	if (this->names)
	{
		DBG3(DBG_KNL, "sending %N %u: %b", this->names, in->nlmsg_type,
			 (u_int)seq, in, in->nlmsg_len);
	}

	this->mutex->lock(this->mutex);
	if (!write_msg(this, in))
	{
		this->mutex->unlock(this->mutex);
		return FAILED;
	}

	INIT(entry,
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.hdrs = array_create(0, 0),
	);
	this->entries->put(this->entries, (void*)seq, entry);

	while (!entry->complete)
	{
		if (lib->watcher->get_state(lib->watcher) == WATCHER_RUNNING)
		{
			entry->condvar->wait(entry->condvar, this->mutex);
		}
		else
		{	/* During (de-)initialization, no watcher thread is active.
			 * collect responses ourselves. */
			read_and_queue(this, TRUE);
		}
	}
	this->entries->remove(this->entries, (void*)seq);

	this->mutex->unlock(this->mutex);

	while (array_remove(entry->hdrs, ARRAY_HEAD, &hdr))
	{
		if (this->names)
		{
			DBG3(DBG_KNL, "received %N %u: %b", this->names, hdr->nlmsg_type,
				 hdr->nlmsg_seq, hdr, hdr->nlmsg_len);
		}
		result = chunk_cat("mm", result,
						   chunk_create((char*)hdr, hdr->nlmsg_len));
	}
	destroy_entry(entry);

	*out_len = result.len;
	*out = (struct nlmsghdr*)result.ptr;

	return SUCCESS;
}

METHOD(netlink_socket_t, netlink_send_ack, status_t,
	private_netlink_socket_t *this, struct nlmsghdr *in)
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
				struct nlmsgerr* err = NLMSG_DATA(hdr);

				if (err->error)
				{
					if (-err->error == EEXIST)
					{	/* do not report existing routes */
						free(out);
						return ALREADY_DONE;
					}
					if (-err->error == ESRCH)
					{	/* do not report missing entries */
						free(out);
						return NOT_FOUND;
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

METHOD(netlink_socket_t, destroy, void,
	private_netlink_socket_t *this)
{
	if (this->socket != -1)
	{
		lib->watcher->remove(lib->watcher, this->socket);
		close(this->socket);
	}
	this->entries->destroy(this->entries);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Described in header.
 */
netlink_socket_t *netlink_socket_create(int protocol, enum_name_t *names)
{
	private_netlink_socket_t *this;
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};

	INIT(this,
		.public = {
			.send = _netlink_send,
			.send_ack = _netlink_send_ack,
			.destroy = _destroy,
		},
		.seq = 200,
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.socket = socket(AF_NETLINK, SOCK_RAW, protocol),
		.entries = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
		.names = names,
	);

	if (this->socket == -1)
	{
		DBG1(DBG_KNL, "unable to create netlink socket");
		destroy(this);
		return NULL;
	}
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)))
	{
		DBG1(DBG_KNL, "unable to bind netlink socket");
		destroy(this);
		return NULL;
	}

	lib->watcher->add(lib->watcher, this->socket, WATCHER_READ, watch, this);

	return &this->public;
}

/**
 * Described in header.
 */
void netlink_add_attribute(struct nlmsghdr *hdr, int rta_type, chunk_t data,
						  size_t buflen)
{
	struct rtattr *rta;

	if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_LENGTH(data.len) > buflen)
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
 * Described in header.
 */
void* netlink_reserve(struct nlmsghdr *hdr, int buflen, int type, int len)
{
	struct rtattr *rta;

	if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_LENGTH(len) > buflen)
	{
		DBG1(DBG_KNL, "unable to add attribute, buffer too small");
		return NULL;
	}

	rta = ((void*)hdr) + NLMSG_ALIGN(hdr->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + rta->rta_len;

	return RTA_DATA(rta);
}
