/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_pdp.h"

#include <errno.h>
#include <unistd.h>

#include <radius_message.h>

#include <daemon.h>
#include <debug.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

typedef struct private_tnc_pdp_t private_tnc_pdp_t;

/**
 * Maximum size of a RADIUS IP packet
 */
#define MAX_PACKET 4096

/**
 * private data of tnc_pdp_t
 */
struct private_tnc_pdp_t {

	/**
	 * implements tnc_pdp_t interface
	 */
	tnc_pdp_t public;

	/**
	 * IPv4 RADIUS socket
	 */
	int ipv4;

	/**
	 * IPv6 RADIUS socket
	 */
	int ipv6;

	/**
	 * Callback job dispatching commands
	 */
	callback_job_t *job;

};


/**
 * Open IPv4 or IPv6 UDP RADIUS socket
 */
static int open_socket(private_tnc_pdp_t *this, int family, u_int16_t port)
{
	int on = TRUE;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int skt;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = family;

	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)&addr;

			htoun32(&sin->sin_addr.s_addr, INADDR_ANY);
			htoun16(&sin->sin_port, port);
			addrlen = sizeof(struct sockaddr_in);
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;

			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			htoun16(&sin6->sin6_port, port);
			addrlen = sizeof(struct sockaddr_in6);
			break;
		}
		default:
			return 0;
	}

	/* open the socket */
	skt = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0)
	{
		DBG1(DBG_NET, "opening RADIUS socket failed: %s", strerror(errno));
		return 0;
	}
	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "unable to set SO_REUSEADDR on socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	/* bind the socket */
	if (bind(skt, (struct sockaddr *)&addr, addrlen) < 0)
	{
		DBG1(DBG_NET, "unable to bind RADIUS socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	return skt;
}

/**
 * Process packets received on the RADIUS socket
 */
static job_requeue_t receive(private_tnc_pdp_t *this)
{
	while (TRUE)
	{
		radius_message_t *request;
		char buffer[MAX_PACKET];
		int max_fd = 0, selected = 0, bytes_read = 0;
		fd_set rfds;
		bool oldstate;
		host_t *source;
		struct msghdr msg;
		struct iovec iov;
		union {
			struct sockaddr_in in4;
			struct sockaddr_in6 in6;
		} src;

		FD_ZERO(&rfds);

		if (this->ipv4)
		{
			FD_SET(this->ipv4, &rfds);
		}
		if (this->ipv6)
		{
			FD_SET(this->ipv6, &rfds);
		}
		max_fd = max(this->ipv4, this->ipv6);

		DBG2(DBG_NET, "waiting for data on RADIUS sockets");
		oldstate = thread_cancelability(TRUE);
		if (select(max_fd + 1, &rfds, NULL, NULL, NULL) <= 0)
		{
			thread_cancelability(oldstate);
			continue;
		}
		thread_cancelability(oldstate);

		if (FD_ISSET(this->ipv4, &rfds))
		{
			selected = this->ipv4;
		}
		else if (FD_ISSET(this->ipv6, &rfds))
		{
			selected = this->ipv6;
		}
		else
		{
			/* oops, shouldn't happen */
			continue;
		}

		/* read received packet */
		msg.msg_name = &src;
		msg.msg_namelen = sizeof(src);
		iov.iov_base = buffer;
		iov.iov_len = MAX_PACKET;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;

		bytes_read = recvmsg(selected, &msg, 0);
		if (bytes_read < 0)
		{
			DBG1(DBG_NET, "error reading RADIUS socket: %s", strerror(errno));
			continue;
		}
		if (msg.msg_flags & MSG_TRUNC)
		{
			DBG1(DBG_NET, "receive buffer too small, RADIUS packet discarded");
			continue;
		}
		source = host_create_from_sockaddr((sockaddr_t*)&src);
		DBG2(DBG_NET, "received RADIUS packet from %#H", source);
		DBG3(DBG_NET, "%b", buffer, bytes_read);
		request = radius_message_parse_response(chunk_create(buffer, bytes_read));
		if (request)
		{
			DBG2(DBG_NET, "received valid RADIUS message");
			request->destroy(request);
		}
		else
		{
			DBG1(DBG_NET, "received invalid RADIUS message, ignored");
		}
		source->destroy(source);
	}
	return JOB_REQUEUE_FAIR;
}

METHOD(tnc_pdp_t, destroy, void,
	private_tnc_pdp_t *this)
{
	this->job->cancel(this->job);
	if (this->ipv4)
	{
		close(this->ipv4);
	}
	if (this->ipv6)
	{
		close(this->ipv6);
	}
	free(this);
}

/*
 * see header file
 */
tnc_pdp_t *tnc_pdp_create(u_int16_t port)
{
	private_tnc_pdp_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.ipv4 = open_socket(this, AF_INET,  port),
		.ipv6 = open_socket(this, AF_INET6, port),
	);

	if (!this->ipv4 && !this->ipv6)
	{
		DBG1(DBG_NET, "couldd not create any RADIUS sockets");
		destroy(this);
		return NULL;
	}
	if (!this->ipv4)
	{
		DBG1(DBG_NET, "could not open IPv4 RADIUS socket, IPv4 disabled");
	}
	if (!this->ipv6)
	{
		DBG1(DBG_NET, "could not open IPv6 RADIUS socket, IPv6 disabled");
	}

	this->job = callback_job_create_with_prio((callback_job_cb_t)receive,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->job);

	return &this->public;
}

