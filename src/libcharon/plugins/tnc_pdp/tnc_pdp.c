/*
 * Copyright (C) 2012 Andreas Steffen
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
#include <sa/authenticators/eap/eap_method.h>

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

	/**
	 * RADIUS shared secret
	 */
	chunk_t secret;

	/**
	 * MD5 hasher
	 */
	hasher_t *hasher;

	/**
	 * HMAC MD5 signer, with secret set
	 */
	signer_t *signer;

	/**
	 * EAP method
	 */
	eap_method_t *method;
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
		DBG1(DBG_CFG, "opening RADIUS socket failed: %s", strerror(errno));
		return 0;
	}
	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		DBG1(DBG_CFG, "unable to set SO_REUSEADDR on socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	/* bind the socket */
	if (bind(skt, (struct sockaddr *)&addr, addrlen) < 0)
	{
		DBG1(DBG_CFG, "unable to bind RADIUS socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	return skt;
}

/**
 * Send a RADIUS message to client
 */
static void send_message(private_tnc_pdp_t *this, radius_message_t *message,
						 host_t *client)
{
	int fd;
	chunk_t data;

	fd = (client->get_family(client) == AF_INET) ? this->ipv4 : this->ipv6;
	data = message->get_encoding(message);

	DBG2(DBG_CFG, "sending RADIUS packet to %#H", client);
	DBG3(DBG_CFG, "%B", &data);

	if (sendto(fd, data.ptr, data.len, 0, client->get_sockaddr(client),
			   *client->get_sockaddr_len(client)) != data.len)
	{
		DBG1(DBG_CFG, "sending RADIUS message failed: %s", strerror(errno));
	}
}

/**
 * Send a RADIUS response for a request
 */
static void send_response(private_tnc_pdp_t *this,
						  radius_message_t *request, radius_message_code_t code,
						  eap_payload_t *eap, host_t *client)
{
	radius_message_t *response;
	chunk_t data;

	response = radius_message_create(code);
	if (eap)
	{
		data = eap->get_data(eap);
		response->add(response, RAT_EAP_MESSAGE, data);
	}
	response->set_identifier(response, request->get_identifier(request));
	response->sign(response, request->get_authenticator(request),
				   this->secret, this->hasher, this->signer, NULL, TRUE);

	DBG1(DBG_CFG, "sending RADIUS %N to client '%H'", radius_message_code_names,
		 code, client);
	send_message(this, response, client);
}

/**
 * Process EAP message
 */
static void process_eap(private_tnc_pdp_t *this, radius_message_t *request,
						host_t *source)
{
	enumerator_t *enumerator;
	eap_payload_t *in, *out = NULL;
	eap_type_t eap_type;
	chunk_t data, message = chunk_empty;
	radius_message_code_t code = RMC_ACCESS_CHALLENGE;
	u_int32_t eap_vendor;
	int type;

	enumerator = request->create_enumerator(request);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_EAP_MESSAGE && data.len)
		{
			message = chunk_cat("mc", message, data);
		}
	}
	enumerator->destroy(enumerator);

	if (message.len)
	{
		in = eap_payload_create_data(message);

		/* apply EAP method selected by RADIUS server */
		eap_type = in->get_type(in, &eap_vendor);

		DBG3(DBG_CFG, "%N payload %B", eap_type_names, eap_type, &message);
		free(message.ptr);

		if (eap_type == EAP_IDENTITY)
		{
			identification_t *server, *peer;
			chunk_t eap_identity;

			if (message.len < 5)
			{
				return;
			}
			eap_identity = chunk_create(message.ptr + 5, message.len - 5);
			peer = identification_create_from_data(eap_identity);
			server = identification_create_from_string("%any");

			this->method = charon->eap->create_instance(charon->eap, EAP_MD5, 0,
												EAP_SERVER, server, peer); 
			if (!this->method)
			{
				peer->destroy(peer);
				server->destroy(server);
				in->destroy(in);
				return;
			}
			this->method->initiate(this->method, &out);
		}
		else
		{
			switch (this->method->process(this->method, in, &out))
			{
				case NEED_MORE:
					code = RMC_ACCESS_CHALLENGE;
					break;
				case SUCCESS:
					code = RMC_ACCESS_ACCEPT;
					DESTROY_IF(out);
					out = eap_payload_create_code(EAP_SUCCESS,
												  in->get_identifier(in));
					break;
				case FAILED:
				default:
					code = RMC_ACCESS_REJECT;
					DESTROY_IF(out);
					out = eap_payload_create_code(EAP_FAILURE,
												  in->get_identifier(in));
			}
		}

		send_response(this, request, code, out, source);
		in->destroy(in);
		out->destroy(out);
	}
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

		DBG2(DBG_CFG, "waiting for data on RADIUS sockets");
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
			DBG1(DBG_CFG, "error reading RADIUS socket: %s", strerror(errno));
			continue;
		}
		if (msg.msg_flags & MSG_TRUNC)
		{
			DBG1(DBG_CFG, "receive buffer too small, RADIUS packet discarded");
			continue;
		}
		source = host_create_from_sockaddr((sockaddr_t*)&src);
		DBG2(DBG_CFG, "received RADIUS packet from %#H", source);
		DBG3(DBG_CFG, "%b", buffer, bytes_read);
		request = radius_message_parse(chunk_create(buffer, bytes_read));
		if (request)
		{
			DBG1(DBG_CFG, "received RADIUS %N from client '%H'",
			 	 radius_message_code_names, request->get_code(request), source);

			if (request->verify(request, NULL, this->secret, this->hasher,
											   this->signer))
			{
				process_eap(this, request, source);
			}
			request->destroy(request);
			
		}
		else
		{
			DBG1(DBG_CFG, "received invalid RADIUS message, ignored");
		}
		source->destroy(source);
	}
	return JOB_REQUEUE_FAIR;
}

METHOD(tnc_pdp_t, destroy, void,
	private_tnc_pdp_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	if (this->ipv4)
	{
		close(this->ipv4);
	}
	if (this->ipv6)
	{
		close(this->ipv6);
	}
	DESTROY_IF(this->signer);
	DESTROY_IF(this->hasher);
	DESTROY_IF(this->method);
	free(this);
}

/*
 * see header file
 */
tnc_pdp_t *tnc_pdp_create(u_int16_t port)
{
	private_tnc_pdp_t *this;
	char *secret;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.ipv4 = open_socket(this, AF_INET,  port),
		.ipv6 = open_socket(this, AF_INET6, port),
		.hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5),
		.signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_MD5_128),
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
	if (!this->hasher || !this->signer)
	{
		destroy(this);
		return NULL;
	}
	secret = lib->settings->get_str(lib->settings,
						"charon.plugins.tnc-pdp.secret", NULL);
	if (!secret)
	{
		DBG1(DBG_CFG, "missing RADIUS secret, PDP disabled");
		destroy(this);
		return NULL;
	}
	this->secret = chunk_create(secret, strlen(secret));
	this->signer->set_key(this->signer, this->secret);

	this->job = callback_job_create_with_prio((callback_job_cb_t)receive,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->job);

	return &this->public;
}

