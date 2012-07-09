/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "radius_socket.h"
#include "radius_mppe.h"

#include <errno.h>
#include <unistd.h>

#include <pen/pen.h>
#include <debug.h>

typedef struct private_radius_socket_t private_radius_socket_t;

/**
 * Private data of an radius_socket_t object.
 */
struct private_radius_socket_t {

	/**
	 * Public radius_socket_t interface.
	 */
	radius_socket_t public;

	/**
	 * Server port for authentication
	 */
	u_int16_t auth_port;

	/**
	 * socket file descriptor for authentication
	 */
	int auth_fd;

	/**
	 * Server port for accounting
	 */
	u_int16_t acct_port;

	/**
	 * socket file descriptor for accounting
	 */
	int acct_fd;

	/**
	 * Server address
	 */
	char *address;

	/**
	 * current RADIUS identifier
	 */
	u_int8_t identifier;

	/**
	 * hasher to use for response verification
	 */
	hasher_t *hasher;

	/**
	 * HMAC-MD5 signer to build Message-Authenticator attribute
	 */
	signer_t *signer;

	/**
	 * random number generator for RADIUS request authenticator
	 */
	rng_t *rng;

	/**
	 * RADIUS secret
	 */
	chunk_t secret;
};

/**
 * Check or establish RADIUS connection
 */
static bool check_connection(private_radius_socket_t *this,
							 int *fd, u_int16_t port)
{
	if (*fd == -1)
	{
		host_t *server;

		server = host_create_from_dns(this->address, AF_UNSPEC, port);
		if (!server)
		{
			DBG1(DBG_CFG, "resolving RADIUS server address '%s' failed",
				 this->address);
			return FALSE;
		}
		*fd = socket(server->get_family(server), SOCK_DGRAM, IPPROTO_UDP);
		if (*fd == -1)
		{
			DBG1(DBG_CFG, "opening RADIUS socket for %#H failed: %s",
				 server, strerror(errno));
			server->destroy(server);
			return FALSE;
		}
		if (connect(*fd, server->get_sockaddr(server),
					*server->get_sockaddr_len(server)) < 0)
		{
			DBG1(DBG_CFG, "connecting RADIUS socket to %#H failed: %s",
				 server, strerror(errno));
			server->destroy(server);
			close(*fd);
			*fd = -1;
			return FALSE;
		}
		server->destroy(server);
	}
	return TRUE;
}

METHOD(radius_socket_t, request, radius_message_t*,
	private_radius_socket_t *this, radius_message_t *request)
{
	chunk_t data;
	int i, *fd;
	u_int16_t port;
	rng_t *rng = NULL;

	if (request->get_code(request) == RMC_ACCOUNTING_REQUEST)
	{
		fd = &this->acct_fd;
		port = this->acct_port;
	}
	else
	{
		fd = &this->auth_fd;
		port = this->auth_port;
		rng = this->rng;
	}

	/* set Message Identifier */
	request->set_identifier(request, this->identifier++);
	/* sign the request */
	if (!request->sign(request, NULL, this->secret, this->hasher, this->signer,
					   rng, rng != NULL))
	{
		return NULL;
	}

	if (!check_connection(this, fd, port))
	{
		return NULL;
	}

	data = request->get_encoding(request);
	DBG3(DBG_CFG, "%B", &data);

	/* timeout after 2, 3, 4, 5 seconds */
	for (i = 2; i <= 5; i++)
	{
		radius_message_t *response;
		bool retransmit = FALSE;
		struct timeval tv;
		char buf[4096];
		fd_set fds;
		int res;

		if (send(*fd, data.ptr, data.len, 0) != data.len)
		{
			DBG1(DBG_CFG, "sending RADIUS message failed: %s", strerror(errno));
			return NULL;
		}
		tv.tv_sec = i;
		tv.tv_usec = 0;

		while (TRUE)
		{
			FD_ZERO(&fds);
			FD_SET(*fd, &fds);
			res = select((*fd) + 1, &fds, NULL, NULL, &tv);
			/* TODO: updated tv to time not waited. Linux does this for us. */
			if (res < 0)
			{	/* failed */
				DBG1(DBG_CFG, "waiting for RADIUS message failed: %s",
					 strerror(errno));
				break;
			}
			if (res == 0)
			{	/* timeout */
				DBG1(DBG_CFG, "retransmitting RADIUS message");
				retransmit = TRUE;
				break;
			}
			res = recv(*fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (res <= 0)
			{
				DBG1(DBG_CFG, "receiving RADIUS message failed: %s",
					 strerror(errno));
				break;
			}
			response = radius_message_parse(chunk_create(buf, res));
			if (response)
			{
				if (response->verify(response,
							request->get_authenticator(request), this->secret,
							this->hasher, this->signer))
				{
					return response;
				}
				response->destroy(response);
			}
			DBG1(DBG_CFG, "received invalid RADIUS message, ignored");
		}
		if (!retransmit)
		{
			break;
		}
	}
	DBG1(DBG_CFG, "RADIUS server is not responding");
	return NULL;
}

/**
 * Decrypt a MS-MPPE-Send/Recv-Key
 */
static chunk_t decrypt_mppe_key(private_radius_socket_t *this, u_int16_t salt,
								chunk_t C, radius_message_t *request)
{
	chunk_t A, R, P, seed;
	u_char *c, *p;

	/**
	 * From RFC2548 (encryption):
	 * b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
	 * b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
	 *      . . .
	 * b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)
	 */

	if (C.len % HASH_SIZE_MD5 || C.len < HASH_SIZE_MD5)
	{
		return chunk_empty;
	}

	A = chunk_create((u_char*)&salt, sizeof(salt));
	R = chunk_create(request->get_authenticator(request), HASH_SIZE_MD5);
	P = chunk_alloca(C.len);
	p = P.ptr;
	c = C.ptr;

	seed = chunk_cata("cc", R, A);

	while (c < C.ptr + C.len)
	{
		/* b(i) = MD5(S + c(i-1)) */
		if (!this->hasher->get_hash(this->hasher, this->secret, NULL) ||
			!this->hasher->get_hash(this->hasher, seed, p))
		{
			return chunk_empty;
		}

		/* p(i) = b(i) xor c(1) */
		memxor(p, c, HASH_SIZE_MD5);

		/* prepare next round */
		seed = chunk_create(c, HASH_SIZE_MD5);
		c += HASH_SIZE_MD5;
		p += HASH_SIZE_MD5;
	}

	/* remove truncation, first byte is key length */
	if (*P.ptr >= P.len)
	{	/* decryption failed? */
		return chunk_empty;
	}
	return chunk_clone(chunk_create(P.ptr + 1, *P.ptr));
}

METHOD(radius_socket_t, decrypt_msk, chunk_t,
	private_radius_socket_t *this, radius_message_t *request,
	radius_message_t *response)
{
	mppe_key_t *mppe_key;
	enumerator_t *enumerator;
	chunk_t data, send = chunk_empty, recv = chunk_empty;
	int type;

	enumerator = response->create_enumerator(response);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_VENDOR_SPECIFIC && data.len > sizeof(mppe_key_t))
		{
			mppe_key = (mppe_key_t*)data.ptr;
			if (ntohl(mppe_key->id) == PEN_MICROSOFT &&
				mppe_key->length == data.len - sizeof(mppe_key->id))
			{
				data = chunk_create(mppe_key->key, data.len - sizeof(mppe_key_t));
				if (mppe_key->type == MS_MPPE_SEND_KEY)
				{
					send = decrypt_mppe_key(this, mppe_key->salt, data, request);
				}
				if (mppe_key->type == MS_MPPE_RECV_KEY)
				{
					recv = decrypt_mppe_key(this, mppe_key->salt, data, request);
				}
			}
		}
	}
	enumerator->destroy(enumerator);
	if (send.ptr && recv.ptr)
	{
		return chunk_cat("mm", recv, send);
	}
	chunk_clear(&send);
	chunk_clear(&recv);
	return chunk_empty;
}

METHOD(radius_socket_t, destroy, void,
	private_radius_socket_t *this)
{
	DESTROY_IF(this->hasher);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->rng);
	if (this->auth_fd != -1)
	{
		close(this->auth_fd);
	};
	if (this->acct_fd != -1)
	{
		close(this->acct_fd);
	}
	free(this);
}

/**
 * See header
 */
radius_socket_t *radius_socket_create(char *address, u_int16_t auth_port,
									  u_int16_t acct_port, chunk_t secret)
{
	private_radius_socket_t *this;

	INIT(this,
		.public = {
			.request = _request,
			.decrypt_msk = _decrypt_msk,
			.destroy = _destroy,
		},
		.address = address,
		.auth_port = auth_port,
		.auth_fd = -1,
		.acct_port = acct_port,
		.acct_fd = -1,
		.hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5),
		.signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_MD5_128),
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
	);

	if (!this->hasher || !this->signer || !this->rng ||
		!this->signer->set_key(this->signer, secret))
	{
		DBG1(DBG_CFG, "RADIUS initialization failed, HMAC/MD5/RNG required");
		destroy(this);
		return NULL;
	}
	this->secret = secret;
	/* we use a random identifier, helps if we restart often */
	this->identifier = random();

	return &this->public;
}
