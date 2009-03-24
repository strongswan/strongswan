/*
 * Copyright (C) 2009 Martin Willi
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

#include "radius_client.h"

#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <utils/host.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>

/**
 * Default RADIUS server port, when not configured
 */
#define RADIUS_PORT 1812

/**
 * Vendor-Id of Microsoft specific attributes
 */
#define VENDOR_ID_MICROSOFT 311

/**
 * Microsoft specific vendor attributes
 */
#define MS_MPPE_SEND_KEY 16
#define MS_MPPE_RECV_KEY 17

typedef struct private_radius_client_t private_radius_client_t;

typedef struct entry_t entry_t;

/**
 * A socket pool entry.
 */
struct entry_t {
	/** socket file descriptor */
	int fd;
	/** current RADIUS identifier */
	u_int8_t identifier;
	/** hasher to use for response verification */
	hasher_t *hasher;
	/** HMAC-MD5 signer to build Message-Authenticator attribute */
	signer_t *signer;
	/** random number generator for RADIUS request authenticator */
	rng_t *rng;
};

/**
 * Private data of an radius_client_t object.
 */
struct private_radius_client_t {
	
	/**
	 * Public radius_client_t interface.
	 */
	radius_client_t public;
	
	/**
	 * The clients socket from the pool
	 */
	entry_t *socket;
	
	/**
	 * RADIUS servers State attribute
	 */
	chunk_t state;
};

/**
 * Global list of radius sockets, contains entry_t's
 */
static linked_list_t *sockets;

/**
 * mutex to lock sockets list
 */
static mutex_t *mutex;

/**
 * condvar to wait for sockets
 */
static condvar_t *condvar;

/**
 * RADIUS secret
 */
static chunk_t secret;

/**
 * NAS-Identifier
 */
static chunk_t nas_identifier;

/**
 * Clean up socket list
 */
void radius_client_cleanup()
{
	entry_t *entry;
	
	mutex->destroy(mutex);
	condvar->destroy(condvar);
	while (sockets->remove_last(sockets, (void**)&entry) == SUCCESS)
	{
		entry->rng->destroy(entry->rng);
		entry->hasher->destroy(entry->hasher);
		entry->signer->destroy(entry->signer);
		close(entry->fd);
		free(entry);
	}
	sockets->destroy(sockets);
}

/**
 * Initialize the socket list
 */
bool radius_client_init()
{
	int i, count, fd;
	u_int16_t port;
	entry_t *entry;
	host_t *host;
	char *server;
	
	nas_identifier.ptr = lib->settings->get_str(lib->settings,
					"charon.plugins.eap_radius.nas_identifier", "strongSwan");
	nas_identifier.len = strlen(nas_identifier.ptr);
	
	secret.ptr = lib->settings->get_str(lib->settings,
					"charon.plugins.eap_radius.secret", NULL);
	if (!secret.ptr)
	{
		DBG1(DBG_CFG, "no RADUIS secret defined");
		return FALSE;
	}
	secret.len = strlen(secret.ptr);
	server = lib->settings->get_str(lib->settings,
					"charon.plugins.eap_radius.server", NULL);
	if (!server)
	{
		DBG1(DBG_CFG, "no RADUIS server defined");
		return FALSE;
	}
	port = lib->settings->get_int(lib->settings,
					"charon.plugins.eap_radius.port", RADIUS_PORT);
	host = host_create_from_dns(server, 0, port);
	if (!host)
	{
		return FALSE;
	}
	count = lib->settings->get_int(lib->settings,
					"charon.plugins.eap_radius.sockets", 5);
	
	sockets = linked_list_create();
	mutex = mutex_create(MUTEX_DEFAULT);
	condvar = condvar_create(CONDVAR_DEFAULT);
	for (i = 0; i < count; i++)
	{
		fd = socket(host->get_family(host), SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0)
		{
			DBG1(DBG_CFG, "opening RADIUS socket failed");
			host->destroy(host);
			radius_client_cleanup();
			return FALSE;
		}
		if (connect(fd, host->get_sockaddr(host),
					*host->get_sockaddr_len(host)) < 0)
		{
			DBG1(DBG_CFG, "connecting RADIUS socket failed");
			host->destroy(host);
			radius_client_cleanup();
			return FALSE;
		}
		entry = malloc_thing(entry_t);
		entry->fd = fd;
		/* we use per-socket crypto elements: this reduces overhead, but
		 * is still thread-save. */
		entry->hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
		entry->signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_MD5_128);
		entry->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!entry->hasher || !entry->signer || !entry->rng)
		{
			DBG1(DBG_CFG, "RADIUS initialization failed, HMAC/MD5/RNG required");
			DESTROY_IF(entry->hasher);
			DESTROY_IF(entry->signer);
			DESTROY_IF(entry->rng);
			free(entry);
			host->destroy(host);
			radius_client_cleanup();
			return FALSE;
		}
		entry->signer->set_key(entry->signer, secret);
		/* we use a random identifier, helps if we restart often (testing) */
		entry->identifier = random();
		sockets->insert_last(sockets, entry);
	}
	host->destroy(host);
	return TRUE;
}

/**
 * Get a socket from the pool, block if none available
 */
static entry_t* get_socket()
{
	entry_t *entry;
	
	mutex->lock(mutex);
	while (sockets->remove_first(sockets, (void**)&entry) != SUCCESS)
	{
		condvar->wait(condvar, mutex);
	}
	mutex->unlock(mutex);
	return entry;
}

/**
 * Release a socket to the pool
 */
static void put_socket(entry_t *entry)
{
	mutex->lock(mutex);
	sockets->insert_last(sockets, entry);
	mutex->unlock(mutex);
	condvar->signal(condvar);
}

/**
 * Save the state attribute to include in further request
 */
static void save_state(private_radius_client_t *this, radius_message_t *msg)
{
	enumerator_t *enumerator;
	int type;
	chunk_t data;
	
	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_STATE)
		{
			free(this->state.ptr);
			this->state = chunk_clone(data);
			enumerator->destroy(enumerator);
			return;
		}
	}
	enumerator->destroy(enumerator);
	/* no state attribute found, remove state */
	chunk_free(&this->state);
}

/**
 * Implementation of radius_client_t.request
 */
static radius_message_t* request(private_radius_client_t *this,
								 radius_message_t *req)
{
	char virtual[] = {0x00,0x00,0x00,0x05};
	radius_message_t *response;
	chunk_t data;
	fd_set fds;
	int  i;
	
	/* set Message Identifier */
	req->set_identifier(req, this->socket->identifier++);
	/* we add the "Virtual" NAS-Port-Type, as we SHOULD include one */
	req->add(req, RAT_NAS_PORT_TYPE, chunk_create(virtual, sizeof(virtual)));
	/* add our NAS-Identifier */
	req->add(req, RAT_NAS_IDENTIFIER, nas_identifier);
	/* add State attribute, if server sent one */
	if (this->state.ptr)
	{
		req->add(req, RAT_STATE, this->state);
	}
	/* sign the request */
	req->sign(req, this->socket->rng, this->socket->signer);
	
	data = req->get_encoding(req);
	FD_ZERO(&fds);
	FD_SET(this->socket->fd, &fds);
	/* timeout after 2, 3, 4, 5 seconds */
	for (i = 2; i <= 5; i++)
	{
		bool retransmit = FALSE;
		struct timeval tv;
		char buf[1024];
		int res, retry = 0;
		
		if (send(this->socket->fd, data.ptr, data.len, 0) != data.len)
		{
			DBG1(DBG_CFG, "sending RADIUS message failed: %s", strerror(errno));
			return NULL;
		}
		while (TRUE)
		{
			tv.tv_sec = i;
			tv.tv_usec = 0;
			
			res = select(this->socket->fd + 1, &fds, NULL, NULL, &tv);
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
			res = recv(this->socket->fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (res <= 0)
			{
				DBG1(DBG_CFG, "receiving RADIUS message failed: %s",
					 strerror(errno));
				break;
			}
			response = radius_message_parse_response(chunk_create(buf, res));
			if (response)
			{	
				if (response->verify(response, req->get_authenticator(req),
							secret, this->socket->hasher, this->socket->signer))
				{
					save_state(this, response);
					return response;
				}
				response->destroy(response);
			}
			/* might be a maliciously injected packet, read onother one.
			 * Limit the number of retries, an attacker could us trick into
			 * a loop otherwise. */
			if (retry++ > 5)
			{
				break;
			}
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
static chunk_t decrypt_mppe_key(private_radius_client_t *this, u_int16_t salt,
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
		this->socket->hasher->get_hash(this->socket->hasher, secret, NULL);
		this->socket->hasher->get_hash(this->socket->hasher, seed, p);
		
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

/**
 * Implementation of radius_client_t.decrypt_msk
 */
static chunk_t decrypt_msk(private_radius_client_t *this,
						   radius_message_t *response, radius_message_t *request)
{
	struct {
		u_int32_t id;
		u_int8_t type;
		u_int8_t length;
		u_int16_t salt;
		u_int8_t key[];
	} __attribute__((packed)) *mppe_key;
	enumerator_t *enumerator;
	chunk_t data, send = chunk_empty, recv = chunk_empty;
	int type;
	
	enumerator = response->create_enumerator(response);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_VENDOR_SPECIFIC &&
			data.len > sizeof(*mppe_key))
		{
			mppe_key = (void*)data.ptr;
			if (ntohl(mppe_key->id) == VENDOR_ID_MICROSOFT &&
				mppe_key->length == data.len - sizeof(mppe_key->id))
			{
				data = chunk_create(mppe_key->key, data.len - sizeof(*mppe_key));
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

/**
 * Implementation of radius_client_t.destroy.
 */
static void destroy(private_radius_client_t *this)
{
	put_socket(this->socket);
	free(this->state.ptr);
	free(this);
}

/**
 * See header
 */
radius_client_t *radius_client_create()
{
	private_radius_client_t *this = malloc_thing(private_radius_client_t);
	
	this->public.request = (radius_message_t*(*)(radius_client_t*, radius_message_t *msg))request;
	this->public.decrypt_msk = (chunk_t(*)(radius_client_t*, radius_message_t *, radius_message_t *))decrypt_msk;
	this->public.destroy = (void(*)(radius_client_t*))destroy;
	
	this->socket = get_socket();
	this->state = chunk_empty;
	
	return &this->public;
}

