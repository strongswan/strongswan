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

#include "dhcp_socket.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_arp.h>

#include <utils/linked_list.h>
#include <utils/identification.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <threading/thread.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

typedef struct private_dhcp_socket_t private_dhcp_socket_t;

/**
 * Private data of an dhcp_socket_t object.
 */
struct private_dhcp_socket_t {

	/**
	 * Public dhcp_socket_t interface.
	 */
	dhcp_socket_t public;

	/**
	 * Random number generator
	 */
	rng_t *rng;

	/**
	 * List of active transactions
	 */
	linked_list_t *active;

	/**
	 * List of successfully completed transactions
	 */
	linked_list_t *completed;

	/**
	 * Lock for transactions
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for transaction completion
	 */
	condvar_t *condvar;

	/**
	 * Threads waiting in condvar
	 */
	int waiting;

	/**
	 * RAW socket
	 */
	int skt;

	/**
	 * DHCP server address, or broadcast
	 */
	host_t *dst;

	/**
	 * Callback job receiving DHCP responses
	 */
	callback_job_t *job;
};

typedef enum {
	BOOTREQUEST = 1,
	BOOTREPLY = 2,
} dhcp_opcode_t;

typedef enum {
	DHCP_HOST_NAME = 12,
	DHCP_MESSAGE_TYPE = 53,
	DHCP_PARAM_REQ_LIST = 55,
} dhcp_option_type_t;

typedef enum {
	DHCP_DISCOVER = 1,
} dhcp_message_type_t;

typedef enum {
	DHCP_ROUTER = 3,
	DHCP_DNS_SERVER = 6,
} dhcp_parameter_t;

typedef struct __attribute__((packed)) {
	u_int8_t type;
	u_int8_t len;
	char data[];
} dhcp_option_t;

typedef struct __attribute__((packed)) {
	u_int8_t opcode;
	u_int8_t hw_type;
	u_int8_t hw_addr_len;
	u_int8_t hop_count;
	u_int32_t transaction_id;
	u_int16_t number_of_seconds;
	u_int16_t flags;
	u_int32_t client_address;
	u_int32_t your_address;
	u_int32_t server_address;
	u_int32_t gateway_address;
	char client_hw_addr[6];
	char client_hw_padding[10];
	char server_hostname[64];
	char boot_filename[128];
	u_int32_t magic_cookie;
	char options[252];
} dhcp_t;

/**
 * Send DHCP discover using a given transaction
 */
static void discover(private_dhcp_socket_t *this,
					 dhcp_transaction_t *transaction)
{
	chunk_t id_data, broadcast = chunk_from_chars(0xFF,0xFF,0xFF,0xFF);
	identification_t *identity;
	dhcp_option_t *option;
	dhcp_t dhcp;
	int optlen = 0;
	u_int hash;
	host_t *src;
	ssize_t len;

	memset(&dhcp, 0, sizeof(dhcp));
	dhcp.opcode = BOOTREQUEST;
	dhcp.hw_type = ARPHRD_ETHER;
	dhcp.hw_addr_len = 6;
	dhcp.transaction_id = transaction->get_id(transaction);
	if (chunk_equals(broadcast, this->dst->get_address(this->dst)))
	{
		/* TODO: send with 0.0.0.0 source address */
	}
	else
	{
		/* act as relay agent */
		src = charon->kernel_interface->get_source_addr(
									charon->kernel_interface, this->dst, NULL);
		if (src)
		{
			memcpy(&dhcp.gateway_address, src->get_address(src).ptr,
				   sizeof(dhcp.gateway_address));
			src->destroy(src);
		}
	}

	identity = transaction->get_identity(transaction);
	id_data = identity->get_encoding(identity);

	/* magic bytes, a locally administered unicast MAC */
	dhcp.client_hw_addr[0] = 0x7A;
	dhcp.client_hw_addr[1] = 0xA7;
	/* with ID specific postfix */
	hash = htonl(chunk_hash(id_data));
	memcpy(&dhcp.client_hw_addr[2], &hash, 4);

	dhcp.magic_cookie = htonl(0x63825363);

	option = (dhcp_option_t*)&dhcp.options[optlen];
	option->type = DHCP_MESSAGE_TYPE;
	option->len = 1;
	option->data[0] = DHCP_DISCOVER;
	optlen += sizeof(dhcp_option_t) + option->len;

	option = (dhcp_option_t*)&dhcp.options[optlen];
	option->type = DHCP_HOST_NAME;
	option->len = min(id_data.len, 64);
	memcpy(option->data, id_data.ptr, option->len);
	optlen += sizeof(dhcp_option_t) + option->len;

	option = (dhcp_option_t*)&dhcp.options[optlen];
	option->type = DHCP_PARAM_REQ_LIST;
	option->len = 2;
	option->data[0] = DHCP_ROUTER;
	option->data[1] = DHCP_DNS_SERVER;
	optlen += sizeof(dhcp_option_t) + option->len;

	dhcp.options[optlen++] = 0xFF;

	len = offsetof(dhcp_t, magic_cookie) + ((optlen + 4) / 64 * 64 + 64);
	if (sendto(this->skt, &dhcp, len, 0, this->dst->get_sockaddr(this->dst),
			   *this->dst->get_sockaddr_len(this->dst)) != len)
	{
		DBG1(DBG_CFG, "sending DHCP DISCOVER failed: %s", strerror(errno));
	}
}

METHOD(dhcp_socket_t, enroll, dhcp_transaction_t*,
	private_dhcp_socket_t *this, identification_t *identity)
{
	dhcp_transaction_t *transaction;
	u_int32_t id;

	this->rng->get_bytes(this->rng, sizeof(id), (u_int8_t*)&id);
	transaction = dhcp_transaction_create(id, identity);
	discover(this, transaction);
	transaction->destroy(transaction);

	return NULL;
}

METHOD(dhcp_socket_t, destroy, void,
	private_dhcp_socket_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	while (this->waiting)
	{
		this->condvar->signal(this->condvar);
	}
	if (this->skt > 0)
	{
		close(this->skt);
	}
	this->mutex->destroy(this->mutex);
	this->condvar->destroy(this->condvar);
	this->active->destroy(this->active);
	this->completed->destroy(this->completed);
	DESTROY_IF(this->rng);
	DESTROY_IF(this->dst);
	free(this);
}

/**
 * See header
 */
dhcp_socket_t *dhcp_socket_create()
{
	private_dhcp_socket_t *this;
	struct sockaddr_in src;
	int on = 1;

	INIT(this,
		.public = {
			.enroll = _enroll,
			.destroy = _destroy,
		},
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.active = linked_list_create(),
		.completed = linked_list_create(),
	);

	if (!this->rng)
	{
		DBG1(DBG_CFG, "unable to create RNG");
		destroy(this);
		return NULL;
	}

	this->dst = host_create_from_string(lib->settings->get_str(lib->settings,
							"charon.plugins.dhcp.server", "255.255.255.255"),
							DHCP_SERVER_PORT);
	if (!this->dst)
	{
		DBG1(DBG_CFG, "configured DHCP server address invalid");
		destroy(this);
		return NULL;
	}

	this->skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (this->skt == -1)
	{
		DBG1(DBG_CFG, "unable to create DHCP send socket: %s", strerror(errno));
		destroy(this);
		return NULL;
	}

	if (setsockopt(this->skt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
	{
		DBG1(DBG_CFG, "unable to reuse DHCP socket address: %s", strerror(errno));
		destroy(this);
		return NULL;
	}
	if (setsockopt(this->skt, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1)
	{
		DBG1(DBG_CFG, "unable to broadcast on DHCP socket: %s", strerror(errno));
		destroy(this);
		return NULL;
	}

	src.sin_family = AF_INET;
	src.sin_port = htons(DHCP_CLIENT_PORT);
	src.sin_addr.s_addr = INADDR_ANY;
	if (bind(this->skt, (struct sockaddr*)&src, sizeof(src)) == -1)
	{
		DBG1(DBG_CFG, "unable to bind DHCP send socket: %s", strerror(errno));
		destroy(this);
		return NULL;
	}

	return &this->public;
}

