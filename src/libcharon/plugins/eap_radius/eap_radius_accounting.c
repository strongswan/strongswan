/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "eap_radius_accounting.h"
#include "eap_radius_plugin.h"

#include <time.h>

#include <radius_message.h>
#include <radius_client.h>
#include <daemon.h>
#include <utils/hashtable.h>
#include <threading/mutex.h>

typedef struct private_eap_radius_accounting_t private_eap_radius_accounting_t;

/**
 * Private data of an eap_radius_accounting_t object.
 */
struct private_eap_radius_accounting_t {

	/**
	 * Public eap_radius_accounting_t interface.
	 */
	eap_radius_accounting_t public;

	/**
	 * Hashtable with sessions, IKE_SA unique id => entry_t
	 */
	hashtable_t *sessions;

	/**
	 * Mutex to lock sessions
	 */
	mutex_t *mutex;

	/**
	 * Session ID prefix
	 */
	u_int32_t prefix;
};

/**
 * Hashtable entry with usage stats
 */
typedef struct {
	/** RADIUS accounting session ID */
	char sid[16];
	/** number of octets sent */
	u_int64_t sent;
	/** number of octets received */
	u_int64_t received;
	/** session creation time */
	time_t created;
} entry_t;

/**
 * Accounting message status types
 */
typedef enum {
	ACCT_STATUS_START = 1,
	ACCT_STATUS_STOP = 2,
	ACCT_STATUS_INTERIM_UPDATE = 3,
	ACCT_STATUS_ACCOUNTING_ON = 7,
	ACCT_STATUS_ACCOUNTING_OFF = 8,
} radius_acct_status_t;

/**
 * Hashtable hash function
 */
static u_int hash(uintptr_t key)
{
	return key;
}

/**
 * Hashtable equals function
 */
static bool equals(uintptr_t a, uintptr_t b)
{
	return a == b;
}

/**
 * Update usage counter when a CHILD_SA rekeys/goes down
 */
static void update_usage(private_eap_radius_accounting_t *this,
						 ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	u_int64_t sent, received;
	entry_t *entry;

	child_sa->get_usestats(child_sa, FALSE, NULL, &sent);
	child_sa->get_usestats(child_sa, TRUE, NULL, &received);

	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions,
								(void*)(uintptr_t)ike_sa->get_unique_id(ike_sa));
	if (entry)
	{
		entry->sent += sent;
		entry->received += received;
	}
	this->mutex->unlock(this->mutex);
}

/**
 * Send a RADIUS message, wait for response
 */
static bool send_message(private_eap_radius_accounting_t *this,
						 radius_message_t *request)
{
	radius_message_t *response;
	radius_client_t *client;
	bool ack = FALSE;

	client = eap_radius_create_client();
	if (client)
	{
		response = client->request(client, request);
		if (response)
		{
			ack = response->get_code(response) == RMC_ACCOUNTING_RESPONSE;
			response->destroy(response);
		}
		else
		{
			charon->bus->alert(charon->bus, ALERT_RADIUS_NOT_RESPONDING);
		}
		client->destroy(client);
	}
	return ack;
}

/**
 * Add common IKE_SA parameters to RADIUS account message
 */
static void add_ike_sa_parameters(radius_message_t *message, ike_sa_t *ike_sa)
{
	host_t *vip;
	char buf[64];
	chunk_t data;

	snprintf(buf, sizeof(buf), "%Y", ike_sa->get_other_eap_id(ike_sa));
	message->add(message, RAT_USER_NAME, chunk_create(buf, strlen(buf)));
	snprintf(buf, sizeof(buf), "%#H", ike_sa->get_other_host(ike_sa));
	message->add(message, RAT_CALLING_STATION_ID, chunk_create(buf, strlen(buf)));
	vip = ike_sa->get_virtual_ip(ike_sa, FALSE);
	if (vip && vip->get_family(vip) == AF_INET)
	{
		message->add(message, RAT_FRAMED_IP_ADDRESS, vip->get_address(vip));
	}
	if (vip && vip->get_family(vip) == AF_INET6)
	{
		/* we currently assign /128 prefixes, only (reserved, length) */
		data = chunk_from_chars(0, 128);
		data = chunk_cata("cc", data, vip->get_address(vip));
		message->add(message, RAT_FRAMED_IPV6_PREFIX, data);
	}
}

/**
 * Send an accounting start message
 */
static void send_start(private_eap_radius_accounting_t *this, ike_sa_t *ike_sa)
{
	radius_message_t *message;
	entry_t *entry;
	u_int32_t id, value;

	id = ike_sa->get_unique_id(ike_sa);
	INIT(entry,
		.created = time_monotonic(NULL),
	);
	snprintf(entry->sid, sizeof(entry->sid), "%u-%u", this->prefix, id);

	message = radius_message_create(RMC_ACCOUNTING_REQUEST);
	value = htonl(ACCT_STATUS_START);
	message->add(message, RAT_ACCT_STATUS_TYPE, chunk_from_thing(value));
	message->add(message, RAT_ACCT_SESSION_ID,
				 chunk_create(entry->sid, strlen(entry->sid)));
	add_ike_sa_parameters(message, ike_sa);
	if (send_message(this, message))
	{
		this->mutex->lock(this->mutex);
		entry = this->sessions->put(this->sessions, (void*)(uintptr_t)id, entry);
		this->mutex->unlock(this->mutex);
		free(entry);
	}
	message->destroy(message);
}

/**
 * Send an account stop message
 */
static void send_stop(private_eap_radius_accounting_t *this, ike_sa_t *ike_sa)
{
	radius_message_t *message;
	entry_t *entry;
	u_int32_t id, value;

	id = ike_sa->get_unique_id(ike_sa);
	this->mutex->lock(this->mutex);
	entry = this->sessions->remove(this->sessions, (void*)(uintptr_t)id);
	this->mutex->unlock(this->mutex);
	if (entry)
	{
		message = radius_message_create(RMC_ACCOUNTING_REQUEST);
		value = htonl(ACCT_STATUS_STOP);
		message->add(message, RAT_ACCT_STATUS_TYPE, chunk_from_thing(value));
		message->add(message, RAT_ACCT_SESSION_ID,
					 chunk_create(entry->sid, strlen(entry->sid)));
		add_ike_sa_parameters(message, ike_sa);
		value = htonl(entry->sent);
		message->add(message, RAT_ACCT_OUTPUT_OCTETS, chunk_from_thing(value));
		value = htonl(entry->sent >> 32);
		if (value)
		{
			message->add(message, RAT_ACCT_OUTPUT_GIGAWORDS,
						 chunk_from_thing(value));
		}
		value = htonl(entry->received);
		message->add(message, RAT_ACCT_INPUT_OCTETS, chunk_from_thing(value));
		value = htonl(entry->received >> 32);
		if (value)
		{
			message->add(message, RAT_ACCT_INPUT_GIGAWORDS,
						 chunk_from_thing(value));
		}
		value = htonl(time_monotonic(NULL) - entry->created);
		message->add(message, RAT_ACCT_SESSION_TIME, chunk_from_thing(value));

		send_message(this, message);
		message->destroy(message);
		free(entry);
	}
}

METHOD(listener_t, ike_updown, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *ike_sa, bool up)
{
	if (!up)
	{
		enumerator_t *enumerator;
		child_sa_t *child_sa;

		/* update usage for all children just before sending stop */
		enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
		while (enumerator->enumerate(enumerator, &child_sa))
		{
			update_usage(this, ike_sa, child_sa);
		}
		enumerator->destroy(enumerator);

		send_stop(this, ike_sa);
	}
	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming)
{
	/* start accounting here, virtual IP now is set */
	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		message->get_exchange_type(message) == IKE_AUTH &&
		!incoming && !message->get_request(message))
	{
		send_start(this, ike_sa);
	}
	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *ike_sa,
	child_sa_t *old, child_sa_t *new)
{
	update_usage(this, ike_sa, old);

	return TRUE;
}

METHOD(listener_t, child_updown, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *ike_sa,
	child_sa_t *child_sa, bool up)
{
	if (!up && ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		update_usage(this, ike_sa, child_sa);
	}
	return TRUE;
}

METHOD(eap_radius_accounting_t, destroy, void,
	private_eap_radius_accounting_t *this)
{
	this->mutex->destroy(this->mutex);
	this->sessions->destroy(this->sessions);
	free(this);
}

/**
 * See header
 */
eap_radius_accounting_t *eap_radius_accounting_create()
{
	private_eap_radius_accounting_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
				.message = _message_hook,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
			},
			.destroy = _destroy,
		},
		/* use system time as Session ID prefix */
		.prefix = (u_int32_t)time(NULL),
		.sessions = hashtable_create((hashtable_hash_t)hash,
									 (hashtable_equals_t)equals, 32),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
