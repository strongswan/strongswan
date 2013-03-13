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
#include <collections/hashtable.h>
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
 * Acct-Terminate-Cause
 */
typedef enum {
	ACCT_CAUSE_USER_REQUEST = 1,
	ACCT_CAUSE_LOST_CARRIER = 2,
	ACCT_CAUSE_LOST_SERVICE = 3,
	ACCT_CAUSE_IDLE_TIMEOUT = 4,
	ACCT_CAUSE_SESSION_TIMEOUT = 5,
	ACCT_CAUSE_ADMIN_RESET = 6,
	ACCT_CAUSE_ADMIN_REBOOT = 7,
	ACCT_CAUSE_PORT_ERROR = 8,
	ACCT_CAUSE_NAS_ERROR = 9,
	ACCT_CAUSE_NAS_REQUEST = 10,
	ACCT_CAUSE_NAS_REBOOT = 11,
	ACCT_CAUSE_PORT_UNNEEDED = 12,
	ACCT_CAUSE_PORT_PREEMPTED = 13,
	ACCT_CAUSE_PORT_SUSPENDED = 14,
	ACCT_CAUSE_SERVICE_UNAVAILABLE = 15,
	ACCT_CAUSE_CALLBACK = 16,
	ACCT_CAUSE_USER_ERROR = 17,
	ACCT_CAUSE_HOST_REQUEST = 18,
} radius_acct_terminate_cause_t;

/**
 * Hashtable entry with usage stats
 */
typedef struct {
	/** RADIUS accounting session ID */
	char sid[16];
	/** number of sent/received octets/packets */
	struct {
		u_int64_t sent;
		u_int64_t received;
	} bytes, packets;
	/** session creation time */
	time_t created;
	/** terminate cause */
	radius_acct_terminate_cause_t cause;
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
	u_int64_t bytes_in, bytes_out, packets_in, packets_out;
	entry_t *entry;

	child_sa->get_usestats(child_sa, FALSE, NULL, &bytes_out, &packets_out);
	child_sa->get_usestats(child_sa, TRUE, NULL, &bytes_in, &packets_in);

	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions,
								(void*)(uintptr_t)ike_sa->get_unique_id(ike_sa));
	if (entry)
	{
		entry->bytes.sent += bytes_out;
		entry->bytes.received += bytes_in;
		entry->packets.sent += packets_out;
		entry->packets.received += packets_in;
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
	enumerator_t *enumerator;
	host_t *vip, *host;
	char buf[64];
	chunk_t data;
	u_int32_t value;

	/* virtual NAS-Port-Type */
	value = htonl(5);
	message->add(message, RAT_NAS_PORT_TYPE, chunk_from_thing(value));
	/* framed ServiceType */
	value = htonl(2);
	message->add(message, RAT_SERVICE_TYPE, chunk_from_thing(value));

	value = htonl(ike_sa->get_unique_id(ike_sa));
	message->add(message, RAT_NAS_PORT, chunk_from_thing(value));
	message->add(message, RAT_NAS_PORT_ID,
				 chunk_from_str(ike_sa->get_name(ike_sa)));

	host = ike_sa->get_my_host(ike_sa);
	data = host->get_address(host);
	switch (host->get_family(host))
	{
		case AF_INET:
			message->add(message, RAT_NAS_IP_ADDRESS, data);
			break;
		case AF_INET6:
			message->add(message, RAT_NAS_IPV6_ADDRESS, data);
		default:
			break;
	}
	snprintf(buf, sizeof(buf), "%#H", host);
	message->add(message, RAT_CALLED_STATION_ID, chunk_from_str(buf));
	host = ike_sa->get_other_host(ike_sa);
	snprintf(buf, sizeof(buf), "%#H", host);
	message->add(message, RAT_CALLING_STATION_ID, chunk_from_str(buf));

	snprintf(buf, sizeof(buf), "%Y", ike_sa->get_other_eap_id(ike_sa));
	message->add(message, RAT_USER_NAME, chunk_from_str(buf));

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (enumerator->enumerate(enumerator, &vip))
	{
		switch (vip->get_family(vip))
		{
			case AF_INET:
				message->add(message, RAT_FRAMED_IP_ADDRESS,
							 vip->get_address(vip));
				break;
			case AF_INET6:
				/* we currently assign /128 prefixes, only (reserved, length) */
				data = chunk_from_chars(0, 128);
				data = chunk_cata("cc", data, vip->get_address(vip));
				message->add(message, RAT_FRAMED_IPV6_PREFIX, data);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
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
		/* default terminate cause, if none other catched */
		.cause = ACCT_CAUSE_USER_REQUEST,
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
	}
	message->destroy(message);
	free(entry);
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

		value = htonl(entry->bytes.sent);
		message->add(message, RAT_ACCT_OUTPUT_OCTETS, chunk_from_thing(value));
		value = htonl(entry->bytes.sent >> 32);
		if (value)
		{
			message->add(message, RAT_ACCT_OUTPUT_GIGAWORDS,
						 chunk_from_thing(value));
		}
		value = htonl(entry->packets.sent);
		message->add(message, RAT_ACCT_OUTPUT_PACKETS, chunk_from_thing(value));

		value = htonl(entry->bytes.received);
		message->add(message, RAT_ACCT_INPUT_OCTETS, chunk_from_thing(value));
		value = htonl(entry->bytes.received >> 32);
		if (value)
		{
			message->add(message, RAT_ACCT_INPUT_GIGAWORDS,
						 chunk_from_thing(value));
		}
		value = htonl(entry->packets.received);
		message->add(message, RAT_ACCT_INPUT_PACKETS, chunk_from_thing(value));

		value = htonl(time_monotonic(NULL) - entry->created);
		message->add(message, RAT_ACCT_SESSION_TIME, chunk_from_thing(value));


		value = htonl(entry->cause);
		message->add(message, RAT_ACCT_TERMINATE_CAUSE, chunk_from_thing(value));

		send_message(this, message);
		message->destroy(message);
		free(entry);
	}
}

METHOD(listener_t, alert, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *ike_sa, alert_t alert,
	va_list args)
{
	radius_acct_terminate_cause_t cause;
	entry_t *entry;

	switch (alert)
	{
		case ALERT_IKE_SA_EXPIRED:
			cause = ACCT_CAUSE_SESSION_TIMEOUT;
			break;
		case ALERT_RETRANSMIT_SEND_TIMEOUT:
			cause = ACCT_CAUSE_LOST_SERVICE;
			break;
		default:
			return TRUE;
	}
	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions,
								(void*)(uintptr_t)ike_sa->get_unique_id(ike_sa));
	if (entry)
	{
		entry->cause = cause;
	}
	this->mutex->unlock(this->mutex);
	return TRUE;
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
	message_t *message, bool incoming, bool plain)
{
	/* start accounting here, virtual IP now is set */
	if (plain && ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		!incoming && !message->get_request(message))
	{
		if (ike_sa->get_version(ike_sa) == IKEV1 &&
			message->get_exchange_type(message) == TRANSACTION)
		{
			send_start(this, ike_sa);
		}
		if (ike_sa->get_version(ike_sa) == IKEV2 &&
			message->get_exchange_type(message) == IKE_AUTH)
		{
			send_start(this, ike_sa);
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	private_eap_radius_accounting_t *this, ike_sa_t *old, ike_sa_t *new)
{
	entry_t *entry;

	this->mutex->lock(this->mutex);
	entry = this->sessions->remove(this->sessions,
							(void*)(uintptr_t)old->get_unique_id(old));
	if (entry)
	{
		entry = this->sessions->put(this->sessions,
							(void*)(uintptr_t)new->get_unique_id(new), entry);
		if (entry)
		{
			free(entry);
		}
	}
	this->mutex->unlock(this->mutex);

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
				.alert = _alert,
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
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
