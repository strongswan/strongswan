/**
 * @file ike_natd.c
 *
 * @brief Implementation of the ike_natd task.
 *
 */

/*
 * Copyright (C) 2006-2007 Martin Willi
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#include "ike_natd.h"

#include <string.h>

#include <daemon.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/notify_payload.h>


typedef struct private_ike_natd_t private_ike_natd_t;

/**
 * Private members of a ike_natd_t task.
 */
struct private_ike_natd_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_natd_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * Hasher used to build NAT detection hashes
	 */
	hasher_t *hasher;
	
	/**
	 * Did we process any NAT detection notifys for a source address?
	 */
	bool src_seen;
	
	/**
	 * Did we process any NAT detection notifys for a destination address?
	 */
	bool dst_seen;
	
	/**
	 * Have we found a matching source address NAT hash?
	 */
	bool src_matched;
	
	/**
	 * Have we found a matching destination address NAT hash?
	 */
	bool dst_matched;
};


/**
 * Build NAT detection hash for a host
 */
static chunk_t generate_natd_hash(private_ike_natd_t *this,
								  ike_sa_id_t *ike_sa_id, host_t *host)
{
	chunk_t natd_chunk, spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk;
	chunk_t natd_hash;
	u_int64_t spi_i, spi_r;
	u_int16_t port;
	
	/* prepare all requred chunks */
	spi_i = ike_sa_id->get_initiator_spi(ike_sa_id);
	spi_r = ike_sa_id->get_responder_spi(ike_sa_id);
	spi_i_chunk.ptr = (void*)&spi_i;
	spi_i_chunk.len = sizeof(spi_i);
	spi_r_chunk.ptr = (void*)&spi_r;
	spi_r_chunk.len = sizeof(spi_r);
	port = htons(host->get_port(host));
	port_chunk.ptr = (void*)&port;
	port_chunk.len = sizeof(port);
	addr_chunk = host->get_address(host);
	DBG2(DBG_IKE, "using SPI %J", ike_sa_id);
		
	/*  natd_hash = SHA1( spi_i | spi_r | address | port ) */
	natd_chunk = chunk_cat("cccc", spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk);
	this->hasher->allocate_hash(this->hasher, natd_chunk, &natd_hash);
	DBG3(DBG_IKE, "natd_chunk %B", &natd_chunk);
	DBG3(DBG_IKE, "natd_hash %B", &natd_hash);
	
	chunk_free(&natd_chunk);
	return natd_hash;
}

/**
 * Build a NAT detection notify payload.
 */
static notify_payload_t *build_natd_payload(private_ike_natd_t *this,
											notify_type_t type, host_t *host)
{
	chunk_t hash;
	notify_payload_t *notify;	
	ike_sa_id_t *ike_sa_id;	
	
	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	hash = generate_natd_hash(this, ike_sa_id, host);
	notify->set_notification_data(notify, hash);
	chunk_free(&hash);
	
	return notify;
}

/**
 * read notifys from message and evaluate them
 */
static void process_payloads(private_ike_natd_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	notify_payload_t *notify;
	chunk_t hash, src_hash, dst_hash;
	ike_sa_id_t *ike_sa_id;
	host_t *me, *other;
	
	/* Precompute NAT-D hashes for incoming NAT notify comparison */
	ike_sa_id = message->get_ike_sa_id(message);
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	dst_hash = generate_natd_hash(this, ike_sa_id, me);
	src_hash = generate_natd_hash(this, ike_sa_id, other);
	
	DBG2(DBG_IKE, "precalculated src_hash %B", &src_hash);
	DBG2(DBG_IKE, "precalculated dst_hash %B", &dst_hash);
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) != NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		switch (notify->get_notify_type(notify))
		{
			case NAT_DETECTION_DESTINATION_IP:
			{
				this->dst_seen = TRUE;
				if (!this->dst_matched)
				{
					hash = notify->get_notification_data(notify);
					DBG2(DBG_IKE, "received dst_hash %B", &hash);
					if (chunk_equals(hash, dst_hash))
					{
						this->dst_matched = TRUE;
					}
				}
				break;
			}
			case NAT_DETECTION_SOURCE_IP:
			{
				this->src_seen = TRUE;
				if (!this->src_matched)
				{
					hash = notify->get_notification_data(notify);
					DBG2(DBG_IKE, "received src_hash %B", &hash);
					if (chunk_equals(hash, src_hash))
					{
						this->src_matched = TRUE;
					}
				}
				break;
			}
			default:
				break;
		}
	}
	iterator->destroy(iterator);
	
	chunk_free(&src_hash);
	chunk_free(&dst_hash);
	
	if (this->src_seen && this->dst_seen)
	{
		if (!this->dst_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, TRUE);
		}
		if (!this->src_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, FALSE);
		}
	}
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_natd_t *this, message_t *message)
{
	process_payloads(this, message);

	if (this->ike_sa->is_natt_enabled(this->ike_sa))
	{
		host_t *me, *other;
	
		me = this->ike_sa->get_my_host(this->ike_sa);
		me->set_port(me, IKEV2_NATT_PORT);
		other = this->ike_sa->get_other_host(this->ike_sa);
		other->set_port(other, IKEV2_NATT_PORT);
	}
	
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_natd_t *this, message_t *message)
{
	notify_payload_t *notify;
	linked_list_t *list;
	host_t *host;
	
	/* include one notify if our address is defined, all addresses otherwise */
	host = this->ike_sa->get_my_host(this->ike_sa);
	if (host->is_anyaddr(host))
	{
		/* TODO: we could get the src address from netlink!? */
		list = charon->kernel_interface->create_address_list(charon->kernel_interface);
		while (list->remove_first(list, (void**)&host) == SUCCESS)
		{
			notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
			host->destroy(host);
			message->add_payload(message, (payload_t*)notify);
		}
		list->destroy(list);
	}
	else
	{
		notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
		message->add_payload(message, (payload_t*)notify);
	}
	
	host = this->ike_sa->get_other_host(this->ike_sa);
	notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, host);
	message->add_payload(message, (payload_t*)notify);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_natd_t *this, message_t *message)
{
	notify_payload_t *notify;
	host_t *me, *other;
	iterator_t *iterator;
	u_int count;
	
	/* when only one payload is in the message, an error occured.
	 * TODO: find a better hack */
	iterator = message->get_payload_iterator(message);
	count = iterator->get_count(iterator);
	iterator->destroy(iterator);
	if (count < 3)
	{
		return NEED_MORE;
	}

	if (this->src_seen && this->dst_seen)
	{
		/* initiator seems to support NAT detection, add response */
		me = this->ike_sa->get_my_host(this->ike_sa);
		notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, me);
		message->add_payload(message, (payload_t*)notify);
		
		other = this->ike_sa->get_other_host(this->ike_sa);
		notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, other);
		message->add_payload(message, (payload_t*)notify);
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_natd_t *this, message_t *message)
{	
	process_payloads(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_natd_t *this)
{
	return IKE_NATD;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_natd_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->src_seen = FALSE;
	this->dst_seen = FALSE;
	this->src_matched = FALSE;
	this->dst_matched = FALSE;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_natd_t *this)
{
	this->hasher->destroy(this->hasher);
	free(this);
}

/*
 * Described in header.
 */
ike_natd_t *ike_natd_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_natd_t *this = malloc_thing(private_ike_natd_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	
	if (initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
	}
	
	this->ike_sa = ike_sa;
	this->initiator = initiator;
	this->hasher = hasher_create(HASH_SHA1);
	this->src_seen = FALSE;
	this->dst_seen = FALSE;
	this->src_matched = FALSE;
	this->dst_matched = FALSE;
	
	return &this->public;
}
