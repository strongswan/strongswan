/*
 * Copyright (C) 2007 Martin Willi
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

#include "ike_mobike.h"

#include <string.h>

#include <daemon.h>
#include <sa/tasks/ike_natd.h>
#include <encoding/payloads/notify_payload.h>

#define COOKIE2_SIZE 16

typedef struct private_ike_mobike_t private_ike_mobike_t;

/**
 * Private members of a ike_mobike_t task.
 */
struct private_ike_mobike_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_mobike_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * cookie2 value to verify new addresses
	 */
	chunk_t cookie2;
	
	/**
	 * NAT discovery reusing the IKE_NATD task
	 */
	ike_natd_t *natd;
	
	/**
	 * use task to update addresses
	 */
	bool update;
	
	/**
	 * do routability check
	 */
	bool check;
	
	/**
	 * include address list update
	 */
	bool address;
};

/**
 * flush the IKE_SAs list of additional addresses
 */
static void flush_additional_addresses(private_ike_mobike_t *this)
{
	iterator_t *iterator;
	host_t *host;
	
	iterator = this->ike_sa->create_additional_address_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&host))
	{
		iterator->remove(iterator);
		host->destroy(host);
	}
	iterator->destroy(iterator);
}


/**
 * read notifys from message and evaluate them
 */
static void process_payloads(private_ike_mobike_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	bool first = TRUE;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		int family = AF_INET;
		notify_payload_t *notify;
		chunk_t data;
		host_t *host;
		
		if (payload->get_type(payload) != NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		switch (notify->get_notify_type(notify))
		{
			case MOBIKE_SUPPORTED:
			{
				peer_cfg_t *peer_cfg;
				
				peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
				if (!this->initiator && 
					peer_cfg && !peer_cfg->use_mobike(peer_cfg))
				{
					DBG1(DBG_IKE, "peer supports MOBIKE, but disabled in config");
				}
				else
				{
					DBG1(DBG_IKE, "peer supports MOBIKE");
					this->ike_sa->enable_extension(this->ike_sa, EXT_MOBIKE);
				}
				break;
			}
			case COOKIE2:
			{
				chunk_free(&this->cookie2);
				this->cookie2 = chunk_clone(notify->get_notification_data(notify));
				break;
			}
			case ADDITIONAL_IP6_ADDRESS:
			{
				family = AF_INET6;
				/* fall through */
			}
			case ADDITIONAL_IP4_ADDRESS:
			{
				if (first)
				{	/* an ADDITIONAL_*_ADDRESS means replace, so flush once */
					flush_additional_addresses(this);
					first = FALSE;
				}
				data = notify->get_notification_data(notify);
				host = host_create_from_chunk(family, data, 0);
				DBG2(DBG_IKE, "got additional MOBIKE peer address: %H", host);
				this->ike_sa->add_additional_address(this->ike_sa, host);
				break;
			}
			case UPDATE_SA_ADDRESSES:
			{
				this->update = TRUE;
				break;
			}
			case NO_ADDITIONAL_ADDRESSES:
			{
				flush_additional_addresses(this);
				break;
			}
			case NAT_DETECTION_SOURCE_IP:
			case NAT_DETECTION_DESTINATION_IP:
			{
				/* NAT check in this MOBIKE exchange, create subtask for it */
				if (this->natd == NULL)
				{
					this->natd = ike_natd_create(this->ike_sa, this->initiator);
				}
				break;
			}
			default:
				break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Add ADDITIONAL_*_ADDRESS notifys depending on our address list
 */
static void build_address_list(private_ike_mobike_t *this, message_t *message)
{
	enumerator_t *enumerator;
	host_t *host, *me;
	notify_type_t type;
	bool additional = FALSE;

	me = this->ike_sa->get_my_host(this->ike_sa);
	enumerator = charon->kernel_interface->create_address_enumerator(
										charon->kernel_interface, FALSE, FALSE);
	while (enumerator->enumerate(enumerator, (void**)&host))
	{
		if (me->ip_equals(me, host))
		{	/* "ADDITIONAL" means do not include IKE_SAs host */
			continue;
		}
		switch (host->get_family(host))
		{
			case AF_INET:
				type = ADDITIONAL_IP4_ADDRESS;
				break;
			case AF_INET6:
				type = ADDITIONAL_IP6_ADDRESS;
				break;
			default:
				continue;
		}
		message->add_notify(message, FALSE, type, host->get_address(host));
		additional = TRUE;
	}
	if (!additional)
	{
		message->add_notify(message, FALSE, NO_ADDITIONAL_ADDRESSES, chunk_empty);
	}
	enumerator->destroy(enumerator);
}

/**
 * build a cookie and add it to the message 
 */
static void build_cookie(private_ike_mobike_t *this, message_t *message)
{
	rng_t *rng;

	chunk_free(&this->cookie2);
	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (rng)
	{
		rng->allocate_bytes(rng, COOKIE2_SIZE, &this->cookie2);
		rng->destroy(rng);
		message->add_notify(message, FALSE, COOKIE2, this->cookie2);
	}
}

/**
 * update addresses of associated CHILD_SAs
 */
static void update_children(private_ike_mobike_t *this)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	
	iterator = this->ike_sa->create_child_sa_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		child_sa->update_hosts(child_sa,
						this->ike_sa->get_my_host(this->ike_sa), 
						this->ike_sa->get_other_host(this->ike_sa),
						this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY));
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of ike_mobike_t.transmit
 */
static void transmit(private_ike_mobike_t *this, packet_t *packet)
{
	host_t *me, *other, *me_old, *other_old;
	iterator_t *iterator;
	packet_t *copy;
	
	if (!this->check)
	{
		return;
	}

	me_old = this->ike_sa->get_my_host(this->ike_sa);
	other_old = this->ike_sa->get_other_host(this->ike_sa);
	
	me = charon->kernel_interface->get_source_addr(
										charon->kernel_interface, other_old);
	if (me)
	{
		me->set_port(me, me->ip_equals(me, me_old) ?
					 me_old->get_port(me_old) : IKEV2_NATT_PORT);
		packet->set_source(packet, me);
	}
	
	iterator = this->ike_sa->create_additional_address_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&other))
	{
		me = charon->kernel_interface->get_source_addr(
											charon->kernel_interface, other);
		if (me)
		{
			if (me->get_family(me) != other->get_family(other))
			{
				me->destroy(me);
				continue;
			}
			/* reuse port for an active address, 4500 otherwise */
			me->set_port(me, me->ip_equals(me, me_old) ?
						 me_old->get_port(me_old) : IKEV2_NATT_PORT);
			other = other->clone(other);
			other->set_port(other, other->ip_equals(other, other_old) ?
							other_old->get_port(other_old) : IKEV2_NATT_PORT);
			DBG1(DBG_IKE, "checking path %#H - %#H", me, other);
			copy = packet->clone(packet);
			copy->set_source(copy, me);
			copy->set_destination(copy, other);
			charon->sender->send(charon->sender, copy);
		}
	}
	iterator->destroy(iterator);
	me = packet->get_source(packet);
	other = packet->get_destination(packet);
	DBG1(DBG_IKE, "checking path %#H - %#H", me, other);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_mobike_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		message->get_payload(message, ID_INITIATOR))
	{
		message->add_notify(message, FALSE, MOBIKE_SUPPORTED, chunk_empty);
		build_address_list(this, message);
	}
	else if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		if (this->update)
		{
			message->add_notify(message, FALSE, UPDATE_SA_ADDRESSES, chunk_empty);
			build_cookie(this, message);
			update_children(this);
		}
		if (this->address)
		{
			build_address_list(this, message);
		}
		if (this->natd)
		{
			this->natd->task.build(&this->natd->task, message);
		}
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_mobike_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		message->get_payload(message, ID_INITIATOR))
	{
		process_payloads(this, message);
	}
	else if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		process_payloads(this, message);
		if (this->update)
		{
			host_t *me, *other;
			
			me = message->get_destination(message);
			other = message->get_source(message);
			this->ike_sa->set_my_host(this->ike_sa, me->clone(me));
			this->ike_sa->set_other_host(this->ike_sa, other->clone(other));
		}
		
		if (this->natd)
		{
			this->natd->task.process(&this->natd->task, message);
		}
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_mobike_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{
		if (this->ike_sa->supports_extension(this->ike_sa, EXT_MOBIKE))
		{
			message->add_notify(message, FALSE, MOBIKE_SUPPORTED, chunk_empty);
			build_address_list(this, message);
		}
		return SUCCESS;
	}
	else if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		if (this->natd)
		{
			this->natd->task.build(&this->natd->task, message);
		}
		if (this->cookie2.ptr)
		{
			message->add_notify(message, FALSE, COOKIE2, this->cookie2);
			chunk_free(&this->cookie2);
		}
		if (this->update)
		{
			update_children(this);
		}
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_mobike_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{
		process_payloads(this, message);
		return SUCCESS;
	}
	else if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		u_int32_t updates = this->ike_sa->get_pending_updates(this->ike_sa) - 1;
		this->ike_sa->set_pending_updates(this->ike_sa, updates);
		if (updates > 0)
		{
			/* newer update queued, ignore this one */
			return SUCCESS;
		}
		if (this->cookie2.ptr)
		{	/* check cookie if we included none */
			chunk_t cookie2;
			
			cookie2 = this->cookie2;
			this->cookie2 = chunk_empty;
			process_payloads(this, message);
			if (!chunk_equals(cookie2, this->cookie2))
			{
				chunk_free(&cookie2);
				DBG1(DBG_IKE, "COOKIE2 mismatch, closing IKE_SA");
				return FAILED;
			}
			chunk_free(&cookie2);
		}
		else
		{
			process_payloads(this, message);
		}
		if (this->natd)
		{
			this->natd->task.process(&this->natd->task, message);
		}
		if (this->update)
		{
			/* update again, as NAT state may have changed */
			update_children(this);
		}
		if (this->check)
		{
			host_t *me_new, *me_old, *other_new, *other_old;
			
			me_new = message->get_destination(message);
			other_new = message->get_source(message);
			me_old = this->ike_sa->get_my_host(this->ike_sa);
			other_old = this->ike_sa->get_other_host(this->ike_sa);
			
			if (!me_new->equals(me_new, me_old))
			{
				this->update = TRUE;
				this->ike_sa->set_my_host(this->ike_sa, me_new->clone(me_new));
			}			
			if (!other_new->equals(other_new, other_old))
			{
				this->update = TRUE;
				this->ike_sa->set_other_host(this->ike_sa, other_new->clone(other_new));
			}
			if (this->update)
			{
				/* start the update with the same task */
				this->check = FALSE;
				this->address = FALSE;
				this->natd = ike_natd_create(this->ike_sa, this->initiator);
				this->ike_sa->set_pending_updates(this->ike_sa, 1);
				return NEED_MORE;
			}
		}
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of ike_mobike_t.roam.
 */
static void roam(private_ike_mobike_t *this, bool address)
{
	this->check = TRUE;
	this->address = address;
	this->ike_sa->set_pending_updates(this->ike_sa, 
							this->ike_sa->get_pending_updates(this->ike_sa) + 1);
}

/**
 * Implementation of ike_mobike_t.is_probing.
 */
static bool is_probing(private_ike_mobike_t *this)
{
	return this->check;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_mobike_t *this)
{
	return IKE_MOBIKE;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_mobike_t *this, ike_sa_t *ike_sa)
{
	chunk_free(&this->cookie2);
	this->ike_sa = ike_sa;
	if (this->natd)
	{
		this->natd->task.migrate(&this->natd->task, ike_sa);
	}
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_mobike_t *this)
{
	chunk_free(&this->cookie2);
	if (this->natd)
	{
		this->natd->task.destroy(&this->natd->task);
	}
	free(this);
}

/*
 * Described in header.
 */
ike_mobike_t *ike_mobike_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_mobike_t *this = malloc_thing(private_ike_mobike_t);

	this->public.roam = (void(*)(ike_mobike_t*,bool))roam;
	this->public.transmit = (void(*)(ike_mobike_t*,packet_t*))transmit;
	this->public.is_probing = (bool(*)(ike_mobike_t*))is_probing;
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
	this->update = FALSE;
	this->check = FALSE;
	this->address = TRUE;
	this->cookie2 = chunk_empty;
	this->natd = NULL;
	
	return &this->public;
}

