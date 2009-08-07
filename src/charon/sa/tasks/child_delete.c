/*
 * Copyright (C) 2006-2007 Martin Willi
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

#include "child_delete.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>


typedef struct private_child_delete_t private_child_delete_t;

/**
 * Private members of a child_delete_t task.
 */
struct private_child_delete_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	child_delete_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * Protocol of CHILD_SA to delete
	 */
	protocol_id_t protocol;
	
	/**
	 * Inbound SPI of CHILD_SA to delete
	 */
	u_int32_t spi;
	
	/**
	 * whether to enforce delete action policy
	 */
	bool check_delete_action;
	
	/**
	 * is this delete exchange following a rekey?
	 */
	bool rekeyed;
	
	/**
	 * CHILD_SAs which get deleted
	 */
	linked_list_t *child_sas;
};

/**
 * build the delete payloads from the listed child_sas
 */
static void build_payloads(private_child_delete_t *this, message_t *message)
{
	delete_payload_t *ah = NULL, *esp = NULL;
	iterator_t *iterator;
	child_sa_t *child_sa;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{	
		protocol_id_t protocol = child_sa->get_protocol(child_sa);
		u_int32_t spi = child_sa->get_spi(child_sa, TRUE);

		switch (protocol)
		{
			case PROTO_ESP:
				if (esp == NULL)
				{
					esp = delete_payload_create(PROTO_ESP);
					message->add_payload(message, (payload_t*)esp);
				}
				esp->add_spi(esp, spi);
				DBG1(DBG_IKE, "sending DELETE for %N CHILD_SA with SPI %.8x", 
							   protocol_id_names, protocol, ntohl(spi));
				break;
			case PROTO_AH:
				if (ah == NULL)
				{
					ah = delete_payload_create(PROTO_AH);
					message->add_payload(message, (payload_t*)ah);
				}
				ah->add_spi(ah, spi);
				DBG1(DBG_IKE, "sending DELETE for %N CHILD_SA with SPI %.8x", 
							   protocol_id_names, protocol, ntohl(spi));
				break;
			default:
				break;
		}
		child_sa->set_state(child_sa, CHILD_DELETING);
	}
	iterator->destroy(iterator);
}

/**
 * read in payloads and find the children to delete
 */
static void process_payloads(private_child_delete_t *this, message_t *message)
{
	enumerator_t *payloads;
	iterator_t *spis;
	payload_t *payload;
	delete_payload_t *delete_payload;
	u_int32_t *spi;
	protocol_id_t protocol;
	child_sa_t *child_sa;
	
	payloads = message->create_payload_enumerator(message);
	while (payloads->enumerate(payloads, &payload))
	{
		if (payload->get_type(payload) == DELETE)
		{
			delete_payload = (delete_payload_t*)payload;
			protocol = delete_payload->get_protocol_id(delete_payload);
			if (protocol != PROTO_ESP && protocol != PROTO_AH)
			{
				continue;
			}
			spis = delete_payload->create_spi_iterator(delete_payload);
			while (spis->iterate(spis, (void**)&spi))
			{
				child_sa = this->ike_sa->get_child_sa(this->ike_sa, protocol,
													  *spi, FALSE);
				if (child_sa == NULL)
				{
					DBG1(DBG_IKE, "received DELETE for %N CHILD_SA with SPI %.8x, "
						 "but no such SA", protocol_id_names, protocol, ntohl(*spi));
					continue;
				}
				DBG1(DBG_IKE, "received DELETE for %N CHILD_SA with SPI %.8x", 
						protocol_id_names, protocol, ntohl(*spi));
				
				switch (child_sa->get_state(child_sa))
				{
					case CHILD_REKEYING:
						this->rekeyed = TRUE;
						/* we reply as usual, rekeying will fail */
						break;
					case CHILD_DELETING:
						/* we don't send back a delete if we initiated ourself */
						if (!this->initiator)
						{
							this->ike_sa->destroy_child_sa(this->ike_sa,
														   protocol, *spi);
							continue;
						}
					case CHILD_INSTALLED:
						if (!this->initiator)
						{	/* reestablish installed children if required */
							this->check_delete_action = TRUE;
						}
					default:
						break;
				}
				
				this->child_sas->insert_last(this->child_sas, child_sa);
			}
			spis->destroy(spis);
		}
	}
	payloads->destroy(payloads);
}

/**
 * destroy the children listed in this->child_sas, reestablish by policy
 */
static status_t destroy_and_reestablish(private_child_delete_t *this)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	child_cfg_t *child_cfg;
	protocol_id_t protocol;
	u_int32_t spi;
	status_t status = SUCCESS;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		/* signal child down event if we are not rekeying */
		if (!this->rekeyed)
		{
			charon->bus->child_updown(charon->bus, child_sa, FALSE);
		}
		spi = child_sa->get_spi(child_sa, TRUE);
		protocol = child_sa->get_protocol(child_sa);
		child_cfg = child_sa->get_config(child_sa);
		child_cfg->get_ref(child_cfg);
		this->ike_sa->destroy_child_sa(this->ike_sa, protocol, spi);
		if (this->check_delete_action)
		{	/* enforce child_cfg policy if deleted passively */
			switch (child_cfg->get_close_action(child_cfg))
			{
				case ACTION_RESTART:
					child_cfg->get_ref(child_cfg);
					status = this->ike_sa->initiate(this->ike_sa, child_cfg, 0,
													NULL, NULL);
					break;
				case ACTION_ROUTE:	
					charon->traps->install(charon->traps,
							this->ike_sa->get_peer_cfg(this->ike_sa), child_cfg);
					break;
				default:
					break;
			}
		}
		child_cfg->destroy(child_cfg);
		if (status != SUCCESS)
		{
			break;
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * send closing signals for all CHILD_SAs over the bus
 */
static void log_children(private_child_delete_t *this)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	u_int64_t bytes_in, bytes_out;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		child_sa->get_usestats(child_sa, TRUE, NULL, &bytes_in);
		child_sa->get_usestats(child_sa, FALSE, NULL, &bytes_out);
		
		DBG0(DBG_IKE, "closing CHILD_SA %s{%d} "
			 "with SPIs %.8x_i (%llu bytes) %.8x_o (%llu bytes) and TS %#R=== %#R",
			 child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			 ntohl(child_sa->get_spi(child_sa, TRUE)), bytes_in,
			 ntohl(child_sa->get_spi(child_sa, FALSE)), bytes_out,
			 child_sa->get_traffic_selectors(child_sa, TRUE),
			 child_sa->get_traffic_selectors(child_sa, FALSE));
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_child_delete_t *this, message_t *message)
{
	child_sa_t *child_sa;
	
	child_sa = this->ike_sa->get_child_sa(this->ike_sa, this->protocol,
										  this->spi, TRUE);
	if (!child_sa)
	{	/* child does not exist anymore */
		return SUCCESS;
	}
	this->child_sas->insert_last(this->child_sas, child_sa);
	if (child_sa->get_state(child_sa) == CHILD_REKEYING)
	{
		this->rekeyed = TRUE;
	}
	log_children(this);
	build_payloads(this, message);
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_child_delete_t *this, message_t *message)
{
	/* flush the list before adding new SAs */
	this->child_sas->destroy(this->child_sas);
	this->child_sas = linked_list_create();
	
	process_payloads(this, message);
	DBG1(DBG_IKE, "CHILD_SA closed");
	return destroy_and_reestablish(this);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_child_delete_t *this, message_t *message)
{
	process_payloads(this, message);
	log_children(this);
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_child_delete_t *this, message_t *message)
{
	/* if we are rekeying, we send an empty informational */
	if (this->ike_sa->get_state(this->ike_sa) != IKE_REKEYING)
	{
		build_payloads(this, message);	
	}
	DBG1(DBG_IKE, "CHILD_SA closed");
	return destroy_and_reestablish(this);
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_child_delete_t *this)
{
	return CHILD_DELETE;
}

/**
 * Implementation of child_delete_t.get_child
 */
static child_sa_t* get_child(private_child_delete_t *this)
{
	child_sa_t *child_sa = NULL;
	this->child_sas->get_first(this->child_sas, (void**)&child_sa);
	return child_sa;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_child_delete_t *this, ike_sa_t *ike_sa)
{
	this->check_delete_action = FALSE;
	this->ike_sa = ike_sa;
	
	this->child_sas->destroy(this->child_sas);
	this->child_sas = linked_list_create();
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_child_delete_t *this)
{
	this->child_sas->destroy(this->child_sas);
	free(this);
}

/*
 * Described in header.
 */
child_delete_t *child_delete_create(ike_sa_t *ike_sa, protocol_id_t protocol,
									u_int32_t spi)
{
	private_child_delete_t *this = malloc_thing(private_child_delete_t);

	this->public.get_child = (child_sa_t*(*)(child_delete_t*))get_child;
	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	
	this->ike_sa = ike_sa;
	this->check_delete_action = FALSE;
	this->child_sas = linked_list_create();
	this->protocol = protocol;
	this->spi = spi;
	this->rekeyed = FALSE;
	
	if (protocol != PROTO_NONE)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
		this->initiator = TRUE;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
		this->initiator = FALSE;
	}
	return &this->public;
}
