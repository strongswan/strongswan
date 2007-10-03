/**
 * @file ike_p2p.c
 *
 * @brief Implementation of the ike_p2p task.
 *
 */

/*
 * Copyright (C) 2007 Tobias Brunner
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

#include "ike_p2p.h"

#include <string.h>

#include <daemon.h>
#include <config/peer_cfg.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/endpoint_notify.h>
#include <processing/jobs/mediation_job.h>

#define P2P_SESSIONID_LEN 8
#define P2P_SESSIONKEY_LEN 16

// FIXME: proposed values
#define P2P_SESSIONID_MIN_LEN 4
#define P2P_SESSIONID_MAX_LEN 16
#define P2P_SESSIONKEY_MIN_LEN 8
#define P2P_SESSIONKEY_MAX_LEN 64


typedef struct private_ike_p2p_t private_ike_p2p_t;

/**
 * Private members of a ike_p2p_t task.
 */
struct private_ike_p2p_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_p2p_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * Is this a mediation connection?
	 */
	bool mediation;
	
	/**
	 * Is this the response from another peer?
	 */
	bool response;
	
	/**
	 * Gathered endpoints
	 */
	linked_list_t *local_endpoints;
	
	/**
	 * Parsed endpoints
	 */
	linked_list_t *remote_endpoints;
	
	/**
	 * Did the peer request a callback?
	 */
	bool callback;
	
	/**
	 * Did the connect fail?
	 */
	bool failed;
	
	/**
	 * Was there anything wrong with the payloads?
	 */
	bool invalid_syntax;
	
	/**
	 * The requested peer
	 */
	identification_t *peer_id;	
	/**
	 * Received ID used for connectivity checks
	 */
	chunk_t session_id;
	
	/**
	 * Received key used for connectivity checks
	 */
	chunk_t session_key;
	
	/**
	 * Peer config of the mediated connection
	 */
	peer_cfg_t *mediated_cfg;

};

// -----------------------------------------------------------------------------

/**
 * Adds a list of endpoints as notifies to a given message
 */
static void add_endpoints_to_message(message_t *message, linked_list_t *endpoints)
{
	iterator_t *iterator;
	endpoint_notify_t *endpoint;
	
	iterator = endpoints->create_iterator(endpoints, TRUE);
	while (iterator->iterate(iterator, (void**)&endpoint))
	{
		message->add_payload(message, (payload_t*)endpoint->build_notify(endpoint));
	}
	iterator->destroy(iterator);
}

/**
 * Gathers endpoints and adds them to the current message
 */
static void gather_and_add_endpoints(private_ike_p2p_t *this, message_t *message)
{
	iterator_t *iterator;
	host_t *addr, *host;
	u_int16_t port;
	
	// get the port that is used to communicate with the ms
	host = this->ike_sa->get_my_host(this->ike_sa);
	port = host->get_port(host);
	
	iterator = charon->kernel_interface->create_address_iterator(
												charon->kernel_interface);
	while (iterator->iterate(iterator, (void**)&addr))
	{
		host = addr->clone(addr);
		host->set_port(host, port);
		
		this->local_endpoints->insert_last(this->local_endpoints,
				endpoint_notify_create_from_host(HOST, host, NULL));
		
		host->destroy(host);
	}
	iterator->destroy(iterator);
	
	host = this->ike_sa->get_server_reflexive_host(this->ike_sa);
	if (host)
	{
		this->local_endpoints->insert_last(this->local_endpoints,
				endpoint_notify_create_from_host(SERVER_REFLEXIVE, host,
						this->ike_sa->get_my_host(this->ike_sa)));
	}
	
	add_endpoints_to_message(message, this->local_endpoints);
}

/**
 * read notifys from message and evaluate them
 */
static void process_payloads(private_ike_p2p_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;

	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) != NOTIFY)
		{
			continue;
		}
		
		notify_payload_t *notify = (notify_payload_t*)payload;
		
		switch (notify->get_notify_type(notify))
		{
			case P2P_CONNECT_FAILED:
			{
				DBG2(DBG_IKE, "received P2P_CONNECT_FAILED notify");
				this->failed = TRUE;
				break;
			}
			case P2P_MEDIATION:
			{
				DBG2(DBG_IKE, "received P2P_MEDIATION notify");
				this->mediation = TRUE;
				break;
			}
			case P2P_ENDPOINT:
			{
				endpoint_notify_t *endpoint = endpoint_notify_create_from_payload(notify);
				if (!endpoint)
				{
					DBG1(DBG_IKE, "received invalid P2P_ENDPOINT notify");
					break;
				}
				DBG2(DBG_IKE, "received P2P_ENDPOINT notify");
				
				this->remote_endpoints->insert_last(this->remote_endpoints, endpoint);
				break;
			}
			case P2P_CALLBACK:
			{
				DBG2(DBG_IKE, "received P2P_CALLBACK notify");
				this->callback = TRUE;
				break;
			}
			case P2P_SESSIONID:
			{
				chunk_free(&this->session_id);
				this->session_id = chunk_clone(notify->get_notification_data(notify));
				DBG3(DBG_IKE, "received p2p_sessionid %B", &this->session_id);
				break;
			}
			case P2P_SESSIONKEY:
			{
				chunk_free(&this->session_key);
				this->session_key = chunk_clone(notify->get_notification_data(notify));
				DBG4(DBG_IKE, "received p2p_sessionkey %B", &this->session_key);
				break;
			}
			case P2P_RESPONSE:
			{
				DBG2(DBG_IKE, "received P2P_RESPONSE notify");
				this->response = TRUE;
				break;
			}
			default:
				break;
		}
	}
	iterator->destroy(iterator);
}

// -----------------------------------------------------------------------------

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{
			peer_cfg_t *peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
			if (peer_cfg->is_mediation(peer_cfg))
			{
				DBG2(DBG_IKE, "adding P2P_MEDIATION");
				message->add_notify(message, FALSE, P2P_MEDIATION, chunk_empty);
			}
			else
			{
				return SUCCESS;
			}
			break;
		}
		case IKE_AUTH:
		{
			if (this->ike_sa->has_condition(this->ike_sa, COND_NAT_HERE))
			{
				endpoint_notify_t *endpoint = endpoint_notify_create_from_host(SERVER_REFLEXIVE, NULL, NULL);
				message->add_payload(message, (payload_t*)endpoint->build_notify(endpoint));
				endpoint->destroy(endpoint);
			}
			break;
		}
		case P2P_CONNECT:
		{
			id_payload_t *id_payload;
			randomizer_t *rand = randomizer_create();
			
			id_payload = id_payload_create_from_identification(ID_PEER, this->peer_id);
			message->add_payload(message, (payload_t*)id_payload);
			
			if (!this->response)
			{
				// only the initiator creates a session ID. the responder returns
				// the session ID that it received from the initiator
				if (rand->allocate_pseudo_random_bytes(rand,
						P2P_SESSIONID_LEN, &this->session_id) != SUCCESS)
				{
					DBG1(DBG_IKE, "unable to generate session ID for P2P_CONNECT");		
					rand->destroy(rand);
					return FAILED;
				}
			}
			
			if (rand->allocate_pseudo_random_bytes(rand,
					P2P_SESSIONKEY_LEN, &this->session_key) != SUCCESS)
			{
				DBG1(DBG_IKE, "unable to generate session key for P2P_CONNECT");
				rand->destroy(rand);
				return FAILED;
			}
			
			rand->destroy(rand);
			
			message->add_notify(message, FALSE, P2P_SESSIONID, this->session_id);
			message->add_notify(message, FALSE, P2P_SESSIONKEY, this->session_key);
			
			if (this->response)
			{
				message->add_notify(message, FALSE, P2P_RESPONSE, chunk_empty);
			}
			else
			{
				// FIXME: should we make that configurable
				message->add_notify(message, FALSE, P2P_CALLBACK, chunk_empty);
			}
			
			gather_and_add_endpoints(this, message);
			
			break;
		}
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case P2P_CONNECT:
		{
			id_payload_t *id_payload;
			id_payload = (id_payload_t*)message->get_payload(message, ID_PEER);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without ID_PEER payload, aborting");
				break;
			}
			this->peer_id = id_payload->get_identification(id_payload);
			
			process_payloads(this, message);
			
			if (this->callback)
			{
				DBG1(DBG_IKE, "received P2P_CALLBACK for '%D'", this->peer_id);
				break;
			}			
			
			if (!this->session_id.ptr)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without P2P_SESSIONID notify, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			if (!this->session_key.ptr)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without P2P_SESSIONKEY notify, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			if (!this->remote_endpoints->get_count(this->remote_endpoints))
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without any P2P_ENDPOINT payloads, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			DBG1(DBG_IKE, "received P2P_CONNECT");
			
			break;
		}
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case P2P_CONNECT:
		{
			if (this->invalid_syntax)
			{
				message->add_notify(message, TRUE, INVALID_SYNTAX, chunk_empty);
				break;
			}
			
			if (this->callback)
			{
				charon->connect_manager->check_and_initiate(charon->connect_manager,
						this->ike_sa->get_id(this->ike_sa),
						this->ike_sa->get_my_id(this->ike_sa), this->peer_id);
				return SUCCESS;
			}
			
			if (this->response)
			{
				// FIXME: handle result of set_responder_data
				// as initiator, upon receiving a response from another peer,
				// update the checklist and start sending checks
				charon->connect_manager->set_responder_data(charon->connect_manager,
						this->session_id, this->session_key, this->remote_endpoints);
			}
			else
			{
				// FIXME: handle result of set_initiator_data
				// as responder, create a checklist with the initiator's data
				charon->connect_manager->set_initiator_data(charon->connect_manager,
						this->peer_id, this->ike_sa->get_my_id(this->ike_sa),
						this->session_id, this->session_key, this->remote_endpoints,
						FALSE);
				if (this->ike_sa->respond(this->ike_sa, this->peer_id,
						this->session_id) != SUCCESS)
				{
					return FAILED;
				}
			}
			
			break;
		}
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{
			process_payloads(this, message);
		
			if (!this->mediation)
			{
				DBG1(DBG_IKE, "server did not return a P2P_MEDIATION, aborting");
				return FAILED;
			}
	
			return NEED_MORE;
		}
		case IKE_AUTH:
		{
			process_payloads(this, message);
			
			//FIXME: we should update the server reflexive endpoint somehow, if mobike notices a change 
			
			endpoint_notify_t *reflexive;
			if (this->remote_endpoints->get_first(this->remote_endpoints, (void**)&reflexive) == SUCCESS &&
					reflexive->get_type(reflexive) == SERVER_REFLEXIVE)
			{//FIXME: should we accept this endpoint even if we did not send a request?
				host_t *endpoint = reflexive->get_host(reflexive);
				DBG2(DBG_IKE, "received server reflexive endpoint %#H", endpoint);
				
				this->ike_sa->set_server_reflexive_host(this->ike_sa, endpoint->clone(endpoint));
			}
			
			// FIXME: what if it failed? e.g. AUTH failure
			SIG(CHILD_UP_SUCCESS, "established mediation connection without CHILD_SA successfully");
			
			break;
		}
		case P2P_CONNECT:
		{
			process_payloads(this, message);
			
			if (this->failed)
			{
				DBG1(DBG_IKE, "peer '%D' is not online", this->peer_id);
				// FIXME: notify the mediated connection (job?)
				// FIXME: probably delete the created checklist, at least as responder
			}
			else
			{
				if (this->response)
				{
					// FIXME: handle result of set_responder_data
					// as responder, we update the checklist and start sending checks
					charon->connect_manager->set_responder_data(charon->connect_manager,
							this->session_id, this->session_key, this->local_endpoints);
				}
				else
				{
					// FIXME: handle result of set_initiator_data
					// as initiator, we create a checklist and set the initiator's data
					charon->connect_manager->set_initiator_data(charon->connect_manager,
						this->ike_sa->get_my_id(this->ike_sa), this->peer_id,
						this->session_id, this->session_key, this->local_endpoints,
						TRUE);
				}
			}
			break;
		}
	}
	return SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * Implementation of task_t.process for initiator (mediation server)
 */
static status_t build_i_ms(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case P2P_CONNECT:
		{
			id_payload_t *id_payload = id_payload_create_from_identification(ID_PEER, this->peer_id);
			message->add_payload(message, (payload_t*)id_payload);
			
			if (this->callback)
			{
				message->add_notify(message, FALSE, P2P_CALLBACK, chunk_empty);
			}
			else
			{
				notify_payload_t *notify;
				
				if (this->response)
				{
					message->add_notify(message, FALSE, P2P_RESPONSE, chunk_empty);
				}
				
				message->add_notify(message, FALSE, P2P_SESSIONID, this->session_id);
				message->add_notify(message, FALSE, P2P_SESSIONKEY, this->session_key);
				
				add_endpoints_to_message(message, this->remote_endpoints);
			}
			
			break;
		}
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder (mediation server)
 */
static status_t process_r_ms(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{
			process_payloads(this, message);
			return this->mediation ? NEED_MORE : SUCCESS;
		}
		case IKE_AUTH:
		{
			process_payloads(this, message);
			break;
		}
		case P2P_CONNECT:
		{
			id_payload_t *id_payload;
			id_payload = (id_payload_t*)message->get_payload(message, ID_PEER);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without ID_PEER payload, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			this->peer_id = id_payload->get_identification(id_payload);
			
			process_payloads(this, message);
			
			if (!this->session_id.ptr)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without P2P_SESSIONID notify, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			if (!this->session_key.ptr)
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without P2P_SESSIONKEY notify, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			if (!this->remote_endpoints->get_count(this->remote_endpoints))
			{
				DBG1(DBG_IKE, "received P2P_CONNECT without any P2P_ENDPOINT payloads, aborting");
				this->invalid_syntax = TRUE;
				break;
			}
			
			break;
		}
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder (mediation server)
 */
static status_t build_r_ms(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{
			message->add_notify(message, FALSE, P2P_MEDIATION, chunk_empty);
			return NEED_MORE;
		}
		case IKE_AUTH:
		{
			endpoint_notify_t *endpoint;
			if (this->remote_endpoints->get_first(this->remote_endpoints, (void**)&endpoint) == SUCCESS &&
					endpoint->get_type(endpoint) == SERVER_REFLEXIVE)
			{
				host_t *host = this->ike_sa->get_other_host(this->ike_sa);
				
				DBG2(DBG_IKE, "received request for a server reflexive endpoint "
						"sending: %#H", host);
				
				endpoint = endpoint_notify_create_from_host(SERVER_REFLEXIVE, host, NULL);								
				message->add_payload(message, (payload_t*)endpoint->build_notify(endpoint));
			}
			
			charon->mediation_manager->update_sa_id(charon->mediation_manager,
					this->ike_sa->get_other_id(this->ike_sa),
					this->ike_sa->get_id(this->ike_sa));
			
			SIG(CHILD_UP_SUCCESS, "established mediation connection without CHILD_SA successfully");
			
			break;
		}
		case P2P_CONNECT:
		{	
			if (this->invalid_syntax)
			{
				message->add_notify(message, TRUE, INVALID_SYNTAX, chunk_empty);
				break;
			}
			
			ike_sa_id_t *peer_sa;
			if (this->callback)
			{
				peer_sa = charon->mediation_manager->check_and_register(charon->mediation_manager,
						this->peer_id, this->ike_sa->get_other_id(this->ike_sa));
			}
			else
			{
				peer_sa = charon->mediation_manager->check(charon->mediation_manager,
						this->peer_id);
			}
			
			if (!peer_sa)
			{
				// the peer is not online
				message->add_notify(message, TRUE, P2P_CONNECT_FAILED, chunk_empty);
				break;
			}
			
			job_t *job = (job_t*)mediation_job_create(this->peer_id,
					this->ike_sa->get_other_id(this->ike_sa), this->session_id,
					this->session_key, this->remote_endpoints, this->response);
			charon->processor->queue_job(charon->processor, job);
			
			break;
		}
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator (mediation server)
 */
static status_t process_i_ms(private_ike_p2p_t *this, message_t *message)
{
	switch(message->get_exchange_type(message))
	{
		case P2P_CONNECT:
		{
			break;
		}
	}
	return SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * Implementation of ike_p2p.connect
 */
static void p2p_connect(private_ike_p2p_t *this, identification_t *peer_id)
{
	this->peer_id = peer_id->clone(peer_id);
}

/**
 * Implementation of ike_p2p.respond
 */
static void p2p_respond(private_ike_p2p_t *this, identification_t *peer_id, 
		chunk_t session_id)
{
	this->peer_id = peer_id->clone(peer_id);
	this->session_id = chunk_clone(session_id);
	this->response = TRUE;
}

/**
 * Implementation of ike_p2p.callback
 */
static void p2p_callback(private_ike_p2p_t *this, identification_t *peer_id)
{
	this->peer_id = peer_id->clone(peer_id);
	this->callback = TRUE;
}

/**
 * Implementation of ike_p2p.relay
 */
static void relay(private_ike_p2p_t *this, identification_t *requester, chunk_t session_id,
		chunk_t session_key, linked_list_t *endpoints, bool response)
{
	this->peer_id = requester->clone(requester);
	this->session_id = chunk_clone(session_id);
	this->session_key = chunk_clone(session_key);
	this->remote_endpoints = endpoints->clone_offset(endpoints, offsetof(endpoint_notify_t, clone));
	this->response = response;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_p2p_t *this)
{
	return IKE_P2P;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_p2p_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_p2p_t *this)
{
	DESTROY_IF(this->peer_id);
	
	chunk_free(&this->session_id);
	chunk_free(&this->session_key);
	
	this->local_endpoints->destroy_offset(this->local_endpoints, offsetof(endpoint_notify_t, destroy));
	this->remote_endpoints->destroy_offset(this->remote_endpoints, offsetof(endpoint_notify_t, destroy));
	
	DESTROY_IF(this->mediated_cfg);
	free(this);
}

/*
 * Described in header.
 */
ike_p2p_t *ike_p2p_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_p2p_t *this = malloc_thing(private_ike_p2p_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	if (id->is_initiator(id))
	{
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
	}
	else
	{
		// mediation server
		if (initiator)
		{
			this->public.task.build = (status_t(*)(task_t*,message_t*))build_i_ms;
			this->public.task.process = (status_t(*)(task_t*,message_t*))process_i_ms;
		}
		else
		{
			this->public.task.build = (status_t(*)(task_t*,message_t*))build_r_ms;
			this->public.task.process = (status_t(*)(task_t*,message_t*))process_r_ms;
		}
	}
	
	this->public.connect = (void(*)(ike_p2p_t*,identification_t*))p2p_connect;
	this->public.respond = (void(*)(ike_p2p_t*,identification_t*,chunk_t))p2p_respond;
	this->public.callback = (void(*)(ike_p2p_t*,identification_t*))p2p_callback;
	this->public.relay = (void(*)(ike_p2p_t*,identification_t*,chunk_t,chunk_t,linked_list_t*,bool))relay;
	
	this->ike_sa = ike_sa;
	this->initiator = initiator;
	
	this->peer_id = NULL;
	this->session_id = chunk_empty;
	this->session_key = chunk_empty;
	this->local_endpoints = linked_list_create();
	this->remote_endpoints = linked_list_create();
	this->mediation = FALSE;
	this->response = FALSE;
	this->callback = FALSE;
	this->failed = FALSE;
	this->invalid_syntax = FALSE;
	
	this->mediated_cfg = NULL;
	
	return &this->public;
}
