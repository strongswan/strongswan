/**
 * @file ike_auth.c
 *
 * @brief Implementation of ike_auth_t transaction.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "ike_auth.h"

#include <string.h>

#include <daemon.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <sa/authenticator.h>
#include <sa/child_sa.h>


typedef struct private_ike_auth_t private_ike_auth_t;

/**
 * Private members of a ike_auth_t object..
 */
struct private_ike_auth_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	ike_auth_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Message sent by our peer, if already generated
	 */
	message_t *message;
	
	/**
	 * Message ID this transaction uses
	 */
	u_int32_t message_id;
	
	/**
	 * Times we did send the request
	 */
	u_int32_t requested;
	
	/**
	 * initiator chosen nonce
	 */
	chunk_t nonce_i;
	
	/**
	 * responder chosen nonce
	 */
	chunk_t nonce_r;
	
	/**
	 * encoded request message of ike_sa_init transaction
	 */
	chunk_t init_request;
	
	/**
	 * encoded response message of ike_sa_init transaction
	 */
	chunk_t init_response;
	
	/**
	 * connection definition used for IKE_SA setup
	 */
	connection_t *connection;
	
	/**
	 * policy definition used CHILD_SA creation
	 */
	policy_t *policy;
	
	/**
	 * Negotiated proposal used for CHILD_SA
	 */
	proposal_t *proposal;
	
	/**
	 * Negotiated traffic selectors for initiator
	 */
	linked_list_t *tsi;
	
	/**
	 * Negotiated traffic selectors for responder
	 */
	linked_list_t *tsr;
	
	/**
	 * CHILD_SA created along with IKE_AUTH
	 */
	child_sa_t *child_sa;
	
	/**
	 * did other peer create a CHILD_SA?
	 */
	bool build_child;
	
	/**
	 * reqid to use for CHILD_SA setup
	 */
	u_int32_t reqid;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_ike_auth_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_ike_auth_t *this)
{
	return this->requested++;
}

/**
 * Implementation of transaction_t.set_config.
 */
static void set_config(private_ike_auth_t *this,
					   connection_t *connection, policy_t *policy)
{
	this->connection = connection;
	this->policy = policy;
}

/**
 * Implementation of transaction_t.set_reqid.
 */
static void set_reqid(private_ike_auth_t *this, u_int32_t reqid)
{
	this->reqid = reqid;
}

/**
 * Implementation of transaction_t.set_nonces.
 */
static void set_nonces(private_ike_auth_t *this, chunk_t nonce_i, chunk_t nonce_r)
{
	this->nonce_i = nonce_i;
	this->nonce_r = nonce_r;
}

/**
 * Implementation of transaction_t.set_init_messages.
 */
static void set_init_messages(private_ike_auth_t *this, chunk_t init_request, chunk_t init_response)
{
	this->init_request = init_request;
	this->init_response = init_response;
}

/**
 * destroy a list of traffic selectors
 */
static void destroy_ts_list(linked_list_t *list)
{
	if (list)
	{
		traffic_selector_t *ts;

		while (list->remove_last(list, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		list->destroy(list);
	}
}

/**
 * destroy a list of proposals
 */
static void destroy_proposal_list(linked_list_t *list)
{
	proposal_t *proposal;
	
	while (list->remove_last(list, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	list->destroy(list);
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_ike_auth_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	identification_t *my_id, *other_id;
	id_payload_t *my_id_payload;
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_id = this->policy->get_my_id(this->policy);
	other_id = this->policy->get_other_id(this->policy);
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, IKE_AUTH);
	request->set_request(request, TRUE);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	/* apply for caller */
	*result = request;
	/* store for retransmission */
	this->message = request;
	
	{	/* build ID payload */
		my_id_payload = id_payload_create_from_identification(TRUE, my_id);
		request->add_payload(request, (payload_t*)my_id_payload);
	}
	
	{	/* TODO: build certreq payload */
		
	}
	
	/* build certificate payload. TODO: Handle certreq from init_ike_sa. */
	if (this->policy->get_auth_method(this->policy) == RSA_DIGITAL_SIGNATURE
	&&  this->connection->get_cert_policy(this->connection) != CERT_NEVER_SEND)
	{
		cert_payload_t *cert_payload;
		
		x509_t *cert = charon->credentials->get_certificate(charon->credentials, my_id);

		if (cert)
		{
			cert_payload = cert_payload_create_from_x509(cert);
			request->add_payload(request, (payload_t*)cert_payload);
		}
		else
		{
			this->logger->log(this->logger, ERROR, 
							  "could not find my certificate, certificate payload omitted");
		}
	}
	
	{	/* build IDr payload, if other_id defined */
		id_payload_t *id_payload;
		if (!other_id->contains_wildcards(other_id))
		{
			id_payload = id_payload_create_from_identification(FALSE, other_id);
			request->add_payload(request, (payload_t*)id_payload);
		}
	}
	
	{	/* build auth payload */
		authenticator_t *authenticator;
		auth_payload_t *auth_payload;
		auth_method_t auth_method;
		status_t status;
		
		auth_method = this->policy->get_auth_method(this->policy);
		authenticator = authenticator_create(this->ike_sa, auth_method);
		status = authenticator->compute_auth_data(authenticator,
												  &auth_payload,
												  this->init_request,
												  this->nonce_r,
												  my_id,
												  other_id,
												  TRUE);
		authenticator->destroy(authenticator);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, 
							  "could not generate AUTH data, deleting IKE_SA");
			return DESTROY_ME;
		}
		request->add_payload(request, (payload_t*)auth_payload);
	}
	
	{	/* build SA payload for CHILD_SA */
		linked_list_t *proposal_list;
		sa_payload_t *sa_payload;
		u_int32_t soft_lifetime, hard_lifetime;
		bool enable_natt;
		
		proposal_list = this->policy->get_proposals(this->policy);
		soft_lifetime = this->policy->get_soft_lifetime(this->policy);
		hard_lifetime = this->policy->get_hard_lifetime(this->policy);
		enable_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
		this->child_sa = child_sa_create(this->reqid, me, other, my_id, other_id,
										 soft_lifetime, hard_lifetime,
										 this->policy->get_updown(this->policy),
										 this->policy->get_hostaccess(this->policy),
										 enable_natt);
		this->child_sa->set_name(this->child_sa, this->policy->get_name(this->policy));
		if (this->child_sa->alloc(this->child_sa, proposal_list) != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
					"could not install CHILD_SA, deleting IKE_SA");
			return DESTROY_ME;
		}
		sa_payload = sa_payload_create_from_proposal_list(proposal_list);
		destroy_proposal_list(proposal_list);
		request->add_payload(request, (payload_t*)sa_payload);
	}
	
	{	/* build TSi payload */
		linked_list_t *ts_list;
		ts_payload_t *ts_payload;
	
		ts_list = this->policy->get_my_traffic_selectors(this->policy, me);
		ts_payload = ts_payload_create_from_traffic_selectors(TRUE, ts_list);
		destroy_ts_list(ts_list);
		
		request->add_payload(request, (payload_t*)ts_payload);
	}
	
	{	/* build TSr payload */
		linked_list_t *ts_list;
		ts_payload_t *ts_payload;
	
		ts_list = this->policy->get_other_traffic_selectors(this->policy, other);
		ts_payload = ts_payload_create_from_traffic_selectors(FALSE, ts_list);
		destroy_ts_list(ts_list);
		
		request->add_payload(request, (payload_t*)ts_payload);
	}
	
	this->message_id = this->ike_sa->get_next_message_id(this->ike_sa);
	request->set_message_id(request, this->message_id);
	return SUCCESS;
}

/**
 * Handle all kind of notifies
 */
static status_t process_notifies(private_ike_auth_t *this, notify_payload_t *notify_payload)
{
	notify_type_t notify_type = notify_payload->get_notify_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "process notify type %s",
					  mapping_find(notify_type_m, notify_type));

	switch (notify_type)
	{
		/* these notifies are not critical. no child_sa is built, but IKE stays alive */
		case SINGLE_PAIR_REQUIRED:
		{
			this->logger->log(this->logger, AUDIT, 
							  "received a SINGLE_PAIR_REQUIRED notify");
			this->build_child = FALSE;
			return SUCCESS;
		}
		case TS_UNACCEPTABLE:
		{
			this->logger->log(this->logger, CONTROL, 
							  "received TS_UNACCEPTABLE notify");
			this->build_child = FALSE;
			return SUCCESS;
		}
		case NO_PROPOSAL_CHOSEN:
		{
			this->logger->log(this->logger, CONTROL, 
							  "received NO_PROPOSAL_CHOSEN notify");
			this->build_child = FALSE;
			return SUCCESS;
		}
		default:
		{
			if (notify_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, 
								  "received %s notify error (%d), deleting IKE_SA",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return DESTROY_ME;	
			}
			else
			{
				this->logger->log(this->logger, CONTROL, 
								  "received %s notify (%d), ignored",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return SUCCESS;
			}
		}
	}
}

/**
 * Build a notify message.
 */
static void build_notify(notify_type_t type, message_t *message, bool flush_message)
{
	notify_payload_t *notify;
	
	if (flush_message)
	{
		payload_t *payload;
		iterator_t *iterator = message->get_payload_iterator(message);
		while (iterator->iterate(iterator, (void**)&payload))
		{
			payload->destroy(payload);
			iterator->remove(iterator);
		}
		iterator->destroy(iterator);
	}
	
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	message->add_payload(message, (payload_t*)notify);
}

/**
 * Import a certificate from a cert payload
 */
static void import_certificate(private_ike_auth_t *this, cert_payload_t *cert_payload)
{
	bool found;
	x509_t *cert;
	cert_encoding_t encoding;
	
	encoding = cert_payload->get_cert_encoding(cert_payload);
	if (encoding != CERT_X509_SIGNATURE)
	{
		this->logger->log(this->logger, ERROR,
						  "certificate payload %s not supported, ignored",
						  enum_name(&cert_encoding_names, encoding));
		return;
	}
	cert = x509_create_from_chunk(cert_payload->get_data_clone(cert_payload));
	if (cert)
	{
		if (charon->credentials->verify(charon->credentials, cert, &found))
		{
			this->logger->log(this->logger, CONTROL|LEVEL1, 
							"received end entity certificate is trusted, added to store");
			if (!found)
			{
				charon->credentials->add_end_certificate(charon->credentials, cert);
			}
			else
			{
				cert->destroy(cert);
			}
		}
		else
		{
			this->logger->log(this->logger, CONTROL, 
							  "received end entity certificate is not trusted, discarded");
			cert->destroy(cert);
		}
	}
	else
	{
		this->logger->log(this->logger, CONTROL, 
						  "parsing of received certificate failed, discarded");
	}
}

/**
 * Install a CHILD_SA for usage
 */
static status_t install_child_sa(private_ike_auth_t *this, bool initiator)
{
	prf_plus_t *prf_plus;
	chunk_t seed;
	status_t status;
	
	seed = chunk_alloc(this->nonce_i.len + this->nonce_r.len);
	memcpy(seed.ptr, this->nonce_i.ptr, this->nonce_i.len);
	memcpy(seed.ptr + this->nonce_i.len, this->nonce_r.ptr, this->nonce_r.len);
	prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
	chunk_free(&seed);
	
	if (initiator)
	{
		status = this->child_sa->update(this->child_sa, this->proposal, prf_plus);
	}
	else
	{
		status = this->child_sa->add(this->child_sa, this->proposal, prf_plus);
	}
	prf_plus->destroy(prf_plus);
	if (status != SUCCESS)
	{
		return DESTROY_ME;
	}
	if (initiator)
	{
		status = this->child_sa->add_policies(this->child_sa, this->tsi, this->tsr);
	}
	else
	{
		status = this->child_sa->add_policies(this->child_sa, this->tsr, this->tsi);
	}
	if (status != SUCCESS)
	{
		return DESTROY_ME;
	}
	
	/* add to IKE_SA, and remove from transaction */
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	this->child_sa = NULL;
	return SUCCESS;
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_ike_auth_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	identification_t *my_id, *other_id;
	message_t *response;
	status_t status;
	iterator_t *payloads;
	id_payload_t *idi_request = NULL;
	id_payload_t *idr_request = NULL;
	auth_payload_t *auth_request = NULL;
	cert_payload_t *cert_request = NULL;
	sa_payload_t *sa_request = NULL;
	ts_payload_t *tsi_request = NULL;
	ts_payload_t *tsr_request = NULL;
	id_payload_t *idr_response;
	
	/* check if we already have built a response (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	this->message_id = request->get_message_id(request);
	
	/* set up response */
	response = message_create();
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	response->set_exchange_type(response, IKE_AUTH);
	response->set_request(response, FALSE);
	response->set_message_id(response, this->message_id);
	response->set_ike_sa_id(response, this->ike_sa->get_id(this->ike_sa));
	this->message = response;
	*result = response;
	
	/* check message type */
	if (request->get_exchange_type(request) != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR,
						  "IKE_AUTH response of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* Iterate over all payloads. */
	payloads = request->get_payload_iterator(request);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case ID_INITIATOR:
				idi_request = (id_payload_t*)payload;
				break;
			case ID_RESPONDER:
				idr_request = (id_payload_t*)payload;
				break;
			case AUTHENTICATION:
				auth_request = (auth_payload_t*)payload;
				break;
			case CERTIFICATE:
				cert_request = (cert_payload_t*)payload;
				break;
			case SECURITY_ASSOCIATION:
				sa_request = (sa_payload_t*)payload;
				break;
			case TRAFFIC_SELECTOR_INITIATOR:
				tsi_request = (ts_payload_t*)payload;
				break;	
			case TRAFFIC_SELECTOR_RESPONDER:
				tsr_request = (ts_payload_t*)payload;
				break;
			case NOTIFY:
			{
				status = process_notifies(this, (notify_payload_t*)payload);
				if (status == FAILED)
				{
					payloads->destroy(payloads);
					/* we return SUCCESS, returned FAILED means do next transaction */
					return SUCCESS;
				}
				if (status == DESTROY_ME)
				{
					payloads->destroy(payloads);
					return DESTROY_ME;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(idi_request && auth_request && sa_request && tsi_request && tsr_request))
	{
		build_notify(INVALID_SYNTAX, response, TRUE);
		this->logger->log(this->logger, AUDIT, 
						  "request message incomplete, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	{	/* process ID payload */
		other_id = idi_request->get_identification(idi_request);
		if (idr_request)
		{
			my_id = idr_request->get_identification(idr_request);
		}
		else
		{
			my_id = identification_create_from_encoding(ID_ANY, CHUNK_INITIALIZER);
		}
	}
	
	{	/* get a policy and process traffic selectors */
		linked_list_t *my_ts, *other_ts;
		
		my_ts = tsr_request->get_traffic_selectors(tsr_request);
		other_ts = tsi_request->get_traffic_selectors(tsi_request);
		
		this->policy = charon->policies->get_policy(charon->policies,
													my_id, other_id,
													my_ts, other_ts,
												    me, other);
		if (this->policy)
		{
			this->tsr = this->policy->select_my_traffic_selectors(this->policy, my_ts, me);
			this->tsi = this->policy->select_other_traffic_selectors(this->policy, other_ts, other);
		}
		destroy_ts_list(my_ts);
		destroy_ts_list(other_ts);
		
		/* TODO: We should check somehow if we have a policy, but with other
		 * traffic selectors. Then we would create a IKE_SA without a CHILD_SA. */
		if (this->policy == NULL)
		{
			this->logger->log(this->logger, AUDIT,
							  "no acceptable policy for IDs %s - %s found, deleting IKE_SA", 
							  my_id->get_string(my_id), other_id->get_string(other_id));
			my_id->destroy(my_id);
			other_id->destroy(other_id);
			build_notify(AUTHENTICATION_FAILED, response, TRUE);
			return DESTROY_ME;
		}
		my_id->destroy(my_id);
		
		/* get my id from policy, which must contain a fully qualified valid id */
		my_id = this->policy->get_my_id(this->policy);
		this->ike_sa->set_my_id(this->ike_sa, my_id->clone(my_id));
		this->ike_sa->set_other_id(this->ike_sa, other_id);
		
		idr_response = id_payload_create_from_identification(FALSE, my_id);
		response->add_payload(response, (payload_t*)idr_response);
	}
	
	if (this->policy->get_auth_method(this->policy) == RSA_DIGITAL_SIGNATURE
	&&  this->connection->get_cert_policy(this->connection) != CERT_NEVER_SEND)
	{	/* build certificate payload */
		x509_t *cert;
		cert_payload_t *cert_payload;
		
		cert = charon->credentials->get_certificate(charon->credentials, my_id);
		if (cert)
		{
			cert_payload = cert_payload_create_from_x509(cert);
			response->add_payload(response, (payload_t *)cert_payload);
		}
		else
		{
			this->logger->log(this->logger, ERROR,
							  "could not find my certificate, cert payload omitted");
		}
	}
	
	if (cert_request)
	{	/* process certificate payload */
		import_certificate(this, cert_request);
	}
	
	{	/* process auth payload */
		authenticator_t *authenticator;
		auth_payload_t *auth_response;
		auth_method_t auth_method;
		status_t status;
		
		auth_method = this->policy->get_auth_method(this->policy);
		authenticator = authenticator_create(this->ike_sa, auth_method);
		status = authenticator->verify_auth_data(authenticator, auth_request,
												 this->init_request,
												 this->nonce_r,
												 my_id,
												 other_id,
												 TRUE);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, 
							  "authentication failed, deleting IKE_SA");
			build_notify(AUTHENTICATION_FAILED, response, TRUE);
			authenticator->destroy(authenticator);
			return DESTROY_ME;
		}
		status = authenticator->compute_auth_data(authenticator, &auth_response,
												  this->init_response,
												  this->nonce_i,
												  my_id,
												  other_id,
												  FALSE);
		authenticator->destroy(authenticator);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, 
							  "authentication data generation failed, deleting IKE_SA");
			build_notify(AUTHENTICATION_FAILED, response, TRUE);
			return DESTROY_ME;
		}
		response->add_payload(response, (payload_t*)auth_response);
	}
	
	{	/* process SA payload */
		linked_list_t *proposal_list;
		sa_payload_t *sa_response;
		ts_payload_t *ts_response;
		bool use_natt;
		u_int32_t soft_lifetime, hard_lifetime;
		
		/* prepare reply */
		sa_response = sa_payload_create();
		
		/* get proposals from request, and select one with ours */
		proposal_list = sa_request->get_proposals(sa_request);
		this->logger->log(this->logger, CONTROL|LEVEL1, "selecting proposals:");
		this->proposal = this->policy->select_proposal(this->policy, proposal_list);
		destroy_proposal_list(proposal_list);

		/* do we have a proposal? */
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "CHILD_SA proposals unacceptable, adding NO_PROPOSAL_CHOSEN notify");
			build_notify(NO_PROPOSAL_CHOSEN, response, FALSE);
		}
		/* do we have traffic selectors? */
		else if (this->tsi->get_count(this->tsi) == 0 || this->tsr->get_count(this->tsr) == 0)
		{
			this->logger->log(this->logger, AUDIT,
							  "CHILD_SA traffic selectors unacceptable, adding TS_UNACCEPTABLE notify");
			build_notify(TS_UNACCEPTABLE, response, FALSE);
		}
		else
		{
			/* create child sa */
			soft_lifetime = this->policy->get_soft_lifetime(this->policy);
			hard_lifetime = this->policy->get_hard_lifetime(this->policy);
			use_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
			this->child_sa = child_sa_create(this->reqid, me, other, my_id, other_id,
											 soft_lifetime, hard_lifetime, 
											 this->policy->get_updown(this->policy),
											 this->policy->get_hostaccess(this->policy),
											 use_natt);
			this->child_sa->set_name(this->child_sa, this->policy->get_name(this->policy));
			if (install_child_sa(this, FALSE) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR,
								  "installing CHILD_SA failed, adding NO_PROPOSAL_CHOSEN notify");
				build_notify(NO_PROPOSAL_CHOSEN, response, FALSE);
			}
			/* add proposal to sa payload */
			sa_response->add_proposal(sa_response, this->proposal);
		}
		response->add_payload(response, (payload_t*)sa_response);
		
		/* add ts payload after sa payload */
		ts_response = ts_payload_create_from_traffic_selectors(TRUE, this->tsi);
		response->add_payload(response, (payload_t*)ts_response);
		ts_response = ts_payload_create_from_traffic_selectors(FALSE, this->tsr);
		response->add_payload(response, (payload_t*)ts_response);
	}
	/* set established state */
	this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
	return SUCCESS;
}


/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_ike_auth_t *this, message_t *response, 
						 transaction_t **transaction)
{
	iterator_t *payloads;
	host_t *me, *other;
	identification_t *other_id;
	ts_payload_t *tsi_payload = NULL;
	ts_payload_t *tsr_payload = NULL;
	id_payload_t *idr_payload = NULL;
	cert_payload_t *cert_payload = NULL;
	auth_payload_t *auth_payload = NULL;
	sa_payload_t *sa_payload = NULL;
	status_t status;
	
	/* check message type */
	if (response->get_exchange_type(response) != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR,
						  "IKE_AUTH response of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	
	/* Iterate over all payloads to collect them */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{ 
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case ID_RESPONDER:
				idr_payload = (id_payload_t*)payload;
				break;
			case AUTHENTICATION:
				auth_payload = (auth_payload_t*)payload;
				break;
			case CERTIFICATE:
				cert_payload = (cert_payload_t*)payload;
				break;
			case SECURITY_ASSOCIATION:
				sa_payload = (sa_payload_t*)payload;
				break;
			case TRAFFIC_SELECTOR_INITIATOR:
				tsi_payload = (ts_payload_t*)payload;
				break;	
			case TRAFFIC_SELECTOR_RESPONDER:
				tsr_payload = (ts_payload_t*)payload;
				break;
			case NOTIFY:
			{
				status = process_notifies(this, (notify_payload_t*)payload);
				if (status == FAILED)
				{
					payloads->destroy(payloads);
					/* we return SUCCESS, returned FAILED means do next transaction */
					return SUCCESS;
				}
				if (status == DESTROY_ME)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, CONTROL, "ignoring payload %s (%d)",
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	if (!(idr_payload && auth_payload && sa_payload && tsi_payload && tsr_payload))
	{
		this->logger->log(this->logger, AUDIT, "response message incomplete, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	{	/* process idr payload */
		identification_t *configured_other_id;
		int wildcards;
		
		other_id = idr_payload->get_identification(idr_payload);
		configured_other_id = this->policy->get_other_id(this->policy);
		
		if (!other_id->matches(other_id, configured_other_id, &wildcards))
		{
			other_id->destroy(other_id);
			this->logger->log(this->logger, AUDIT,
							  "other peer uses unacceptable ID (%s, excepted %s), deleting IKE_SA",
							  other_id->get_string(other_id),
							  configured_other_id->get_string(configured_other_id));
			return DESTROY_ME;
		}
		/* update other ID. It was already set, but may contain wildcards */
		this->ike_sa->set_other_id(this->ike_sa, other_id);
	}
	
	if (cert_payload)
	{	/* process cert payload */
		import_certificate(this, cert_payload);
	}
	
	{	/* authenticate peer */
		authenticator_t *authenticator;
		auth_method_t auth_method;
		identification_t *my_id;
		status_t status;
		
		auth_method = this->policy->get_auth_method(this->policy);
		authenticator = authenticator_create(this->ike_sa, auth_method);
		my_id = this->policy->get_my_id(this->policy);

		status = authenticator->verify_auth_data(authenticator,
												 auth_payload,
												 this->init_response,
												 this->nonce_i,
												 my_id,
												 other_id,
												 FALSE);
		authenticator->destroy(authenticator);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "authentication failed, deleting IKE_SA");
			return DESTROY_ME;	
		}
	}
	
	{	/* process traffic selectors for us */
		linked_list_t *ts_received = tsi_payload->get_traffic_selectors(tsi_payload);
		this->tsi = this->policy->select_my_traffic_selectors(this->policy, ts_received, me);
		destroy_ts_list(ts_received);
	}
	
	{	/* process traffic selectors for other */
		linked_list_t *ts_received = tsr_payload->get_traffic_selectors(tsr_payload);
		this->tsr = this->policy->select_other_traffic_selectors(this->policy, ts_received, other);
		destroy_ts_list(ts_received);
	}
	
	{	/* process sa payload */
		linked_list_t *proposal_list;
		
		proposal_list = sa_payload->get_proposals(sa_payload);
		/* we have to re-check here if other's selection is valid */
		this->proposal = this->policy->select_proposal(this->policy, proposal_list);
		destroy_proposal_list(proposal_list);
		
		/* everything fine to create CHILD? */
		if (this->proposal == NULL ||
			this->tsi->get_count(this->tsi) == 0 ||
			this->tsr->get_count(this->tsr) == 0 ||
			!this->build_child)
		{
			this->logger->log(this->logger, AUDIT,
							  "CHILD_SA creation failed");
		}
		else
		{
			if (install_child_sa(this, TRUE) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR,
								  "installing CHILD_SA failed, no CHILD_SA built");
			}
		}
	}
	/* set new state */
	this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
	return SUCCESS;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_ike_auth_t *this)
{
	DESTROY_IF(this->message);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->child_sa);
	DESTROY_IF(this->policy);
	DESTROY_IF(this->connection);
	destroy_ts_list(this->tsi);
	destroy_ts_list(this->tsr);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	chunk_free(&this->init_request);
	chunk_free(&this->init_response);
	free(this);
}

/*
 * Described in header.
 */
ike_auth_t *ike_auth_create(ike_sa_t *ike_sa)
{
	private_ike_auth_t *this = malloc_thing(private_ike_auth_t);

	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* public functions */
	this->public.set_config = (void(*)(ike_auth_t*,connection_t*,policy_t*))set_config;
	this->public.set_reqid = (void(*)(ike_auth_t*,u_int32_t))set_reqid;
	this->public.set_nonces = (void(*)(ike_auth_t*,chunk_t,chunk_t))set_nonces;
	this->public.set_init_messages = (void(*)(ike_auth_t*,chunk_t,chunk_t))set_init_messages;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	this->init_request = CHUNK_INITIALIZER;
	this->init_response = CHUNK_INITIALIZER;
	this->child_sa = NULL;
	this->proposal = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->build_child = TRUE;
	this->reqid = 0;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);

	return &this->public;
}
