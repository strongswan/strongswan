/**
 * @file ike_sa.c
 *
 * @brief Implementation of ike_sa_t.
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

#include <sys/time.h>
#include <string.h>

#include "ike_sa.h"

#include <types.h>
#include <daemon.h>
#include <definitions.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>
#include <crypto/diffie_hellman.h>
#include <crypto/prf_plus.h>
#include <crypto/crypters/crypter.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/transform_attribute.h>
#include <encoding/payloads/ts_payload.h>
#include <sa/transactions/transaction.h>
#include <sa/transactions/ike_sa_init.h>
#include <sa/transactions/delete_ike_sa.h>
#include <sa/transactions/create_child_sa.h>
#include <sa/transactions/delete_child_sa.h>
#include <sa/transactions/dead_peer_detection.h>
#include <sa/transactions/rekey_ike_sa.h>
#include <queues/jobs/retransmit_request_job.h>
#include <queues/jobs/delete_ike_sa_job.h>
#include <queues/jobs/send_dpd_job.h>
#include <queues/jobs/send_keepalive_job.h>
#include <queues/jobs/rekey_ike_sa_job.h>
#include <queues/jobs/route_job.h>
#include <queues/jobs/initiate_job.h>

/**
 * String mappings for ike_sa_state_t.
 */
mapping_t ike_sa_state_m[] = {
	{IKE_CREATED, "CREATED"},
	{IKE_CONNECTING, "CONNECTING"},
	{IKE_ESTABLISHED, "ESTABLISHED"},
	{IKE_REKEYING, "REKEYING"},
	{IKE_DELETING, "DELETING"},
	{MAPPING_END, NULL}
};


typedef struct private_ike_sa_t private_ike_sa_t;

/**
 * Private data of an ike_sa_t object.
 */
struct private_ike_sa_t {

	/**
	 * Public members
	 */
	ike_sa_t public;

	/**
	 * Identifier for the current IKE_SA.
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * Current state of the IKE_SA
	 */
	ike_sa_state_t state;
	
	/**
	 * Name of the connection used by this IKE_SA
	 */
	char *name;
	
	/**
	 * Address of local host
	 */
	host_t *my_host;
	
	/**
	 * Address of remote host
	 */
	host_t *other_host;
	
	/**
	 * Identification used for us
	 */
	identification_t *my_id;
	
	/**
	 * Identification used for other
	 */
	identification_t *other_id;
	
	/**
	 * Linked List containing the child sa's of the current IKE_SA.
	 */
	linked_list_t *child_sas;
	
	/**
	 * crypter for inbound traffic
	 */
	crypter_t *crypter_in;
	
	/**
	 * crypter for outbound traffic
	 */
	crypter_t *crypter_out;
	
	/**
	 * Signer for inbound traffic
	 */
	signer_t *signer_in;
	
	/**
	 * Signer for outbound traffic
	 */
	signer_t *signer_out;
	
	/**
	 * Multi purpose prf, set key, use it, forget it
	 */
	prf_t *prf;
	
	/**
	 * Prf function for derivating keymat child SAs
	 */
	prf_t *child_prf;
	
	/**
	 * PRF, with key set to pi_key, used for authentication
	 */
	prf_t *prf_auth_i;

	/**
	 * PRF, with key set to pr_key, used for authentication
	 */
	prf_t *prf_auth_r;
	
	/**
	 * A logger for this IKE_SA.
	 */
	logger_t *logger;
	
	/**
	 * NAT hasher.
	 */
	hasher_t *nat_hasher;
	
	/**
	 * NAT status of local host.
	 */
	bool nat_here;
	
	/**
	 * NAT status of remote host.
	 */
	bool nat_there;
	
	/**
	 * message ID for next outgoung request
	 */
	u_int32_t message_id_out;

	/**
	 * Timestamps for this IKE_SA
	 */
	struct {
		/** last IKE message received */
		u_int32_t inbound;
		/** last IKE message sent */
		u_int32_t outbound;
		/** when IKE_SA became established */
		u_int32_t established;
		/** when IKE_SA gets rekeyed */
		u_int32_t rekey;
		/** when IKE_SA gets deleted */
		u_int32_t delete;
	} time;
	
	/**
	 * interval to send DPD liveness check
	 */
	time_t dpd_delay;
	
	/**
	 * number of retransmit sequences to go through before giving up (keyingtries)
	 */
	u_int32_t retrans_sequences;
	
	/**
	 * List of queued transactions to process
	 */
	linked_list_t *transaction_queue;
	
	/**
	 * Transaction currently initiated
	 * (only one supported yet, window size = 1)
	 */
	transaction_t *transaction_out;
	
	/**
	 * last transaction initiated by peer processed.
	 * (only one supported yet, window size = 1)
	 * Stored for retransmission.
	 */
	transaction_t *transaction_in;
	
	/**
	 * Next incoming transaction expected. Used to
	 * do multi transaction operations.
	 */
	transaction_t *transaction_in_next;
	
	/**
	 * Transaction which rekeys this IKE_SA, used do detect simultaneus rekeying
	 */
	rekey_ike_sa_t *rekeying_transaction;
};

/**
 * get the time of the latest traffic processed by the kernel
 */
static time_t get_kernel_time(private_ike_sa_t* this, bool inbound)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	time_t latest = 0, use_time;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_use_time(child_sa, inbound, &use_time) == SUCCESS)
		{
			latest = max(latest, use_time);
		}
	}
	iterator->destroy(iterator);
	
	return latest;
}

/**
 * get the time of the latest received traffice
 */
static time_t get_time_inbound(private_ike_sa_t *this)
{
	return max(this->time.inbound, get_kernel_time(this, TRUE));
}

/**
 * get the time of the latest sent traffic
 */
static time_t get_time_outbound(private_ike_sa_t *this)
{
	return max(this->time.outbound, get_kernel_time(this, FALSE));
}

/**
 * Implementation of ike_sa_t.get_name.
 */
static char *get_name(private_ike_sa_t *this)
{
	return this->name;
}

/**
 * Implementation of ike_sa_t.set_name.
 */
static void set_name(private_ike_sa_t *this, char* name)
{
	free(this->name);
	this->name = strdup(name);
}

/**
 * Implementation of ike_sa_t.apply_connection.
 */
static void apply_connection(private_ike_sa_t *this, connection_t *connection)
{
	this->dpd_delay = connection->get_dpd_delay(connection);
	this->retrans_sequences = connection->get_retrans_seq(connection);
}

/**
 * Implementation of ike_sa_t.get_my_host.
 */
static host_t *get_my_host(private_ike_sa_t *this)
{
	return this->my_host;
}

/**
 * Implementation of ike_sa_t.set_my_host.
 */
static void set_my_host(private_ike_sa_t *this, host_t *me)
{
	DESTROY_IF(this->my_host);
	this->my_host = me;
}

/**
 * Implementation of ike_sa_t.get_other_host.
 */
static host_t *get_other_host(private_ike_sa_t *this)
{
	return this->other_host;
}

/**
 * Implementation of ike_sa_t.set_other_host.
 */
static void set_other_host(private_ike_sa_t *this, host_t *other)
{
	DESTROY_IF(this->other_host);
	this->other_host = other;
}

/**
 * Update connection host, as addresses may change (NAT)
 */
static void update_hosts(private_ike_sa_t *this, host_t *me, host_t *other)
{
	/*
	 * Quoting RFC 4306:
	 *
	 * 2.11.  Address and Port Agility
	 * 
	 *    IKE runs over UDP ports 500 and 4500, and implicitly sets up ESP and
	 *    AH associations for the same IP addresses it runs over.  The IP
	 *    addresses and ports in the outer header are, however, not themselves
	 *    cryptographically protected, and IKE is designed to work even through
	 *    Network Address Translation (NAT) boxes.  An implementation MUST
	 *    accept incoming requests even if the source port is not 500 or 4500,
	 *    and MUST respond to the address and port from which the request was
	 *    received.  It MUST specify the address and port at which the request
	 *    was received as the source address and port in the response.  IKE
	 *    functions identically over IPv4 or IPv6.
	 *
	 *    [...]
	 *
	 *    There are cases where a NAT box decides to remove mappings that
	 *    are still alive (for example, the keepalive interval is too long,
	 *    or the NAT box is rebooted).  To recover in these cases, hosts
	 *    that are not behind a NAT SHOULD send all packets (including
	 *    retransmission packets) to the IP address and port from the last
	 *    valid authenticated packet from the other end (i.e., dynamically
	 *    update the address).  A host behind a NAT SHOULD NOT do this
	 *    because it opens a DoS attack possibility.  Any authenticated IKE
	 *    packet or any authenticated UDP-encapsulated ESP packet can be
	 *    used to detect that the IP address or the port has changed.
	 */
	iterator_t *iterator = NULL;
	child_sa_t *child_sa = NULL;
	host_diff_t my_diff, other_diff;
	
	if (this->my_host->is_anyaddr(this->my_host) ||
		this->other_host->is_anyaddr(this->other_host))
	{
		/* on first received message */
		this->my_host->destroy(this->my_host);
		this->my_host = me->clone(me);
		this->other_host->destroy(this->other_host);
		this->other_host = other->clone(other);
		return;
	}
	
	my_diff = me->get_differences(me, this->my_host);
	other_diff = other->get_differences(other, this->other_host);
	
	if (!my_diff && !other_diff)
	{
		return;
	}
	
	if (my_diff)
	{
		this->my_host->destroy(this->my_host);
		this->my_host = me->clone(me);
	}
	
	if (!this->nat_here)
	{
		/* update without restrictions if we are not NATted */
		if (other_diff)
		{
			this->other_host->destroy(this->other_host);
			this->other_host = other->clone(other);
		}
	}
	else
	{
		/* if we are natted, only port may change */
		if (other_diff & HOST_DIFF_ADDR)
		{
			return;
		}
		else if (other_diff & HOST_DIFF_PORT)
		{
			this->other_host->set_port(this->other_host, other->get_port(other));
		}
	}
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		child_sa->update_hosts(child_sa, this->my_host, this->other_host, 
							   my_diff, other_diff);
		/* TODO: what to do if update fails? Delete CHILD_SA? */
	}
	iterator->destroy(iterator);
}

/**
 * called when the peer is not responding anymore
 */
static void dpd_detected(private_ike_sa_t *this)
{
	/* check for childrens with dpdaction=hold */
	connection_t *connection = NULL;
	policy_t *policy;
	linked_list_t *my_ts, *other_ts;
	child_sa_t* child_sa;
	dpd_action_t action;
	job_t *job;
	
	this->logger->log(this->logger, CONTROL|LEVEL1,
					  "dead peer detected, handling CHILD_SAs dpd action");
	
	while(this->child_sas->remove_first(this->child_sas,
		  									(void**)&child_sa) == SUCCESS)
	{
		/* get the policy which belongs to this CHILD */
		my_ts = child_sa->get_my_traffic_selectors(child_sa);
		other_ts = child_sa->get_other_traffic_selectors(child_sa);
		policy = charon->policies->get_policy(charon->policies,
											  this->my_id, this->other_id,
											  my_ts, other_ts,
											  this->my_host, this->other_host);
		if (policy == NULL)
		{
			this->logger->log(this->logger, ERROR,
							  "no policy found for this CHILD_SA");
			continue;
		}
		
		action = policy->get_dpd_action(policy);
		/* get a connection for further actions */
		if (connection == NULL && 
			(action == DPD_ROUTE || action == DPD_RESTART))
		{
			connection = charon->connections->get_connection_by_hosts(
											charon->connections,
											this->my_host, this->other_host);
			if (connection == NULL)
			{
				this->logger->log(this->logger, ERROR,
								  "no connection found for this IKE_SA");
				break;
			}
		}
		
		this->logger->log(this->logger, CONTROL, "dpd action for %s is %s", 
						  policy->get_name(policy),
						  enum_name(&dpd_action_names, action));
		
		switch (action)
		{
			case DPD_ROUTE:
				connection->get_ref(connection);
				job = (job_t*)route_job_create(connection, policy, TRUE);
				charon->job_queue->add(charon->job_queue, job);
				break;
			case DPD_RESTART:
				connection->get_ref(connection);
				job = (job_t*)initiate_job_create(connection, policy);
				charon->job_queue->add(charon->job_queue, job);
				break;
			default:
				policy->destroy(policy);
				break;
		}
		child_sa->destroy(child_sa);
	}
	DESTROY_IF(connection);
}

/**
 * send a request and schedule retransmission
 */
static status_t transmit_request(private_ike_sa_t *this)
{
	message_t *request;
	packet_t *packet;
	status_t status;
	retransmit_request_job_t *job;
	u_int32_t transmitted;
	u_int32_t timeout;
	transaction_t *transaction = this->transaction_out;
	u_int32_t message_id;
	
	transmitted = transaction->requested(transaction);
	timeout = charon->configuration->get_retransmit_timeout(charon->configuration,
															transmitted,
															this->retrans_sequences);
	if (timeout == 0)
	{
		this->logger->log(this->logger, ERROR,
						  "giving up after %d retransmits, deleting IKE_SA",
						  transmitted - 1);
		dpd_detected(this);
		return DESTROY_ME;
	}
	
	status = transaction->get_request(transaction, &request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR,
						  "generating request failed");
		return status;
	}
	message_id = transaction->get_message_id(transaction);
	/* if we retransmit, the request is already generated */
	if (transmitted == 0)
	{
		status = request->generate(request, this->crypter_out, this->signer_out, &packet);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
							  "request generation failed. transaction discarded");
			return FAILED;
		}
	}
	else
	{
		this->logger->log(this->logger, CONTROL, 
						  "sending retransmit %d for %s request with message ID %d",
						  transmitted,
						  mapping_find(exchange_type_m, request->get_exchange_type(request)),
						  message_id);
		packet = request->get_packet(request);
	}
	/* finally send */
	charon->send_queue->add(charon->send_queue, packet);
	this->time.outbound = time(NULL);
	
	/* schedule retransmission job */
	job = retransmit_request_job_create(message_id, this->ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue, (job_t*)job, timeout);
	return SUCCESS;
}

/**
 * Implementation of ike_sa.retransmit_request.
 */
static status_t retransmit_request(private_ike_sa_t *this, u_int32_t message_id)
{
	if (this->transaction_out == NULL ||
		this->transaction_out->get_message_id(this->transaction_out) != message_id)
	{
		/* no retransmit necessary, transaction did already complete */
		return SUCCESS;
	}
	return transmit_request(this);
}

/**
 * Check for transactions in the queue and initiate the first transaction found.
 */
static status_t process_transaction_queue(private_ike_sa_t *this)
{
	if (this->transaction_out)
	{
		/* already a transaction in progress */
		return SUCCESS;
	}
	
	while (TRUE)
	{
		if (this->transaction_queue->remove_first(this->transaction_queue,
			(void**)&this->transaction_out) != SUCCESS)
		{
			/* transaction queue empty */
			return SUCCESS;
		}
		switch (transmit_request(this))
		{
			case SUCCESS:
				return SUCCESS;
			case DESTROY_ME:
				/* critical, IKE_SA unusable, destroy immediately */
				this->logger->log(this->logger, ERROR, 
								  "transaction initiaton failed, deleting IKE_SA");
				return DESTROY_ME;
			default:
				/* discard transaction, process next one */
				this->logger->log(this->logger, ERROR, 
								  "transaction initiation failed, discarded");
				this->transaction_out->destroy(this->transaction_out);
				this->transaction_out = NULL;
				/* handle next transaction */
				continue;
		}
	}
}

/**
 * Queue a new transaction and execute the next outstanding transaction
 */
static status_t queue_transaction(private_ike_sa_t *this, transaction_t *transaction, bool prefer)
{
	/* inject next transaction */
	if (transaction)
	{
		if (prefer)
		{
			this->transaction_queue->insert_first(this->transaction_queue, transaction);
		}
		else
		{
			this->transaction_queue->insert_last(this->transaction_queue, transaction);
		}
	}
	/* process a transaction */
	return process_transaction_queue(this);
}

/**
 * process an incoming request.
 */
static status_t process_request(private_ike_sa_t *this, message_t *request)
{
	transaction_t *last, *current = NULL;
	message_t *response;
	packet_t *packet;
	u_int32_t request_mid;
	status_t status;
	
	request_mid = request->get_message_id(request);
	last = this->transaction_in;
	
	/* check if message ID is correct */
	if (last)
	{
		u_int32_t last_mid = last->get_message_id(last);
		
		if (last_mid == request_mid)
		{
			/* retransmit detected */
			this->logger->log(this->logger, ERROR,
							  "received retransmitted request for message ID %d, retransmitting response",
							  request_mid);
			last->get_response(last, request, &response, &this->transaction_in_next);
			packet = response->get_packet(response);
			charon->send_queue->add(charon->send_queue, packet);
			this->time.outbound = time(NULL);
			return SUCCESS;
		}
		
		if (last_mid > request_mid)
		{
			/* something seriously wrong here, message id may not decrease */
			this->logger->log(this->logger, ERROR,
							  "received request with message ID %d, excepted %d, ingored",
							  request_mid, last_mid + 1);
			return FAILED;
		}
		/* we allow jumps in message IDs, as long as they are incremental */
		if (last_mid + 1 < request_mid)
		{
			this->logger->log(this->logger, ERROR,
							  "received request with message ID %d, excepted %d",
							  request_mid, last_mid + 1);
		}
	}
	else
	{
		if (request_mid != 0)
		{
			/* warn, but allow it */
			this->logger->log(this->logger, CONTROL,
							  "first received request has message ID %d, excepted 0", 
							  request_mid);
		}
	}
	
	/* check if we already have a pre-created transaction for this request */
	if (this->transaction_in_next)
	{
		current = this->transaction_in_next;
		this->transaction_in_next = NULL;
	}
	else
	{
		current = transaction_create(&this->public, request);
		if (current == NULL)
		{
			this->logger->log(this->logger, ERROR, 
							  "no idea how to handle received message (%d), ignored",
							  request->get_exchange_type(request));
			return FAILED;
		}
	}
	
	/* send message. get_request() always gives a valid response */
	status = current->get_response(current, request, &response, &this->transaction_in_next);
	if (response->generate(response, this->crypter_out, this->signer_out, &packet) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, 
						  "response generation failed, discarding transaction");
		current->destroy(current);
		return FAILED;
	}
	
	charon->send_queue->add(charon->send_queue, packet);
	this->time.outbound = time(NULL);
	/* act depending on transaction result */
	switch (status)
	{
		case DESTROY_ME:
			/* transactions says we should destroy the IKE_SA, so do it */
			current->destroy(current);
			return DESTROY_ME;
		default:
			/* store for retransmission, destroy old transaction */
			this->transaction_in = current;
			if (last)
			{
				last->destroy(last);
			}
			return SUCCESS;
	}
}

/**
 * process an incoming response
 */
static status_t process_response(private_ike_sa_t *this, message_t *response)
{
	transaction_t *current, *new = NULL;
	
	current = this->transaction_out;
	/* check if message ID is that of our currently active transaction */
	if (current == NULL ||
		current->get_message_id(current) != response->get_message_id(response))
	{
		this->logger->log(this->logger, ERROR, 
						  "received response with message ID %d not requested, ignored");
		return FAILED;
	}
	
	switch (current->conclude(current, response, &new))
	{
		case DESTROY_ME:
			/* state requested to destroy IKE_SA */
			return DESTROY_ME;
		default:
			/* discard transaction, process next one */
			break;
	}
	/* transaction comleted, remove */
	current->destroy(current);
	this->transaction_out = NULL;
	
	/* queue new transaction */
	return queue_transaction(this, new, TRUE);
}

/**
 * send a notify back to the sender
 */
static void send_notify_response(private_ike_sa_t *this,
								 message_t *request,
								 notify_type_t type)
{
	notify_payload_t *notify;
	message_t *response;
	host_t *src, *dst;
	packet_t *packet;
	
	response = message_create();
	dst = request->get_source(request);
	src = request->get_destination(request);
	response->set_source(response, src->clone(src));
	response->set_destination(response, dst->clone(dst));
	response->set_exchange_type(response, request->get_exchange_type(request));
	response->set_request(response, FALSE);
	response->set_message_id(response, request->get_message_id(request));
	response->set_ike_sa_id(response, this->ike_sa_id);
	notify = notify_payload_create_from_protocol_and_type(PROTO_NONE, type);
	response->add_payload(response, (payload_t *)notify);
	if (response->generate(response, this->crypter_out, this->signer_out, &packet) != SUCCESS)
	{
		response->destroy(response);
		return;
	}
	charon->send_queue->add(charon->send_queue, packet);
	this->time.outbound = time(NULL);
	response->destroy(response);
	return;
}


/**
 * Implementation of ike_sa_t.process_message.
 */
static status_t process_message(private_ike_sa_t *this, message_t *message)
{
	status_t status;
	bool is_request;
	
	is_request = message->get_request(message);
	
	status = message->parse_body(message, this->crypter_in, this->signer_in);
	if (status != SUCCESS)
	{
		if (is_request)
		{
			switch (status)
			{
				case NOT_SUPPORTED:
					this->logger->log(this->logger, ERROR,
									"ciritcal unknown payloads found");
					if (is_request)
					{
						send_notify_response(this, message, UNSUPPORTED_CRITICAL_PAYLOAD);
					}
					break;
				case PARSE_ERROR:
					this->logger->log(this->logger, ERROR,
									"message parsing failed");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
					break;
				case VERIFY_ERROR:
					this->logger->log(this->logger, ERROR,
									"message verification failed");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
					break;
				case FAILED:
					this->logger->log(this->logger, ERROR,
									"integrity check failed");
					/* ignored */
					break;
				case INVALID_STATE:
					this->logger->log(this->logger, ERROR,
									"found encrypted message, but no keys available");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
				default:
					break;
			}
		}
		this->logger->log(this->logger, ERROR,
						  "%s %s with message ID %d processing failed",
						  mapping_find(exchange_type_m, message->get_exchange_type(message)),
						  message->get_request(message) ? "request" : "response",
						  message->get_message_id(message));
	}
	else
	{
		/* check if message is trustworthy, and update connection information */
		if (this->state == IKE_CREATED ||
			message->get_exchange_type(message) != IKE_SA_INIT)
		{
			update_hosts(this, message->get_destination(message),
							   message->get_source(message));
			this->time.inbound = time(NULL);
		}
		if (is_request)
		{
			status = process_request(this, message);
		}
		else
		{
			status = process_response(this, message);
		}
	}
	return status;
}

/**
 * Implementation of ike_sa_t.initiate.
 */
static status_t initiate(private_ike_sa_t *this,
						 connection_t *connection, policy_t *policy)
{
	switch (this->state)
	{
		case IKE_CREATED:
		{
			/* in state CREATED, we must do the ike_sa_init
			 * and ike_auth transactions. Along with these,
			 * a CHILD_SA with the supplied policy is set up.
			 */
			ike_sa_init_t *ike_sa_init;
			
			this->logger->log(this->logger, CONTROL, 
							  "initiating IKE_SA");
			DESTROY_IF(this->my_host);
			this->my_host = connection->get_my_host(connection);
			this->my_host = this->my_host->clone(this->my_host);
			DESTROY_IF(this->other_host);
			this->other_host = connection->get_other_host(connection);
			this->other_host = this->other_host->clone(this->other_host);
			this->retrans_sequences = connection->get_retrans_seq(connection);
			this->dpd_delay = connection->get_dpd_delay(connection);
			
			this->message_id_out = 1;
			ike_sa_init = ike_sa_init_create(&this->public);
			ike_sa_init->set_config(ike_sa_init, connection, policy);
			return queue_transaction(this, (transaction_t*)ike_sa_init, TRUE);
		}
		case IKE_DELETING:
		case IKE_REKEYING:
		{
			/* if we are in DELETING/REKEYING, we deny set up of a policy. */
			this->logger->log(this->logger, CONTROL, 
							  "creating CHILD_SA discarded, as IKE_SA is in state %s",
							  mapping_find(ike_sa_state_m, this->state));
			policy->destroy(policy);
			connection->destroy(connection);
			return FAILED;
		}
		case IKE_CONNECTING:
		case IKE_ESTABLISHED:
		{
			/* if we are ESTABLISHED or CONNECTING,we queue the 
			 * transaction to create the CHILD_SA. It gets processed
			 * when the IKE_SA is ready to do so. We don't need the
			 * connection, as the IKE_SA is already established/establishing.
			 */
			create_child_sa_t *create_child;
			
			this->logger->log(this->logger, CONTROL, 
							  "initiating CHILD_SA");
			
			connection->destroy(connection);
			create_child = create_child_sa_create(&this->public);
			create_child->set_policy(create_child, policy);
			return queue_transaction(this, (transaction_t*)create_child, FALSE);
		}
	}
	return FAILED;
}

/**
 * Implementation of ike_sa_t.acquire.
 */
static status_t acquire(private_ike_sa_t *this, u_int32_t reqid)
{
	connection_t *connection;
	policy_t *policy;
	iterator_t *iterator;
	child_sa_t *current, *child_sa = NULL;
	linked_list_t *my_ts, *other_ts;
	
	if (this->state == IKE_DELETING)
	{
		this->logger->log(this->logger, CONTROL, 
						  "acquiring CHILD_SA with reqid %d discarded, as IKE_SA is deleting",
						  reqid);
		return FAILED;
	}
	
	
	/* find CHILD_SA */
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->get_reqid(current) == reqid)
		{
			child_sa = current;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!child_sa)
	{
		this->logger->log(this->logger, ERROR, 
						  "CHILD_SA with reqid %d not found, unable to acquire",
						  reqid);
		return FAILED;
	}
	my_ts = child_sa->get_my_traffic_selectors(child_sa);
	other_ts = child_sa->get_other_traffic_selectors(child_sa);
	
	policy = charon->policies->get_policy(charon->policies, 
										  this->my_id, this->other_id, 
										  my_ts, other_ts, 
										  this->my_host, this->other_host);
	if (policy == NULL)
	{
		this->logger->log(this->logger, ERROR, 
						  "no policy found to acquire CHILD_SA with reqid %d", 
						  reqid);
		return FAILED;
	}
	
	switch (this->state)
	{
		case IKE_CREATED:
		{
			ike_sa_init_t *ike_sa_init;
			
			this->logger->log(this->logger, CONTROL,
							  "acquiring CHILD_SA with reqid %d, IKE_SA setup needed", 
							  reqid);
			
			connection = charon->connections->get_connection_by_hosts(
					charon->connections, this->my_host, this->other_host);
			
			if (connection == NULL)
			{
				this->logger->log(this->logger, ERROR, 
								  "no connection found to acquire IKE_SA for CHILD_SA with reqid %d", 
								  reqid);
				policy->destroy(policy);
				return FAILED;
			}
			
			this->message_id_out = 1;
			ike_sa_init = ike_sa_init_create(&this->public);
			ike_sa_init->set_config(ike_sa_init, connection, policy);
			/* reuse existing reqid */
			ike_sa_init->set_reqid(ike_sa_init, reqid);
			return queue_transaction(this, (transaction_t*)ike_sa_init, TRUE);
		}
		case IKE_CONNECTING:
		case IKE_ESTABLISHED:
		{
			create_child_sa_t *create_child;
			
			this->logger->log(this->logger, CONTROL, 
							  "acquiring CHILD_SA with reqid %d",
							  reqid);
			
			create_child = create_child_sa_create(&this->public);
			create_child->set_policy(create_child, policy);
			/* reuse existing reqid */
			create_child->set_reqid(create_child, reqid);
			return queue_transaction(this, (transaction_t*)create_child, FALSE);
		}
		default:
			break;
	}
	return FAILED;
}

/**
 * destroy a list of traffic selectors
 */
static void ts_list_destroy(linked_list_t *list)
{
	traffic_selector_t *ts;
	while (list->remove_last(list, (void**)&ts) == SUCCESS)
	{
		ts->destroy(ts);
	}
	list->destroy(list);
}

/**
 * compare two lists of traffic selectors for equality
 */
static bool ts_list_equals(linked_list_t *l1, linked_list_t *l2)
{
	bool equals = TRUE;
	iterator_t *i1, *i2;
	traffic_selector_t *t1, *t2;
	
	i1 = l1->create_iterator(l1, TRUE);
	i2 = l2->create_iterator(l2, TRUE);
	while (i1->iterate(i1, (void**)&t1) && i2->iterate(i2, (void**)&t2))
	{
		if (!t1->equals(t1, t2))
		{
			equals = FALSE;
			break;
		}
	}
	/* check if one iterator is not at the end */
	if (i1->has_next(i1) || i2->has_next(i2))
	{
		equals = FALSE;
	}
	i1->destroy(i1);
	i2->destroy(i2);
	return equals;
}

/**
 * Implementation of ike_sa_t.route.
 */
static status_t route(private_ike_sa_t *this, connection_t *connection, policy_t *policy)
{
	child_sa_t *child_sa = NULL;
	iterator_t *iterator;
	linked_list_t *my_ts, *other_ts;
	status_t status;
	
	/* check if not already routed*/
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) == CHILD_ROUTED)
		{
			linked_list_t *my_ts_conf, *other_ts_conf;
			
			my_ts = child_sa->get_my_traffic_selectors(child_sa);
			other_ts = child_sa->get_other_traffic_selectors(child_sa);
			
			my_ts_conf = policy->get_my_traffic_selectors(policy, this->my_host);
			other_ts_conf = policy->get_other_traffic_selectors(policy, this->other_host);
			
			if (ts_list_equals(my_ts, my_ts_conf) &&
					ts_list_equals(other_ts, other_ts_conf))
			{
				ts_list_destroy(my_ts_conf);
				ts_list_destroy(other_ts_conf);
				iterator->destroy(iterator);
				this->logger->log(this->logger, CONTROL, 
								"a CHILD_SA with such a policy already routed");
				
				return FAILED;
			}
			ts_list_destroy(my_ts_conf);
			ts_list_destroy(other_ts_conf);
		}
	}
	iterator->destroy(iterator);
	
	switch (this->state)
	{
		case IKE_CREATED:
		case IKE_CONNECTING:
			/* we update IKE_SA information as good as possible, 
			 * this allows us to set up the SA later when an acquire comes in. */
			if (this->my_id->get_type(this->my_id) == ID_ANY)
			{
				this->my_id->destroy(this->my_id);
				this->my_id = policy->get_my_id(policy);
				this->my_id = this->my_id->clone(this->my_id);
			}
			if (this->other_id->get_type(this->other_id) == ID_ANY)
			{
				this->other_id->destroy(this->other_id);
				this->other_id = policy->get_other_id(policy);
				this->other_id = this->other_id->clone(this->other_id);
			}
			if (this->my_host->is_anyaddr(this->my_host))
			{
				this->my_host->destroy(this->my_host);
				this->my_host = connection->get_my_host(connection);
				this->my_host = this->my_host->clone(this->my_host);
			}
			if (this->other_host->is_anyaddr(this->other_host))
			{
				this->other_host->destroy(this->other_host);
				this->other_host = connection->get_other_host(connection);
				this->other_host = this->other_host->clone(this->other_host);
			}
			set_name(this, connection->get_name(connection));
			this->retrans_sequences = connection->get_retrans_seq(connection);
			this->dpd_delay = connection->get_dpd_delay(connection);
			break;
		case IKE_ESTABLISHED:
		case IKE_REKEYING:
			/* nothing to do. We allow it for rekeying, as it will be
			 * adopted by the new IKE_SA */
			break;
		case IKE_DELETING:
			/* deny */
			return FAILED;
	}

	child_sa = child_sa_create(0, this->my_host, this->other_host,
							   this->my_id, this->other_id,
							   0, 0,
							   NULL, policy->get_hostaccess(policy),
							   FALSE);
	child_sa->set_name(child_sa, policy->get_name(policy));
	my_ts = policy->get_my_traffic_selectors(policy, this->my_host);
	other_ts = policy->get_other_traffic_selectors(policy, this->other_host);
	status = child_sa->add_policies(child_sa, my_ts, other_ts);
	ts_list_destroy(my_ts);
	ts_list_destroy(other_ts);
	this->child_sas->insert_last(this->child_sas, child_sa);
	
	return status;
}

/**
 * Implementation of ike_sa_t.unroute.
 */
static status_t unroute(private_ike_sa_t *this, policy_t *policy)
{
	iterator_t *iterator;
	child_sa_t *child_sa = NULL;
	linked_list_t *my_ts, *other_ts, *my_ts_conf, *other_ts_conf;
	
	/* find CHILD_SA in ROUTED state */
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) == CHILD_ROUTED)
		{
			my_ts = child_sa->get_my_traffic_selectors(child_sa);
			other_ts = child_sa->get_other_traffic_selectors(child_sa);
			
			my_ts_conf = policy->get_my_traffic_selectors(policy, this->my_host);
			other_ts_conf = policy->get_other_traffic_selectors(policy, this->other_host);
			
			if (ts_list_equals(my_ts, my_ts_conf) &&
				ts_list_equals(other_ts, other_ts_conf))
			{
				iterator->remove(iterator);
				child_sa->destroy(child_sa);
				ts_list_destroy(my_ts_conf);
				ts_list_destroy(other_ts_conf);
				break;
			}
			ts_list_destroy(my_ts_conf);
			ts_list_destroy(other_ts_conf);
		}
	}
	iterator->destroy(iterator);
	/* if we are not established, and we have no more routed childs, remove whole SA */
	if (this->state == IKE_CREATED &&
		this->child_sas->get_count(this->child_sas) == 0)
	{
		return DESTROY_ME;
	}
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.send_dpd
 */
static status_t send_dpd(private_ike_sa_t *this)
{
	send_dpd_job_t *job;
	time_t diff;
	
	if (this->dpd_delay == 0)
	{
		/* DPD disabled */
		return SUCCESS;
	}
	
	if (this->transaction_out)
	{
		/* there is a transaction in progress. Come back later */
		diff = 0;
	}
	else
	{
		/* check if there was any inbound traffic */
		time_t last_in, now;
		last_in = get_time_inbound(this);
		now = time(NULL);
		diff = now - last_in;
		if (diff >= this->dpd_delay)
		{
			/* to long ago, initiate dead peer detection */
			dead_peer_detection_t *dpd;
			this->logger->log(this->logger, CONTROL, "sending DPD request");
			dpd = dead_peer_detection_create(&this->public);
			queue_transaction(this, (transaction_t*)dpd, FALSE);
			diff = 0;
		}
	}
	/* recheck in "interval" seconds */
	job = send_dpd_job_create(this->ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue, (job_t*)job,
									  (this->dpd_delay - diff) * 1000);
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.send_keepalive
 */
static void send_keepalive(private_ike_sa_t *this)
{
	send_keepalive_job_t *job;
	time_t last_out, now, diff, interval;
	
	last_out = get_time_outbound(this);
	now = time(NULL);
	
	diff = now - last_out;
	interval = charon->configuration->get_keepalive_interval(charon->configuration);
	
	if (diff >= interval)
	{
		packet_t *packet;
		chunk_t data;
		
		packet = packet_create();
		packet->set_source(packet, this->my_host->clone(this->my_host));
		packet->set_destination(packet, this->other_host->clone(this->other_host));
		data.ptr = malloc(1);
		data.ptr[0] = 0xFF;
		data.len = 1;
		packet->set_data(packet, data);
		charon->send_queue->add(charon->send_queue, packet);
		this->logger->log(this->logger, CONTROL, "sending keep alive");
		diff = 0;
	}
	job = send_keepalive_job_create(this->ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue, (job_t*)job,
									  (interval - diff) * 1000);
}

/**
 * Implementation of ike_sa_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_t *this)
{
	return this->state;
}

/**
 * Implementation of ike_sa_t.set_state.
 */
static void set_state(private_ike_sa_t *this, ike_sa_state_t state)
{
	this->logger->log(this->logger, CONTROL, "state change: %s => %s",
					  mapping_find(ike_sa_state_m, this->state),
					  mapping_find(ike_sa_state_m, state));
	if (state == IKE_ESTABLISHED)
	{
		this->time.established = time(NULL);
		this->logger->log(this->logger, AUDIT, "IKE_SA established: %s[%s]...%s[%s]",
						this->my_host->get_string(this->my_host),
						this->my_id->get_string(this->my_id),
						this->other_host->get_string(this->other_host),
						this->other_id->get_string(this->other_id));
		/* start DPD checks */
		send_dpd(this);
	}
	this->state = state;
}

/**
 * Implementation of ike_sa_t.get_prf.
 */
static prf_t *get_prf(private_ike_sa_t *this)
{
	return this->prf;
}

/**
 * Implementation of ike_sa_t.get_prf.
 */
static prf_t *get_child_prf(private_ike_sa_t *this)
{
	return this->child_prf;
}

/**
 * Implementation of ike_sa_t.get_prf_auth_i.
 */
static prf_t *get_prf_auth_i(private_ike_sa_t *this)
{
	return this->prf_auth_i;
}

/**
 * Implementation of ike_sa_t.get_prf_auth_r.
 */
static prf_t *get_prf_auth_r(private_ike_sa_t *this)
{
	return this->prf_auth_r;
}

/**
 * Implementation of ike_sa_t.get_id.
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implementation of ike_sa_t.get_my_id.
 */
static identification_t* get_my_id(private_ike_sa_t *this)
{
	return this->my_id;
}

/**
 * Implementation of ike_sa_t.set_my_id.
 */
static void set_my_id(private_ike_sa_t *this, identification_t *me)
{
	DESTROY_IF(this->my_id);
	this->my_id = me;
}

/**
 * Implementation of ike_sa_t.get_other_id.
 */
static identification_t* get_other_id(private_ike_sa_t *this)
{
	return this->other_id;
}

/**
 * Implementation of ike_sa_t.set_other_id.
 */
static void set_other_id(private_ike_sa_t *this, identification_t *other)
{
	DESTROY_IF(this->other_id);
	this->other_id = other;
}

/**
 * Implementation of ike_sa_t.derive_keys.
 */
static status_t derive_keys(private_ike_sa_t *this,
							proposal_t *proposal, diffie_hellman_t *dh,
							chunk_t nonce_i, chunk_t nonce_r,
							bool initiator, prf_t *child_prf, prf_t *old_prf)
{
	prf_plus_t *prf_plus;
	chunk_t skeyseed, secret, key, nonces, prf_plus_seed;
	algorithm_t *algo;
	size_t key_size;
	crypter_t *crypter_i, *crypter_r;
	signer_t *signer_i, *signer_r;
	u_int8_t spi_i_buf[sizeof(u_int64_t)], spi_r_buf[sizeof(u_int64_t)];
	chunk_t spi_i = chunk_from_buf(spi_i_buf);
	chunk_t spi_r = chunk_from_buf(spi_r_buf);
	
	/* Create SAs general purpose PRF first, we may use it here */
	if (!proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &algo))
	{
		this->logger->log(this->logger, ERROR, "no PSEUDO_RANDOM_FUNCTION selected!");
		return FAILED;
	}
	this->prf = prf_create(algo->algorithm);
	if (this->prf == NULL)
	{
		this->logger->log(this->logger, ERROR, "PSEUDO_RANDOM_FUNCTION %s not supported!",
						  mapping_find(pseudo_random_function_m, algo->algorithm));
		return FAILED;
	}
	
	dh->get_shared_secret(dh, &secret);
	this->logger->log_chunk(this->logger, PRIVATE, "shared Diffie Hellman secret", secret);
	nonces = chunk_cat("cc", nonce_i, nonce_r);
	*((u_int64_t*)spi_i.ptr) = this->ike_sa_id->get_initiator_spi(this->ike_sa_id);
	*((u_int64_t*)spi_r.ptr) = this->ike_sa_id->get_responder_spi(this->ike_sa_id);
	prf_plus_seed = chunk_cat("ccc", nonces, spi_i, spi_r);
	
	/* KEYMAT = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) 
	 *
	 * if we are rekeying, SKEYSEED built on another way 
	 */
	if (child_prf == NULL) /* not rekeying */
	{	
		/* SKEYSEED = prf(Ni | Nr, g^ir) */
		this->prf->set_key(this->prf, nonces);
		this->prf->allocate_bytes(this->prf, secret, &skeyseed);
		this->logger->log_chunk(this->logger, PRIVATE|LEVEL1, "SKEYSEED", skeyseed);
		this->prf->set_key(this->prf, skeyseed);
		chunk_free(&skeyseed);
		chunk_free(&secret);
		prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	}
	else
	{
		/* SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr) 
		 * use OLD SAs PRF functions for both prf_plus and prf */
		secret = chunk_cat("mc", secret, nonces);
		child_prf->allocate_bytes(child_prf, secret, &skeyseed);
		this->logger->log_chunk(this->logger, PRIVATE|LEVEL1, "SKEYSEED", skeyseed);
		old_prf->set_key(old_prf, skeyseed);
		chunk_free(&skeyseed);
		chunk_free(&secret);
		prf_plus = prf_plus_create(old_prf, prf_plus_seed);
	}
	chunk_free(&nonces);
	chunk_free(&prf_plus_seed);
	
	/* KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr */
	
	/* SK_d is used for generating CHILD_SA key mat => child_prf */
	proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &algo);
	this->child_prf = prf_create(algo->algorithm);
	key_size = this->child_prf->get_key_size(this->child_prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_d secret", key);
	this->child_prf->set_key(this->child_prf, key);
	chunk_free(&key);
	
	/* SK_ai/SK_ar used for integrity protection => signer_in/signer_out */
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &algo))
	{
		this->logger->log(this->logger, ERROR, "no INTEGRITY_ALGORITHM selected?!");
		return FAILED;
	}
	signer_i = signer_create(algo->algorithm);
	signer_r = signer_create(algo->algorithm);
	if (signer_i == NULL || signer_r == NULL)
	{
		this->logger->log(this->logger, ERROR, "INTEGRITY_ALGORITHM %s not supported!",
						  mapping_find(integrity_algorithm_m,algo->algorithm));
		return FAILED;
	}
	key_size = signer_i->get_key_size(signer_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ai secret", key);
	signer_i->set_key(signer_i, key);
	chunk_free(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ar secret", key);
	signer_r->set_key(signer_r, key);
	chunk_free(&key);
	
	if (initiator)
	{
		this->signer_in = signer_r;
		this->signer_out = signer_i;
	}
	else
	{
		this->signer_in = signer_i;
		this->signer_out = signer_r;
	}
	
	/* SK_ei/SK_er used for encryption => crypter_in/crypter_out */
	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &algo))
	{
		this->logger->log(this->logger, ERROR, "no ENCRYPTION_ALGORITHM selected!");
		return FAILED;
	}
	crypter_i = crypter_create(algo->algorithm, algo->key_size / 8);
	crypter_r = crypter_create(algo->algorithm, algo->key_size / 8);
	if (crypter_i == NULL || crypter_r == NULL)
	{
		this->logger->log(this->logger, ERROR, 
						  "ENCRYPTION_ALGORITHM %s (key size %d) not supported!",
						  mapping_find(encryption_algorithm_m, algo->algorithm),
						  algo->key_size);
		return FAILED;
	}
	key_size = crypter_i->get_key_size(crypter_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ei secret", key);
	crypter_i->set_key(crypter_i, key);
	chunk_free(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_er secret", key);
	crypter_r->set_key(crypter_r, key);
	chunk_free(&key);
	
	if (initiator)
	{
		this->crypter_in = crypter_r;
		this->crypter_out = crypter_i;
	}
	else
	{
		this->crypter_in = crypter_i;
		this->crypter_out = crypter_r;
	}
	
	/* SK_pi/SK_pr used for authentication => prf_auth_i, prf_auth_r */	
	proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &algo);
	this->prf_auth_i = prf_create(algo->algorithm);
	this->prf_auth_r = prf_create(algo->algorithm);
	
	key_size = this->prf_auth_i->get_key_size(this->prf_auth_i);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pi secret", key);
	this->prf_auth_i->set_key(this->prf_auth_i, key);
	chunk_free(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pr secret", key);
	this->prf_auth_r->set_key(this->prf_auth_r, key);
	chunk_free(&key);
	
	/* all done, prf_plus not needed anymore */
	prf_plus->destroy(prf_plus);
	
	return SUCCESS;
	
}

/**
 * Implementation of ike_sa_t.add_child_sa.
 */
static void add_child_sa(private_ike_sa_t *this, child_sa_t *child_sa)
{
	this->child_sas->insert_last(this->child_sas, child_sa);
}

/**
 * Implementation of ike_sa_t.has_child_sa.
 */
static bool has_child_sa(private_ike_sa_t *this, u_int32_t reqid)
{
	iterator_t *iterator;
	child_sa_t *current;
	bool found = FALSE;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->get_reqid(current) == reqid)
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of ike_sa_t.get_child_sa.
 */
static child_sa_t* get_child_sa(private_ike_sa_t *this, protocol_id_t protocol,
								u_int32_t spi, bool inbound)
{
	iterator_t *iterator;
	child_sa_t *current, *found = NULL;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);
		if (current->get_spi(current, inbound) == spi &&
				  current->get_protocol(current) == protocol)
		{
			found = current;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of ike_sa_t.create_child_sa_iterator.
 */
static iterator_t* create_child_sa_iterator(private_ike_sa_t *this)
{
	return this->child_sas->create_iterator(this->child_sas, TRUE);
}

/**
 * Implementation of ike_sa_t.rekey_child_sa.
 */
static status_t rekey_child_sa(private_ike_sa_t *this, protocol_id_t protocol, u_int32_t spi)
{
	create_child_sa_t *rekey;
	child_sa_t *child_sa;
	
	child_sa = get_child_sa(this, protocol, spi, TRUE);
	if (child_sa == NULL)
	{
		return NOT_FOUND;
	}
	
	rekey = create_child_sa_create(&this->public);
	rekey->rekeys_child(rekey, child_sa);
	return queue_transaction(this, (transaction_t*)rekey, FALSE);
}

/**
 * Implementation of ike_sa_t.delete_child_sa.
 */
static status_t delete_child_sa(private_ike_sa_t *this, protocol_id_t protocol, u_int32_t spi)
{
	delete_child_sa_t *del;
	child_sa_t *child_sa;
	
	child_sa = get_child_sa(this, protocol, spi, TRUE);
	if (child_sa == NULL)
	{
		return NOT_FOUND;
	}
	
	del = delete_child_sa_create(&this->public);
	del->set_child_sa(del, child_sa);
	return queue_transaction(this, (transaction_t*)del, FALSE);
}

/**
 * Implementation of ike_sa_t.destroy_child_sa.
 */
static status_t destroy_child_sa(private_ike_sa_t *this, protocol_id_t protocol, u_int32_t spi)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	status_t status = NOT_FOUND;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_protocol(child_sa) == protocol &&
			child_sa->get_spi(child_sa, TRUE) == spi)
		{
			child_sa->destroy(child_sa);
			iterator->remove(iterator);
			status = SUCCESS;
			break;
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of ike_sa_t.set_lifetimes.
 */
static void set_lifetimes(private_ike_sa_t *this,
						  u_int32_t soft_lifetime, u_int32_t hard_lifetime)
{
	job_t *job;
	
	if (soft_lifetime)
	{
		this->time.rekey = this->time.established + soft_lifetime;
		job = (job_t*)rekey_ike_sa_job_create(this->ike_sa_id);
		charon->event_queue->add_relative(charon->event_queue, job,
										  soft_lifetime * 1000);
	}
	
	if (hard_lifetime)
	{
		this->time.delete = this->time.established + hard_lifetime;
		job = (job_t*)delete_ike_sa_job_create(this->ike_sa_id, TRUE);
		charon->event_queue->add_relative(charon->event_queue, job,
										  hard_lifetime * 1000);
	}
}

/**
 * Implementation of ike_sa_t.rekey.
 */
static status_t rekey(private_ike_sa_t *this)
{
	rekey_ike_sa_t *rekey_ike_sa;
	
	this->logger->log(this->logger, CONTROL, 
					  "rekeying IKE_SA between %s[%s]..%s[%s]",
					  this->my_host->get_string(this->my_host),
					  this->my_id->get_string(this->my_id),
					  this->other_host->get_string(this->other_host),
					  this->other_id->get_string(this->other_id));
	
	if (this->state != IKE_ESTABLISHED)
	{
		this->logger->log(this->logger, ERROR, 
						  "unable to rekey IKE_SA in state %s",
						  mapping_find(ike_sa_state_m, this->state));
		return FAILED;
	}
	
	rekey_ike_sa = rekey_ike_sa_create(&this->public);
	return queue_transaction(this, (transaction_t*)rekey_ike_sa, FALSE);
}

/**
 * Implementation of ike_sa_t.get_rekeying_transaction.
 */
static rekey_ike_sa_t* get_rekeying_transaction(private_ike_sa_t *this)
{
	return this->rekeying_transaction;
}

/**
 * Implementation of ike_sa_t.set_rekeying_transaction.
 */
static void set_rekeying_transaction(private_ike_sa_t *this, rekey_ike_sa_t *rekey)
{
	this->rekeying_transaction = rekey;
}

/**
 * Implementation of ike_sa_t.adopt_children.
 */
static void adopt_children(private_ike_sa_t *this, private_ike_sa_t *other)
{
	child_sa_t *child_sa;
	
	while (other->child_sas->remove_last(other->child_sas,
		   								 (void**)&child_sa) == SUCCESS)
	{
		this->child_sas->insert_first(this->child_sas, (void*)child_sa);
	}
}

/**
 * Implementation of ike_sa_t.log_status.
 */
static void log_status(private_ike_sa_t *this, logger_t *logger, char *name)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	bool contains_child = FALSE;
	
	/* check for a CHILD_SA with specified name. We then print the IKE_SA,
	 * even it has another name */
	if (name != NULL)
	{
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			if (streq(name, child_sa->get_name(child_sa)))
			{
				contains_child = TRUE;
				break;
			}
		}
		iterator->destroy(iterator);
	}
	
	if (name == NULL || contains_child || streq(name, this->name))
	{
		if (logger == NULL)
		{
			logger = this->logger;
		}		
		logger->log(logger, CONTROL|LEVEL1,
					"  \"%s\": IKE_SA in state %s, SPIs: 0x%.16llx 0x%.16llx",
					this->name,
					mapping_find(ike_sa_state_m, this->state),
					this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					this->ike_sa_id->get_responder_spi(this->ike_sa_id));
		logger->log(logger, CONTROL, "  \"%s\": %s[%s]...%s[%s]",
					this->name,
					this->my_host->get_string(this->my_host),
					this->my_id->get_string(this->my_id),
					this->other_host->get_string(this->other_host),
					this->other_id->get_string(this->other_id));
		
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&child_sa);
			child_sa->log_status(child_sa, logger);
		}
		iterator->destroy(iterator);
	}
}

/**
 * Implementation of public_ike_sa_t.delete.
 */
static status_t delete_(private_ike_sa_t *this)
{
	switch (this->state)
	{
		case IKE_CONNECTING:
		case IKE_ESTABLISHED:
		{
			delete_ike_sa_t *delete_ike_sa;
			if (this->transaction_out)
			{
				/* already a transaction in progress. As this may hang
				* around a while, we don't inform the other peer. */
				return DESTROY_ME;
			}
			delete_ike_sa = delete_ike_sa_create(&this->public);
			return queue_transaction(this, (transaction_t*)delete_ike_sa, FALSE);
		}
		case IKE_CREATED:
		case IKE_DELETING:
		default:
		{
			return DESTROY_ME;
		}
	}
}

/**
 * Implementation of ike_sa_t.get_next_message_id.
 */
static u_int32_t get_next_message_id (private_ike_sa_t *this)
{
	return this->message_id_out++;
}

/**
 * Implementation of ike_sa_t.is_natt_enabled.
 */
static bool is_natt_enabled (private_ike_sa_t *this)
{
	return this->nat_here || this->nat_there;
}

/**
 * Implementation of ike_sa_t.enable_natt.
 */
static void enable_natt (private_ike_sa_t *this, bool local)
{
	if (local)
	{
		this->logger->log(this->logger, CONTROL,
						  "local host is behind NAT, using NAT-T, scheduled keep alives");
		this->nat_here = TRUE;
		send_keepalive(this);
	}
	else
	{
		this->logger->log(this->logger, CONTROL, 
						  "remote host is behind NAT, using NAT-T");
		this->nat_there = TRUE;
	}
}

/**
 * Implementation of ike_sa_t.destroy.
 */
static void destroy(private_ike_sa_t *this)
{
	child_sa_t *child_sa;
	transaction_t *transaction;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "going to destroy IKE SA %llu:%llu, role %s", 
					  this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					  this->ike_sa_id->get_responder_spi(this->ike_sa_id),
					  this->ike_sa_id->is_initiator(this->ike_sa_id) ? "initiator" : "responder");
	
	if (this->state == IKE_ESTABLISHED)
	{
		this->logger->log(this->logger, ERROR, 
						  "destroying an established IKE SA without knowledge from remote peer!");
	}

	while (this->child_sas->remove_last(this->child_sas, (void**)&child_sa) == SUCCESS)
	{
		child_sa->destroy(child_sa);
	}
	this->child_sas->destroy(this->child_sas);
	
	while (this->transaction_queue->remove_last(this->transaction_queue, (void**)&transaction) == SUCCESS)
	{
		transaction->destroy(transaction);
	}
	this->transaction_queue->destroy(this->transaction_queue);
	
	DESTROY_IF(this->transaction_in);
	DESTROY_IF(this->transaction_in_next);
	DESTROY_IF(this->transaction_out);
	DESTROY_IF(this->crypter_in);
	DESTROY_IF(this->crypter_out);
	DESTROY_IF(this->signer_in);
	DESTROY_IF(this->signer_out);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->child_prf);
	DESTROY_IF(this->prf_auth_i);
	DESTROY_IF(this->prf_auth_r);

	this->logger->log(this->logger, AUDIT, 
					  "IKE_SA deleted between %s[%s]...%s[%s]",
					  this->my_host->get_string(this->my_host),
					  this->my_id->get_string(this->my_id),
					  this->other_host->get_string(this->other_host),
					  this->other_id->get_string(this->other_id));
	
	DESTROY_IF(this->my_host);
	DESTROY_IF(this->other_host);
	DESTROY_IF(this->my_id);
	DESTROY_IF(this->other_id);
	
	free(this->name);
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
}

/*
 * Described in header.
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = malloc_thing(private_ike_sa_t);
	
	/* Public functions */
	this->public.get_state = (ike_sa_state_t(*)(ike_sa_t*)) get_state;
	this->public.set_state = (void(*)(ike_sa_t*,ike_sa_state_t)) set_state;
	this->public.get_name = (char*(*)(ike_sa_t*))get_name;
	this->public.set_name = (void(*)(ike_sa_t*,char*))set_name;
	this->public.process_message = (status_t(*)(ike_sa_t*, message_t*)) process_message;
	this->public.initiate = (status_t(*)(ike_sa_t*,connection_t*,policy_t*)) initiate;
	this->public.route = (status_t(*)(ike_sa_t*,connection_t*,policy_t*)) route;
	this->public.unroute = (status_t(*)(ike_sa_t*,policy_t*)) unroute;
	this->public.acquire = (status_t(*)(ike_sa_t*,u_int32_t)) acquire;
	this->public.get_id = (ike_sa_id_t*(*)(ike_sa_t*)) get_id;
	this->public.get_my_host = (host_t*(*)(ike_sa_t*)) get_my_host;
	this->public.set_my_host = (void(*)(ike_sa_t*,host_t*)) set_my_host;
	this->public.get_other_host = (host_t*(*)(ike_sa_t*)) get_other_host;
	this->public.set_other_host = (void(*)(ike_sa_t*,host_t*)) set_other_host;
	this->public.get_my_id = (identification_t*(*)(ike_sa_t*)) get_my_id;
	this->public.set_my_id = (void(*)(ike_sa_t*,identification_t*)) set_my_id;
	this->public.get_other_id = (identification_t*(*)(ike_sa_t*)) get_other_id;
	this->public.set_other_id = (void(*)(ike_sa_t*,identification_t*)) set_other_id;
	this->public.get_next_message_id = (u_int32_t(*)(ike_sa_t*)) get_next_message_id;
	this->public.retransmit_request = (status_t (*) (ike_sa_t *, u_int32_t)) retransmit_request;
	this->public.log_status = (void (*) (ike_sa_t*,logger_t*,char*))log_status;
	this->public.delete = (status_t(*)(ike_sa_t*))delete_;
	this->public.destroy = (void(*)(ike_sa_t*))destroy;
	this->public.send_dpd = (status_t (*)(ike_sa_t*)) send_dpd;
	this->public.send_keepalive = (void (*)(ike_sa_t*)) send_keepalive;
	this->public.get_prf = (prf_t *(*) (ike_sa_t *)) get_prf;
	this->public.get_child_prf = (prf_t *(*) (ike_sa_t *)) get_child_prf;
	this->public.get_prf_auth_i = (prf_t *(*) (ike_sa_t *)) get_prf_auth_i;
	this->public.get_prf_auth_r = (prf_t *(*) (ike_sa_t *)) get_prf_auth_r;
	this->public.derive_keys = (status_t (*) (ike_sa_t *,proposal_t*,diffie_hellman_t*,chunk_t,chunk_t,bool,prf_t*,prf_t*)) derive_keys;
	this->public.add_child_sa = (void (*) (ike_sa_t*,child_sa_t*)) add_child_sa;
	this->public.has_child_sa = (bool(*)(ike_sa_t*,u_int32_t)) has_child_sa;
	this->public.get_child_sa = (child_sa_t* (*)(ike_sa_t*,protocol_id_t,u_int32_t,bool)) get_child_sa;
	this->public.create_child_sa_iterator = (iterator_t* (*)(ike_sa_t*)) create_child_sa_iterator;
	this->public.rekey_child_sa = (status_t(*)(ike_sa_t*,protocol_id_t,u_int32_t)) rekey_child_sa;
	this->public.delete_child_sa = (status_t(*)(ike_sa_t*,protocol_id_t,u_int32_t)) delete_child_sa;
	this->public.destroy_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t))destroy_child_sa;
	this->public.enable_natt = (void(*)(ike_sa_t*, bool)) enable_natt;
	this->public.is_natt_enabled = (bool(*)(ike_sa_t*)) is_natt_enabled;
	this->public.set_lifetimes = (void(*)(ike_sa_t*,u_int32_t,u_int32_t))set_lifetimes;
	this->public.apply_connection = (void(*)(ike_sa_t*,connection_t*))apply_connection;
	this->public.rekey = (status_t(*)(ike_sa_t*))rekey;
	this->public.get_rekeying_transaction = (void*(*)(ike_sa_t*))get_rekeying_transaction;
	this->public.set_rekeying_transaction = (void(*)(ike_sa_t*,void*))set_rekeying_transaction;
	this->public.adopt_children = (void(*)(ike_sa_t*,ike_sa_t*))adopt_children;
	
	/* initialize private fields */
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->name = strdup("(uninitialized)");
	this->child_sas = linked_list_create();
	this->my_host = host_create_from_string("0.0.0.0", 0);
	this->other_host = host_create_from_string("0.0.0.0", 0);
	this->my_id = identification_create_from_encoding(ID_ANY, CHUNK_INITIALIZER);
	this->other_id = identification_create_from_encoding(ID_ANY, CHUNK_INITIALIZER);
	this->crypter_in = NULL;
	this->crypter_out = NULL;
	this->signer_in = NULL;
	this->signer_out = NULL;
	this->prf = NULL;
	this->prf_auth_i = NULL;
	this->prf_auth_r = NULL;
 	this->child_prf = NULL;
	this->nat_here = FALSE;
	this->nat_there = FALSE;
	this->transaction_queue = linked_list_create();
	this->transaction_in = NULL;
	this->transaction_in_next = NULL;
	this->transaction_out = NULL;
	this->rekeying_transaction = NULL;
	this->state = IKE_CREATED;
	this->message_id_out = 0;
	/* set to NOW, as when we rekey an existing IKE_SA no message is exchanged */
	this->time.inbound = this->time.outbound = time(NULL);
	this->time.established = 0;
	this->time.rekey = 0;
	this->time.delete = 0;
	this->dpd_delay = 0;
	this->retrans_sequences = 0;
	
	return &this->public;
}
