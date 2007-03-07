/**
 * @file ike_cert.c
 *
 * @brief Implementation of the ike_cert task.
 *
 */

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

#include "ike_cert.h"

#include <daemon.h>
#include <sa/ike_sa.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>


typedef struct private_ike_cert_t private_ike_cert_t;

/**
 * Private members of a ike_cert_t task.
 */
struct private_ike_cert_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_cert_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * list of CA cert hashes requested, items point to 20 byte chunk
	 */
	linked_list_t *cas;
};

/**
 * read certificate requests 
 */
static void process_certreqs(private_ike_cert_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == CERTIFICATE_REQUEST)
		{
			certreq_payload_t *certreq = (certreq_payload_t*)payload;
			cert_encoding_t encoding;
			chunk_t keyids, keyid;
			
			encoding =  certreq->get_cert_encoding(certreq);
			if (encoding != CERT_X509_SIGNATURE)
			{
				DBG1(DBG_IKE, "certreq payload %N not supported, ignored",
					 cert_encoding_names, encoding);
				continue;
			}

			keyids = certreq->get_data(certreq);
					
			while (keyids.len >= HASH_SIZE_SHA1)
			{
				keyid = chunk_create(keyids.ptr, HASH_SIZE_SHA1);
				keyid = chunk_clone(keyid);
				this->cas->insert_last(this->cas, keyid.ptr);
				keyids = chunk_skip(keyids, HASH_SIZE_SHA1);
			}
		}
	}
	iterator->destroy(iterator);
}

/**
 * import certificates
 */
static void process_certs(private_ike_cert_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == CERTIFICATE)
		{
			cert_encoding_t encoding;
			x509_t *cert;
			chunk_t cert_data;
			bool found;
			cert_payload_t *cert_payload = (cert_payload_t*)payload;
			
			encoding = cert_payload->get_cert_encoding(cert_payload);
			if (encoding != CERT_X509_SIGNATURE)
			{
				DBG1(DBG_IKE, "certificate payload %N not supported, ignored",
					 cert_encoding_names, encoding);
				continue;
			}
			
			cert_data = cert_payload->get_data_clone(cert_payload);
			cert = x509_create_from_chunk(cert_data, 0);
			if (cert)
			{
				if (charon->credentials->verify(charon->credentials,
												cert, &found))
				{
					DBG2(DBG_IKE, "received end entity certificate is trusted, "
						 "added to store");
					if (!found)
					{
						charon->credentials->add_end_certificate(
													charon->credentials, cert);
					}
					else
					{
						cert->destroy(cert);
					}
				}
				else
				{
					DBG1(DBG_IKE, "received end entity certificate is not "
						 "trusted, discarded");
					cert->destroy(cert);
				}
			}
			else
			{
				DBG1(DBG_IKE, "parsing of received certificate failed, discarded");
				chunk_free(&cert_data);
			}
		}
	}
	iterator->destroy(iterator);
}

/**
 * build certificate requests
 */
static void build_certreqs(private_ike_cert_t *this, message_t *message)
{
	connection_t *connection;
	policy_t *policy;
	identification_t *ca;
	certreq_payload_t *certreq;
	
	connection = this->ike_sa->get_connection(this->ike_sa);
	
	if (connection->get_certreq_policy(connection) != CERT_NEVER_SEND)
	{	
		policy = this->ike_sa->get_policy(this->ike_sa);
		
		if (policy)
		{
			ca = policy->get_other_ca(policy);
			
			if (ca && ca->get_type(ca) != ID_ANY)
			{
				certreq = certreq_payload_create_from_cacert(ca);
			}
			else
			{
				certreq = certreq_payload_create_from_cacerts();
			}
		}
		else
		{
			certreq = certreq_payload_create_from_cacerts();
		}
		
		if (certreq)
		{
			message->add_payload(message, (payload_t*)certreq);
		}
	}
}

/**
 * add certificates to message
 */
static void build_certs(private_ike_cert_t *this, message_t *message)
{
	policy_t *policy;
	connection_t *connection;
	x509_t *cert;
	cert_payload_t *payload;
	
	policy = this->ike_sa->get_policy(this->ike_sa);
	connection = this->ike_sa->get_connection(this->ike_sa);

	if (policy && policy->get_auth_method(policy) == AUTH_RSA)
	{
		switch (connection->get_cert_policy(connection))
		{
			case CERT_NEVER_SEND:
				break;
			case CERT_SEND_IF_ASKED:
				if (this->cas->get_count(this->cas) == 0)
				{
					break;
				}
				/* FALL */
			case CERT_ALWAYS_SEND:
			{
				/* TODO: respect CA cert request */
				cert = charon->credentials->get_certificate(charon->credentials,
													policy->get_my_id(policy));
				if (cert)
				{
					payload = cert_payload_create_from_x509(cert);
					message->add_payload(message, (payload_t*)payload);
				}
			}	
		}
	}
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_cert_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return NEED_MORE;
	}
		
	build_certreqs(this, message);
	build_certs(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_cert_t *this, message_t *message)
{	
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return NEED_MORE;
	}
	
	process_certreqs(this, message);
	process_certs(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_cert_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		build_certreqs(this, message);
		return NEED_MORE;
	}
	
	build_certs(this, message);
	
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_cert_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		process_certreqs(this, message);
		return NEED_MORE;
	}
	
	process_certs(this, message);
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_cert_t *this)
{
	return IKE_CERT;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_cert_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	
	this->cas->destroy_function(this->cas, free);
	this->cas = linked_list_create();
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_cert_t *this)
{
	this->cas->destroy_function(this->cas, free);
	free(this);
}

/*
 * Described in header.
 */
ike_cert_t *ike_cert_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_cert_t *this = malloc_thing(private_ike_cert_t);

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
	this->cas = linked_list_create();
	
	return &this->public;
}
