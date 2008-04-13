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
 *
 * $Id$
 */

#include "ike_cert_pre.h"

#include <daemon.h>
#include <sa/ike_sa.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <credentials/certificates/x509.h>


typedef struct private_ike_cert_pre_t private_ike_cert_pre_t;

/**
 * Private members of a ike_cert_pre_t task.
 */
struct private_ike_cert_pre_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_cert_pre_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
};

/**
 * read certificate requests 
 */
static void process_certreqs(private_ike_cert_pre_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	auth_info_t *auth;
	bool ca_found = FALSE;
	
	auth = this->ike_sa->get_my_auth(this->ike_sa);
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == CERTIFICATE_REQUEST)
		{
			certreq_payload_t *certreq = (certreq_payload_t*)payload;
			chunk_t keyid;
			enumerator_t *enumerator;
			
			this->ike_sa->set_condition(this->ike_sa, COND_CERTREQ_SEEN, TRUE);
			
			if (certreq->get_cert_type(certreq) != CERT_X509)
			{
				DBG1(DBG_IKE, "cert payload %N not supported - ignored",
					 certificate_type_names, certreq->get_cert_type(certreq));
				continue;
			}
			enumerator = certreq->create_keyid_enumerator(certreq);
			while (enumerator->enumerate(enumerator, &keyid))
			{
				identification_t *id;
				certificate_t *cert;
				
				id = identification_create_from_encoding(
										ID_PUBKEY_INFO_SHA1, keyid);
				cert = charon->credentials->get_cert(charon->credentials, 
										CERT_X509, KEY_ANY, id, TRUE);
				if (cert)
				{
					DBG1(DBG_IKE, "received cert request for \"%D\"",
						 cert->get_subject(cert));
					auth->add_item(auth, AUTHN_CA_CERT, cert);
					cert->destroy(cert);
					ca_found = TRUE;
				}
				else
				{
					DBG1(DBG_IKE, "received cert request for unknown ca "
								  "with keyid %D", id);
					auth->add_item(auth, AUTHN_CA_CERT_KEYID, id);
				}
				id->destroy(id);
			}
			enumerator->destroy(enumerator);
		}
	}
	iterator->destroy(iterator);
}

/**
 * import certificates
 */
static void process_certs(private_ike_cert_pre_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	auth_info_t *auth;
	bool first = TRUE;
	
	auth = this->ike_sa->get_other_auth(this->ike_sa);
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == CERTIFICATE)
		{
			certificate_t *cert;
			cert_payload_t *cert_payload = (cert_payload_t*)payload;
			
			cert = cert_payload->get_cert(cert_payload);
			if (cert)
			{
				if (first)
				{	/* the first certificate MUST be an end entity one */
				
					DBG1(DBG_IKE, "received end entity cert \"%D\"",
						 cert->get_subject(cert));
					auth->add_item(auth, AUTHN_SUBJECT_CERT, cert);
					first = FALSE;
				}
				else
				{
					DBG1(DBG_IKE, "received issuer cert \"%D\"",
						 cert->get_subject(cert));
					auth->add_item(auth, AUTHN_IM_CERT, cert);
				}
			}
			cert->destroy(cert);
		}
	}
	iterator->destroy(iterator);
}

/**
 * add a certificate request to the message, building request payload if required.
 */
static void add_certreq_payload(message_t *message, certreq_payload_t **reqp, 
								certificate_t *cert)
{
	public_key_t *public;
	certreq_payload_t *req;

	public = cert->get_public_key(cert);
	if (!public)
	{
		return;
	}
	switch (cert->get_type(cert))
	{
		case CERT_X509:
		{
			identification_t *keyid;
			x509_t *x509 = (x509_t*)cert;
			
			if (!(x509->get_flags(x509) & X509_CA))
			{	/* no CA cert, skip */
				break;
			}
			if (*reqp == NULL)
			{
				*reqp = certreq_payload_create_type(CERT_X509);
				message->add_payload(message, (payload_t*)*reqp);
			}
			req = *reqp;
			keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
			req->add_keyid(req, keyid->get_encoding(keyid));
			DBG1(DBG_IKE, "sending cert request for \"%D\"",
				 cert->get_subject(cert));
			break;
		}
		default:
			break;
	}
	public->destroy(public);
}

/**
 * build certificate requests
 */
static void build_certreqs(private_ike_cert_pre_t *this, message_t *message)
{
	ike_cfg_t *ike_cfg;
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_info_t *auth;
	bool restricted = FALSE;
	auth_item_t item;
	certreq_payload_t *x509_req = NULL;
	
	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
	if (!ike_cfg->send_certreq(ike_cfg))
	{
		return;
	}
	auth = this->ike_sa->get_other_auth(this->ike_sa);

	/* check if we require a specific CA for that peer */
	enumerator = auth->create_item_enumerator(auth);
	while (enumerator->enumerate(enumerator, &item, &cert))
	{
		if (item == AUTHN_CA_CERT)
		{
			restricted = TRUE;
			add_certreq_payload(message, &x509_req, cert);
		}
	}
	enumerator->destroy(enumerator);
		
	if (!restricted)
	{
		/* otherwise include all trusted CA certificates */
		enumerator = charon->credentials->create_cert_enumerator(
							charon->credentials, CERT_ANY, KEY_ANY, NULL, TRUE);
		while (enumerator->enumerate(enumerator, &cert, TRUE))
		{
			add_certreq_payload(message, &x509_req, cert);
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_cert_pre_t *this, message_t *message)
{	
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return NEED_MORE;
	}
	build_certreqs(this, message);
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_cert_pre_t *this, message_t *message)
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
static status_t build_r(private_ike_cert_pre_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		build_certreqs(this, message);
		return NEED_MORE;
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_cert_pre_t *this, message_t *message)
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
static task_type_t get_type(private_ike_cert_pre_t *this)
{
	return IKE_CERT_PRE;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_cert_pre_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_cert_pre_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_cert_pre_t *ike_cert_pre_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_cert_pre_t *this = malloc_thing(private_ike_cert_pre_t);

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
	
	return &this->public;
}
