/*
 * Copyright (C) 2008 Tobias Brunner
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
	
	/**
	 * Did we send a HTTP_CERT_LOOKUP_SUPPORTED Notify?
	 */
	bool http_cert_lookup_supported_sent;
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
		switch(payload->get_type(payload))
		{
			case CERTIFICATE_REQUEST:
			{
				certreq_payload_t *certreq = (certreq_payload_t*)payload;
				chunk_t keyid;
				enumerator_t *enumerator;
				
				this->ike_sa->set_condition(this->ike_sa, COND_CERTREQ_SEEN, TRUE);
				
				if (certreq->get_cert_type(certreq) != CERT_X509)
				{
					DBG1(DBG_IKE, "cert payload %N not supported - ignored",
						 certificate_type_names, certreq->get_cert_type(certreq));
					break;
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
				break;
			}
			case NOTIFY:
			{
				notify_payload_t *notify = (notify_payload_t*)payload;
				
				/* we only handle one type of notify here */
				if (notify->get_notify_type(notify) == HTTP_CERT_LOOKUP_SUPPORTED)
				{
					this->ike_sa->enable_extension(this->ike_sa, EXT_HASH_AND_URL);
				}
				break;
			}
			default:
				/* ignore other payloads here, these are handled elsewhere */
				break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * tries to extract a certificate from the cert payload or the credential
 * manager (based on the hash of a "Hash and URL" encoded cert).
 * Note: the returned certificate (if any) has to be destroyed
 */ 
static certificate_t *try_get_cert(cert_payload_t *cert_payload)
{
	certificate_t *cert = NULL;
	switch (cert_payload->get_cert_encoding(cert_payload))
	{
		case ENC_X509_SIGNATURE:
		{
			cert = cert_payload->get_cert(cert_payload);
			break;
		}
		case ENC_X509_HASH_AND_URL:
		{
			identification_t *id;
			chunk_t hash = cert_payload->get_hash(cert_payload);
			if (!hash.ptr)
			{
				/* invalid "Hash and URL" data (logged elsewhere) */
				break;
			}
			id = identification_create_from_encoding(ID_CERT_DER_SHA1, hash);
			cert = charon->credentials->get_cert(charon->credentials, 
									CERT_X509, KEY_ANY, id, FALSE);
			id->destroy(id);
			break;
		}
		default:
		{
			break;
		}
	}
	return cert;
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
			cert_payload_t *cert_payload = (cert_payload_t*)payload;
			cert_encoding_t type = cert_payload->get_cert_encoding(cert_payload);
			switch (type)
			{
				case ENC_X509_SIGNATURE:
				case ENC_X509_HASH_AND_URL:
				{
					if (type == ENC_X509_HASH_AND_URL &&
						!this->http_cert_lookup_supported_sent)
					{
						DBG1(DBG_IKE, "received hash-and-url encoded cert, but"
								" we don't accept them, ignore");
						break;
					}
					
					certificate_t *cert = try_get_cert(cert_payload);
					
					if (cert)
					{
						/* we've got a certificate from the payload or the cache */ 
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
						cert->destroy(cert);
					}
					else if (type == ENC_X509_HASH_AND_URL)
					{
						/* we received a "Hash and URL" encoded certificate that
						 * we haven't fetched yet, we store the URL and fetch
						 * it later */
						char *url = cert_payload->get_url(cert_payload);
						if (!url)
						{
							DBG1(DBG_IKE, "received invalid hash-and-url encoded"
									" cert, ignore");
							break;
						}
						
						if (first)
						{	/* the first certificate MUST be an end entity one */
							DBG1(DBG_IKE, "received hash-and-url for end"
									" entity cert \"%s\"", url);
							auth->add_item(auth, AUTHN_SUBJECT_HASH_URL, url);
							first = FALSE;
						}
						else
						{
							DBG1(DBG_IKE, "received hash-and-url for issuer"
									" cert \"%s\"", url);
							auth->add_item(auth, AUTHN_IM_HASH_URL, url);
						}
					}
					break;
				}
				case ENC_PKCS7_WRAPPED_X509:
				case ENC_PGP:
				case ENC_DNS_SIGNED_KEY:
				case ENC_KERBEROS_TOKEN:
				case ENC_CRL:
				case ENC_ARL:
				case ENC_SPKI:
				case ENC_X509_ATTRIBUTE:
				case ENC_RAW_RSA_KEY:
				case ENC_X509_HASH_AND_URL_BUNDLE:
				case ENC_OCSP_CONTENT:
				default:
					DBG1(DBG_ENC, "certificate encoding %N not supported",
						 cert_encoding_names, cert_payload->get_cert_encoding(cert_payload));
			}
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
	peer_cfg_t *peer_cfg;
	enumerator_t *enumerator;
	certificate_t *cert;
	bool restricted = FALSE;
	certreq_payload_t *x509_req = NULL;
	
	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
	if (!ike_cfg->send_certreq(ike_cfg))
	{
		return;
	}

	/* check if we require a specific CA for that peer */
	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (peer_cfg)
	{
		void *ptr;
		identification_t *id;
		auth_item_t item;
		auth_info_t *auth = peer_cfg->get_auth(peer_cfg);
		enumerator_t *auth_enumerator = auth->create_item_enumerator(auth);

		while (auth_enumerator->enumerate(auth_enumerator, &item, &ptr))
		{
			switch (item)
			{
				case AUTHZ_CA_CERT:
					cert = (certificate_t *)ptr;
					add_certreq_payload(message, &x509_req, cert);
					restricted = TRUE;
					break;
				case AUTHZ_CA_CERT_NAME:
					id = (identification_t *)ptr;
					enumerator = charon->credentials->create_cert_enumerator(
							charon->credentials, CERT_ANY, KEY_ANY, id, TRUE);
					while (enumerator->enumerate(enumerator, &cert, TRUE))
					{
						add_certreq_payload(message, &x509_req, cert);
						restricted = TRUE;
					}
					enumerator->destroy(enumerator);
					break;
				default:
					break;
			}
		}
		auth_enumerator->destroy(auth_enumerator);
	}
		
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
	
	/* if we've added at least one certreq, we notify our peer that we support
	 * "Hash and URL" for the requested certificates */
	if (lib->settings->get_bool(lib->settings, "charon.hash_and_url", FALSE) &&
		message->get_payload(message, CERTIFICATE_REQUEST))
	{
		message->add_notify(message, FALSE, HTTP_CERT_LOOKUP_SUPPORTED, chunk_empty);
		this->http_cert_lookup_supported_sent = TRUE;
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
	this->http_cert_lookup_supported_sent = FALSE;
	
	return &this->public;
}
