/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2006-2009 Martin Willi
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

#include "ike_cert_post.h"

#include <daemon.h>
#include <sa/ike_sa.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <credentials/certificates/x509.h>


typedef struct private_ike_cert_post_t private_ike_cert_post_t;

/**
 * Private members of a ike_cert_post_t task.
 */
struct private_ike_cert_post_t {

	/**
	 * Public methods and task_t interface.
	 */
	ike_cert_post_t public;

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
 * Generates the cert payload, if possible with "Hash and URL"
 */
static cert_payload_t *build_cert_payload(private_ike_cert_post_t *this,
										 certificate_t *cert)
{
	hasher_t *hasher;
	identification_t *id;
	chunk_t hash, encoded ;
	enumerator_t *enumerator;
	char *url;

	if (!this->ike_sa->supports_extension(this->ike_sa, EXT_HASH_AND_URL))
	{
		return cert_payload_create_from_cert(cert);
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1(DBG_IKE, "unable to use hash-and-url: sha1 not supported");
		return cert_payload_create_from_cert(cert);
	}

	encoded = cert->get_encoding(cert);
	hasher->allocate_hash(hasher, encoded, &hash);
	id = identification_create_from_encoding(ID_KEY_ID, hash);

	enumerator = charon->credentials->create_cdp_enumerator(
										charon->credentials, CERT_X509, id);
	if (!enumerator->enumerate(enumerator, &url))
	{
		url = NULL;
	}
	enumerator->destroy(enumerator);

	id->destroy(id);
	chunk_free(&hash);
	chunk_free(&encoded);
	hasher->destroy(hasher);
	if (url)
	{
		return cert_payload_create_from_hash_and_url(hash, url);
	}
	return cert_payload_create_from_cert(cert);
}

/**
 * add certificates to message
 */
static void build_certs(private_ike_cert_post_t *this, message_t *message)
{
	peer_cfg_t *peer_cfg;
	auth_payload_t *payload;

	payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (!peer_cfg || !payload || payload->get_auth_method(payload) == AUTH_PSK)
	{	/* no CERT payload for EAP/PSK */
		return;
	}

	switch (peer_cfg->get_cert_policy(peer_cfg))
	{
		case CERT_NEVER_SEND:
			break;
		case CERT_SEND_IF_ASKED:
			if (!this->ike_sa->has_condition(this->ike_sa, COND_CERTREQ_SEEN))
			{
				break;
			}
			/* FALL */
		case CERT_ALWAYS_SEND:
		{
			cert_payload_t *payload;
			enumerator_t *enumerator;
			certificate_t *cert;
			auth_rule_t type;
			auth_cfg_t *auth;

			auth = this->ike_sa->get_auth_cfg(this->ike_sa, TRUE);

			/* get subject cert first, then issuing certificates */
			cert = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
			if (!cert)
			{
				break;
			}
			payload = build_cert_payload(this, cert);
			if (!payload)
			{
				break;
			}
			DBG1(DBG_IKE, "sending end entity cert \"%Y\"",
				 cert->get_subject(cert));
			message->add_payload(message, (payload_t*)payload);

			enumerator = auth->create_enumerator(auth);
			while (enumerator->enumerate(enumerator, &type, &cert))
			{
				if (type == AUTH_RULE_IM_CERT)
				{
					payload = cert_payload_create_from_cert(cert);
					if (payload)
					{
						DBG1(DBG_IKE, "sending issuer cert \"%Y\"",
							 cert->get_subject(cert));
						message->add_payload(message, (payload_t*)payload);
					}
				}
			}
			enumerator->destroy(enumerator);
		}
	}
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_cert_post_t *this, message_t *message)
{
	build_certs(this, message);

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_cert_post_t *this, message_t *message)
{
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_cert_post_t *this, message_t *message)
{
	build_certs(this, message);

	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{	/* stay alive, we might have additional rounds with certs */
		return NEED_MORE;
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_cert_post_t *this, message_t *message)
{
	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{	/* stay alive, we might have additional rounds with CERTS */
		return NEED_MORE;
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_cert_post_t *this)
{
	return IKE_CERT_POST;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_cert_post_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_cert_post_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_cert_post_t *ike_cert_post_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_cert_post_t *this = malloc_thing(private_ike_cert_post_t);

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

