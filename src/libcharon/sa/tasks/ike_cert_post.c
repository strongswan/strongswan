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
#include <encoding/payloads/sa_payload.h>
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

	/**
	 * Certificate payload type that we are handling
	 */
	payload_type_t payload_type;

	/**
	 * States of ike cert pre
	 */
	enum {
		CP_INIT,
		CP_SA,
		CP_SA_POST,
	} state;
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
	cert_payload_t *payload = NULL;

	if (!this->ike_sa->supports_extension(this->ike_sa, EXT_HASH_AND_URL))
	{
		return cert_payload_create_from_cert(cert, this->payload_type);
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1(DBG_IKE, "unable to use hash-and-url: sha1 not supported");
		return cert_payload_create_from_cert(cert, this->payload_type);
	}

	if (!cert->get_encoding(cert, CERT_ASN1_DER, &encoded))
	{
		DBG1(DBG_IKE, "encoding certificate for cert payload failed");
		hasher->destroy(hasher);
		return NULL;
	}
	hasher->allocate_hash(hasher, encoded, &hash);
	chunk_free(&encoded);
	hasher->destroy(hasher);
	id = identification_create_from_encoding(ID_KEY_ID, hash);

	enumerator = lib->credmgr->create_cdp_enumerator(lib->credmgr, CERT_X509, id);
	if (enumerator->enumerate(enumerator, &url))
	{
		payload = cert_payload_create_from_hash_and_url(hash, url, this->payload_type);
		DBG1(DBG_IKE, "sending hash-and-url \"%s\"", url);
	}
	else
	{
		payload = cert_payload_create_from_cert(cert, this->payload_type);
	}
	enumerator->destroy(enumerator);
	chunk_free(&hash);
	id->destroy(id);
	return payload;
}

/**
 * Checks for the auth_method to see if this task should handle certificates.
 * (IKEv1 only)
 */
static status_t check_auth_method(private_ike_cert_post_t *this,
																	message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	status_t status = SUCCESS;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == SECURITY_ASSOCIATION_V1)
		{
			sa_payload_t *sa_payload = (sa_payload_t*)payload;

			switch (sa_payload->get_auth_method(sa_payload))
			{
				case 	AUTH_RSA:
				case 	AUTH_XAUTH_INIT_RSA:
				case  AUTH_XAUTH_RESP_RSA:
					DBG3(DBG_IKE, "handling certs method (%d)",
								sa_payload->get_auth_method(sa_payload));
					status = NEED_MORE;
					break;
				default:
					DBG3(DBG_IKE, "not handling certs method (%d)",
								sa_payload->get_auth_method(sa_payload));
					status = SUCCESS;
					break;
			}

			this->state = CP_SA;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return status;
}

/**
 * add certificates to message
 */
static void build_certs(private_ike_cert_post_t *this, message_t *message)
{
	peer_cfg_t *peer_cfg;

	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);

	if (!peer_cfg)
	{
		return;
	}

	if (this->payload_type == CERTIFICATE)
	{
		auth_payload_t *payload;
		payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);

		if (!payload || payload->get_auth_method(payload) == AUTH_PSK)
		{	/* no CERT payload for EAP/PSK */
			return;
		}
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
					payload = cert_payload_create_from_cert(cert, this->payload_type);
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

	return;
}

METHOD(task_t, build_i, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	build_certs(this, message);

	return NEED_MORE;
}

METHOD(task_t, build_i_v1, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	/* TODO:*/

	return FAILED;
}

METHOD(task_t, process_r, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	build_certs(this, message);

	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{	/* stay alive, we might have additional rounds with certs */
		return NEED_MORE;
	}
	return SUCCESS;
}

METHOD(task_t, build_r_v1, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	switch (message->get_exchange_type(message))
	{
		case ID_PROT:
		{
			switch (this->state)
			{
				case CP_INIT:
					this->state = CP_SA;
					return check_auth_method(this, message);
					break;

				case CP_SA:
					this->state = CP_SA_POST;
					build_certs(this, message);
					break;

				case CP_SA_POST:
					build_certs(this, message);
					return SUCCESS;
			}
			break;
		}
		case AGGRESSIVE:
		{
			if (check_auth_method(this, message) == NEED_MORE)
			{
				build_certs(this, message);
			}
			return SUCCESS;
			break;
		}
		default:
			break;
	}

	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{
		return NEED_MORE;
	}

	return SUCCESS;
}

METHOD(task_t, process_i, status_t,
	private_ike_cert_post_t *this, message_t *message)
{
	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{	/* stay alive, we might have additional rounds with CERTS */
		return NEED_MORE;
	}
	return SUCCESS;
}

METHOD(task_t, get_type, task_type_t,
	private_ike_cert_post_t *this)
{
	return TASK_IKE_CERT_POST;
}

METHOD(task_t, migrate, void,
	private_ike_cert_post_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, destroy, void,
	private_ike_cert_post_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_cert_post_t *ike_cert_post_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_cert_post_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.initiator = initiator,
	);


	if (initiator)
	{
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.process = _process_r;
	}

	if (ike_sa->get_version(ike_sa) == IKEV2)
	{
		this->payload_type = CERTIFICATE;

		if (initiator)
		{
			this->public.task.build = _build_i;
		}
		else
		{
			this->public.task.build = _build_r;
		}
	}
	else
	{
		this->payload_type = CERTIFICATE_V1;

		if (initiator)
		{
			this->public.task.build = _build_i_v1;
		}
		else
		{
			this->public.task.build = _build_r_v1;
		}
	}

	return &this->public;
}

