/*
 * Copyright (C) 2011 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "main_mode.h"

#include <string.h>

#include <daemon.h>
#include <sa/keymat_v1.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/hash_payload.h>
#include <processing/jobs/initiate_xauth_job.h>

typedef struct private_main_mode_t private_main_mode_t;

/**
 * Private members of a main_mode_t task.
 */
struct private_main_mode_t {

	/**
	 * Public methods and task_t interface.
	 */
	main_mode_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * IKE config to establish
	 */
	ike_cfg_t *ike_cfg;

	/**
	 * Peer config to use
	 */
	peer_cfg_t *peer_cfg;

	/**
	 * Local authentication configuration
	 */
	auth_cfg_t *my_auth;

	/**
	 * Remote authentication configuration
	 */
	auth_cfg_t *other_auth;

	/**
	 * selected IKE proposal
	 */
	proposal_t *proposal;

	/**
	 * DH exchange
	 */
	diffie_hellman_t *dh;

	/**
	 * Keymat derivation (from SA)
	 */
	keymat_v1_t *keymat;

	/**
	 * Received public DH value from peer
	 */
	chunk_t dh_value;

	/**
	 * Initiators nonce
	 */
	chunk_t nonce_i;

	/**
	 * Responder nonce
	 */
	chunk_t nonce_r;

	/**
	 * Encoded SA initiator payload used for authentication
	 */
	chunk_t sa_payload;

	/**
	 * Negotiated SA lifetime
	 */
	u_int32_t lifetime;

	/**
	 * Negotiated authentication method
	 */
	auth_method_t auth_method;

	/** states of main mode */
	enum {
		MM_INIT,
		MM_SA,
		MM_KE,
		MM_AUTH,
	} state;
};

/**
 * Get the first authentcation config from peer config
 */
static auth_cfg_t *get_auth_cfg(private_main_mode_t *this, bool local)
{
	enumerator_t *enumerator;
	auth_cfg_t *cfg = NULL;

	enumerator = this->peer_cfg->create_auth_cfg_enumerator(this->peer_cfg,
															local);
	enumerator->enumerate(enumerator, &cfg);
	enumerator->destroy(enumerator);
	return cfg;
}

/**
 * Save the encoded SA payload of a message
 */
static bool save_sa_payload(private_main_mode_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload, *sa = NULL;
	chunk_t data;
	size_t offset = IKE_HEADER_LENGTH;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == SECURITY_ASSOCIATION_V1)
		{
			sa = payload;
			break;
		}
		else
		{
			offset += payload->get_length(payload);
		}
	}
	enumerator->destroy(enumerator);

	data = message->get_packet_data(message);
	if (sa && data.len >= offset + sa->get_length(sa))
	{
		/* Get SA payload without 4 byte fixed header */
		data = chunk_skip(data, offset);
		data.len = sa->get_length(sa);
		data = chunk_skip(data, 4);
		this->sa_payload = chunk_clone(data);
		return TRUE;
	}
	return FALSE;
}

/**
 * Build main mode hash payloads
 */
static void build_hash(private_main_mode_t *this, bool initiator,
					   message_t *message, identification_t *id)
{
	hash_payload_t *hash_payload;
	chunk_t hash, dh;

	this->dh->get_my_public_value(this->dh, &dh);
	hash = this->keymat->get_hash(this->keymat, initiator, dh, this->dh_value,
					this->ike_sa->get_id(this->ike_sa), this->sa_payload, id);
	free(dh.ptr);

	hash_payload = hash_payload_create(HASH_V1);
	hash_payload->set_hash(hash_payload, hash);
	free(hash.ptr);

	message->add_payload(message, &hash_payload->payload_interface);
}

/**
 * Verify main mode hash payload
 */
static bool verify_hash(private_main_mode_t *this, bool initiator,
					   message_t *message, identification_t *id)
{
	hash_payload_t *hash_payload;
	chunk_t hash, dh;
	bool equal;

	hash_payload = (hash_payload_t*)message->get_payload(message,
														 HASH_V1);
	if (!hash_payload)
	{
		DBG1(DBG_IKE, "HASH payload missing in message");
		return FALSE;
	}
	hash = hash_payload->get_hash(hash_payload);
	this->dh->get_my_public_value(this->dh, &dh);
	hash = this->keymat->get_hash(this->keymat, initiator, this->dh_value, dh,
				this->ike_sa->get_id(this->ike_sa), this->sa_payload, id);
	free(dh.ptr);
	equal = chunk_equals(hash, hash_payload->get_hash(hash_payload));
	free(hash.ptr);
	if (!equal)
	{
		DBG1(DBG_IKE, "calculated HASH does not match HASH payload");
	}
	return equal;
}

/**
 * Generate and add NONCE, KE payload
 */
static bool add_nonce_ke(private_main_mode_t *this, chunk_t *nonce,
						 message_t *message)
{
	nonce_payload_t *nonce_payload;
	ke_payload_t *ke_payload;
	rng_t *rng;

	ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE_V1,
													   this->dh);
	message->add_payload(message, &ke_payload->payload_interface);

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "no RNG found to create nonce");
		return FALSE;
	}
	rng->allocate_bytes(rng, NONCE_SIZE, nonce);
	rng->destroy(rng);

	nonce_payload = nonce_payload_create(NONCE_V1);
	nonce_payload->set_nonce(nonce_payload, *nonce);
	message->add_payload(message, &nonce_payload->payload_interface);

	return TRUE;
}

/**
 * Extract nonce from NONCE payload, process KE payload
 */
static bool get_nonce_ke(private_main_mode_t *this, chunk_t *nonce,
						 message_t *message)
{
	nonce_payload_t *nonce_payload;
	ke_payload_t *ke_payload;

	ke_payload = (ke_payload_t*)message->get_payload(message, KEY_EXCHANGE_V1);
	if (!ke_payload)
	{
		DBG1(DBG_IKE, "KE payload missing in message");
		return FALSE;
	}
	this->dh_value = chunk_clone(ke_payload->get_key_exchange_data(ke_payload));
	this->dh->set_other_public_value(this->dh, this->dh_value);

	nonce_payload = (nonce_payload_t*)message->get_payload(message, NONCE_V1);
	if (!nonce_payload)
	{
		DBG1(DBG_IKE, "NONCE payload missing in message");
		return FALSE;
	}
	*nonce = nonce_payload->get_nonce(nonce_payload);

	return TRUE;
}

/**
 * Get auth method to use
 */
static auth_method_t get_auth_method(private_main_mode_t *this)
{
	switch ((uintptr_t)this->my_auth->get(this->my_auth, AUTH_RULE_AUTH_CLASS))
	{
		case AUTH_CLASS_PSK:
			return AUTH_PSK;
		case AUTH_CLASS_XAUTH_PSK:
			return AUTH_XAUTH_INIT_PSK;
		case AUTH_CLASS_XAUTH_PUBKEY:
			return AUTH_XAUTH_INIT_RSA;
		case AUTH_CLASS_PUBKEY:
			/* TODO-IKEv1: look for a key, return RSA or ECDSA */
		default:
			/* TODO-IKEv1: XAUTH methods */
			return AUTH_RSA;
	}
}

METHOD(task_t, build_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_INIT:
		{
			sa_payload_t *sa_payload;
			linked_list_t *proposals;
			packet_t *packet;

			this->ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
			DBG0(DBG_IKE, "initiating IKE_SA %s[%d] to %H",
				 this->ike_sa->get_name(this->ike_sa),
				 this->ike_sa->get_unique_id(this->ike_sa),
				 this->ike_sa->get_other_host(this->ike_sa));
			this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

			this->peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
			this->peer_cfg->get_ref(this->peer_cfg);

			this->my_auth = get_auth_cfg(this, TRUE);
			this->other_auth = get_auth_cfg(this, FALSE);
			if (!this->my_auth || !this->other_auth)
			{
				DBG1(DBG_CFG, "no auth config found");
				return FAILED;
			}

			proposals = this->ike_cfg->get_proposals(this->ike_cfg);
			this->auth_method = get_auth_method(this);
			this->lifetime = this->peer_cfg->get_reauth_time(this->peer_cfg,
															FALSE);
			if (!this->lifetime)
			{	/* fall back to rekey time of no rekey time configured */
				this->lifetime = this->peer_cfg->get_rekey_time(this->peer_cfg,
																 FALSE);
			}
			sa_payload = sa_payload_create_from_proposals_v1(proposals,
						this->lifetime, 0, this->auth_method, MODE_NONE, FALSE);
			proposals->destroy_offset(proposals, offsetof(proposal_t, destroy));

			message->add_payload(message, &sa_payload->payload_interface);

			/* pregenerate message to store SA payload */
			if (this->ike_sa->generate_message(this->ike_sa, message,
											   &packet) != SUCCESS)
			{
				DBG1(DBG_IKE, "pregenerating SA payload failed");
				return FAILED;
			}
			packet->destroy(packet);
			if (!save_sa_payload(this, message))
			{
				DBG1(DBG_IKE, "SA payload invalid");
				return FAILED;
			}

			this->state = MM_SA;
			return NEED_MORE;
		}
		case MM_SA:
		{
			u_int16_t group;

			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return FAILED;
			}
			this->dh = this->keymat->keymat.create_dh(&this->keymat->keymat,
													  group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return FAILED;
			}
			if (!add_nonce_ke(this, &this->nonce_i, message))
			{
				return FAILED;
			}
			this->state = MM_KE;
			return NEED_MORE;
		}
		case MM_KE:
		{
			id_payload_t *id_payload;
			identification_t *id;

			id = this->my_auth->get(this->my_auth, AUTH_RULE_IDENTITY);
			if (!id)
			{
				DBG1(DBG_CFG, "own identity not known");
				return FAILED;
			}

			this->ike_sa->set_my_id(this->ike_sa, id->clone(id));

			id_payload = id_payload_create_from_identification(ID_V1, id);
			message->add_payload(message, &id_payload->payload_interface);

			build_hash(this, TRUE, message, id);

			this->state = MM_AUTH;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_r, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_INIT:
		{
			linked_list_t *list;
			sa_payload_t *sa_payload;

			this->ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
			DBG0(DBG_IKE, "%H is initiating a Main Mode",
				 message->get_source(message));
			this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

			this->ike_sa->update_hosts(this->ike_sa,
									   message->get_destination(message),
									   message->get_source(message), TRUE);

			sa_payload = (sa_payload_t*)message->get_payload(message,
													SECURITY_ASSOCIATION_V1);
			if (!sa_payload || !save_sa_payload(this, message))
			{
				DBG1(DBG_IKE, "SA payload missing or invalid");
				return FAILED;
			}

			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return FAILED;
			}

			this->auth_method = sa_payload->get_auth_method(sa_payload);
			this->lifetime = sa_payload->get_lifetime(sa_payload);

			this->state = MM_SA;
			return NEED_MORE;
		}
		case MM_SA:
		{
			u_int16_t group;

			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return FAILED;
			}
			this->dh = lib->crypto->create_dh(lib->crypto, group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return FAILED;
			}
			if (!get_nonce_ke(this, &this->nonce_i, message))
			{
				return FAILED;
			}
			this->state = MM_KE;
			return NEED_MORE;
		}
		case MM_KE:
		{
			enumerator_t *enumerator;
			id_payload_t *id_payload;
			identification_t *id, *any;

			id_payload = (id_payload_t*)message->get_payload(message, ID_V1);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "IDii payload missing");
				return FAILED;
			}

			id = id_payload->get_identification(id_payload);
			any = identification_create_from_encoding(ID_ANY, chunk_empty);
			enumerator = charon->backends->create_peer_cfg_enumerator(
									charon->backends,
									this->ike_sa->get_my_host(this->ike_sa),
									this->ike_sa->get_other_host(this->ike_sa),
									any, id);
			if (!enumerator->enumerate(enumerator, &this->peer_cfg))
			{
				DBG1(DBG_IKE, "no peer config found");
				id->destroy(id);
				any->destroy(any);
				enumerator->destroy(enumerator);
				return FAILED;
			}
			this->peer_cfg->get_ref(this->peer_cfg);
			enumerator->destroy(enumerator);
			any->destroy(any);

			this->ike_sa->set_other_id(this->ike_sa, id);

			this->ike_sa->set_peer_cfg(this->ike_sa, this->peer_cfg);

			this->my_auth = get_auth_cfg(this, TRUE);
			this->other_auth = get_auth_cfg(this, FALSE);
			if (!this->my_auth || !this->other_auth)
			{
				DBG1(DBG_IKE, "auth config missing");
				return FAILED;
			}

			if (!verify_hash(this, TRUE, message, id))
			{
				return FAILED;
			}

			this->state = MM_AUTH;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

/**
 * Lookup a shared secret for this IKE_SA
 */
static shared_key_t *lookup_shared_key(private_main_mode_t *this)
{
	host_t *me, *other;
	identification_t *my_id, *other_id;
	shared_key_t *shared_key;

	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_id = identification_create_from_sockaddr(me->get_sockaddr(me));
	other_id = identification_create_from_sockaddr(other->get_sockaddr(other));
	if (!my_id || !other_id)
	{
		DESTROY_IF(my_id);
		DESTROY_IF(other_id);
		return NULL;
	}
	shared_key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE, my_id,
										  other_id);
	if (!shared_key)
	{
		DBG1(DBG_IKE, "no shared key found for %H - %H", me, other);
	}
	my_id->destroy(my_id);
	other_id->destroy(other_id);
	return shared_key;
}

/**
 * Derive key material for this IKE_SA
 */
static bool derive_keys(private_main_mode_t *this, chunk_t nonce_i,
						chunk_t nonce_r)
{
	ike_sa_id_t *id = this->ike_sa->get_id(this->ike_sa);
	shared_key_t *shared_key = NULL;

	switch (this->auth_method)
	{
		case AUTH_PSK:
		case AUTH_XAUTH_INIT_PSK:
			shared_key = lookup_shared_key(this);
			break;
		default:
			break;
	}
	if (!this->keymat->derive_ike_keys(this->keymat, this->proposal, this->dh,
			this->dh_value, nonce_i, nonce_r, id, this->auth_method, shared_key))
	{
		DESTROY_IF(shared_key);
		return FALSE;
	}
	DESTROY_IF(shared_key);
	charon->bus->ike_keys(charon->bus, this->ike_sa, this->dh, nonce_i, nonce_r,
						  NULL);
	return TRUE;
}

METHOD(task_t, build_r, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_SA:
		{
			sa_payload_t *sa_payload;

			sa_payload = sa_payload_create_from_proposal_v1(this->proposal,
					this->lifetime, 0, this->auth_method, MODE_NONE, FALSE);
			message->add_payload(message, &sa_payload->payload_interface);

			return NEED_MORE;
		}
		case MM_KE:
		{
			if (!add_nonce_ke(this, &this->nonce_r, message))
			{
				return FAILED;
			}
			if (!derive_keys(this, this->nonce_i, this->nonce_r))
			{
				DBG1(DBG_IKE, "key derivation failed");
				return FAILED;
			}
			return NEED_MORE;
		}
		case MM_AUTH:
		{
			id_payload_t *id_payload;
			identification_t *id;

			id = this->my_auth->get(this->my_auth, AUTH_RULE_IDENTITY);
			if (!id)
			{
				DBG1(DBG_CFG, "own identity not known");
				return FAILED;
			}

			this->ike_sa->set_my_id(this->ike_sa, id->clone(id));

			id_payload = id_payload_create_from_identification(ID_V1, id);
			message->add_payload(message, &id_payload->payload_interface);

			build_hash(this, FALSE, message, id);

			DBG0(DBG_IKE, "IKE_SA %s[%d] established between %H[%Y]...%H[%Y]",
				 this->ike_sa->get_name(this->ike_sa),
				 this->ike_sa->get_unique_id(this->ike_sa),
				 this->ike_sa->get_my_host(this->ike_sa),
				 this->ike_sa->get_my_id(this->ike_sa),
				 this->ike_sa->get_other_host(this->ike_sa),
				 this->ike_sa->get_other_id(this->ike_sa));
			this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
			charon->bus->ike_updown(charon->bus, this->ike_sa, TRUE);

			switch (this->auth_method)
			{
				case AUTH_XAUTH_INIT_PSK:
				case AUTH_XAUTH_INIT_RSA: /* There should be more INIT cases here once added */
				{
					job_t *job = (job_t *) initiate_xauth_job_create(this->ike_sa->get_id(this->ike_sa));
					lib->processor->queue_job(lib->processor, job);
					break;
				}
				default:
					break;
			}
			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_SA:
		{
			linked_list_t *list;
			sa_payload_t *sa_payload;
			auth_method_t auth_method;
			u_int32_t lifetime;

			sa_payload = (sa_payload_t*)message->get_payload(message,
													SECURITY_ASSOCIATION_V1);
			if (!sa_payload)
			{
				DBG1(DBG_IKE, "SA payload missing");
				return FAILED;
			}
			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return FAILED;
			}

			lifetime = sa_payload->get_lifetime(sa_payload);
			if (lifetime != this->lifetime)
			{
				DBG1(DBG_IKE, "received lifetime %us does not match configured "
					 "%us, using lower value", lifetime, this->lifetime);
			}
			this->lifetime = min(this->lifetime, lifetime);
			auth_method = sa_payload->get_auth_method(sa_payload);
			if (auth_method != this->auth_method)
			{
				DBG1(DBG_IKE, "received %N authentication, but configured %N, "
					 "continue with configured", auth_method_names, auth_method,
					 auth_method_names, this->auth_method);
			}
			return NEED_MORE;
		}
		case MM_KE:
		{
			if (!get_nonce_ke(this, &this->nonce_r, message))
			{
				return FAILED;
			}
			if (!derive_keys(this, this->nonce_i, this->nonce_r))
			{
				DBG1(DBG_IKE, "key derivation failed");
				return FAILED;
			}
			return NEED_MORE;
		}
		case MM_AUTH:
		{
			id_payload_t *id_payload;
			identification_t *id;

			id_payload = (id_payload_t*)message->get_payload(message, ID_V1);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "IDir payload missing");
				return FAILED;
			}
			id = id_payload->get_identification(id_payload);
			if (!id->matches(id, this->other_auth->get(this->other_auth,
													   AUTH_RULE_IDENTITY)))
			{
				DBG1(DBG_IKE, "IDir does not match");
				id->destroy(id);
				return FAILED;
			}
			this->ike_sa->set_other_id(this->ike_sa, id);

			if (!verify_hash(this, FALSE, message, id))
			{
				return FAILED;
			}

			/* TODO-IKEv1: check for XAUTH rounds, queue them */
			DBG0(DBG_IKE, "IKE_SA %s[%d] established between %H[%Y]...%H[%Y]",
				 this->ike_sa->get_name(this->ike_sa),
				 this->ike_sa->get_unique_id(this->ike_sa),
				 this->ike_sa->get_my_host(this->ike_sa),
				 this->ike_sa->get_my_id(this->ike_sa),
				 this->ike_sa->get_other_host(this->ike_sa),
				 this->ike_sa->get_other_id(this->ike_sa));
			this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
			charon->bus->ike_updown(charon->bus, this->ike_sa, TRUE);

			switch (this->auth_method)
			{
				case AUTH_XAUTH_RESP_PSK:
				case AUTH_XAUTH_RESP_RSA: /* There should be more RESP cases here once added */
				{
					job_t *job = (job_t *) initiate_xauth_job_create(this->ike_sa->get_id(this->ike_sa));
					lib->processor->queue_job(lib->processor, job);
					break;
				}
				default:
					break;
			}

			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, get_type, task_type_t,
	private_main_mode_t *this)
{
	return TASK_MAIN_MODE;
}

METHOD(task_t, migrate, void,
	private_main_mode_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, destroy, void,
	private_main_mode_t *this)
{
	DESTROY_IF(this->peer_cfg);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->dh);
	free(this->dh_value.ptr);
	free(this->nonce_i.ptr);
	free(this->nonce_r.ptr);
	free(this->sa_payload.ptr);
	free(this);
}

/*
 * Described in header.
 */
main_mode_t *main_mode_create(ike_sa_t *ike_sa, bool initiator)
{
	private_main_mode_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.keymat = (keymat_v1_t*)ike_sa->get_keymat(ike_sa),
		.initiator = initiator,
		.state = MM_INIT,
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}
