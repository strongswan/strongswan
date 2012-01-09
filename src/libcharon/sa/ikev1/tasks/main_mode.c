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
#include <sa/ikev1/keymat_v1.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/hash_payload.h>
#include <sa/ikev1/tasks/xauth.h>
#include <sa/ikev1/tasks/mode_config.h>
#include <sa/ikev1/tasks/informational.h>
#include <sa/ikev1/tasks/isakmp_delete.h>
#include <processing/jobs/adopt_children_job.h>

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
static auth_cfg_t *get_auth_cfg(peer_cfg_t *peer_cfg, bool local)
{
	enumerator_t *enumerator;
	auth_cfg_t *cfg = NULL;

	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, local);
	enumerator->enumerate(enumerator, &cfg);
	enumerator->destroy(enumerator);
	return cfg;
}

/**
 * Create an authenticator, if supported
 */
static authenticator_t *create_authenticator(private_main_mode_t *this,
											 id_payload_t *id)
{
	authenticator_t *authenticator;
	authenticator = authenticator_create_v1(this->ike_sa, this->initiator,
											this->auth_method, this->dh,
											this->dh_value, this->sa_payload,
											id->get_encoded(id));
	if (!authenticator)
	{
		DBG1(DBG_IKE, "negotiated authentication method %N not supported",
			 auth_method_names, this->auth_method);
	}
	return authenticator;
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
 * Get the two auth classes from local or remote config
 */
static void get_auth_class(peer_cfg_t *peer_cfg, bool local,
						   auth_class_t *c1, auth_class_t *c2)
{
	enumerator_t *enumerator;
	auth_cfg_t *auth;

	*c1 = *c2 = AUTH_CLASS_ANY;

	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, local);
	while (enumerator->enumerate(enumerator, &auth))
	{
		if (*c1 == AUTH_CLASS_ANY)
		{
			*c1 = (uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS);
		}
		else
		{
			*c2 = (uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS);
			break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Get auth method to use from a peer config
 */
static auth_method_t get_auth_method(private_main_mode_t *this,
									 peer_cfg_t *peer_cfg)
{
	auth_class_t i1, i2, r1, r2;

	get_auth_class(peer_cfg, this->initiator, &i1, &i2);
	get_auth_class(peer_cfg, !this->initiator, &r1, &r2);

	if (i1 == AUTH_CLASS_PUBKEY && r1 == AUTH_CLASS_PUBKEY)
	{
		if (i2 == AUTH_CLASS_ANY && r2 == AUTH_CLASS_ANY)
		{
			/* TODO-IKEv1: ECDSA? */
			return AUTH_RSA;
		}
		if (i2 == AUTH_CLASS_XAUTH)
		{
			return AUTH_XAUTH_INIT_RSA;
		}
		if (r2 == AUTH_CLASS_XAUTH)
		{
			return AUTH_XAUTH_RESP_RSA;
		}
	}
	if (i1 == AUTH_CLASS_PSK && r1 == AUTH_CLASS_PSK)
	{
		if (i2 == AUTH_CLASS_ANY && r2 == AUTH_CLASS_ANY)
		{
			return AUTH_PSK;
		}
		if (i2 == AUTH_CLASS_XAUTH)
		{
			return AUTH_XAUTH_INIT_PSK;
		}
		if (r2 == AUTH_CLASS_XAUTH)
		{
			return AUTH_XAUTH_RESP_PSK;
		}
	}
	if (i1 == AUTH_CLASS_XAUTH && r1 == AUTH_CLASS_PUBKEY &&
		i2 == AUTH_CLASS_ANY && r2 == AUTH_CLASS_ANY)
	{
		return AUTH_HYBRID_INIT_RSA;
	}
	return AUTH_NONE;
}

/**
 * Check if a peer skipped authentication by using Hybrid authentication
 */
static bool skipped_auth(private_main_mode_t *this, bool local)
{
	bool initiator;

	initiator = local == this->initiator;
	if (initiator && this->auth_method == AUTH_HYBRID_INIT_RSA)
	{
		return TRUE;
	}
	if (!initiator && this->auth_method == AUTH_HYBRID_RESP_RSA)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Check if remote authentication constraints fulfilled
 */
static bool check_constraints(private_main_mode_t *this)
{
	identification_t *id;
	auth_cfg_t *auth;

	auth = this->ike_sa->get_auth_cfg(this->ike_sa, FALSE);
	/* auth identity to comply */
	id = this->ike_sa->get_other_id(this->ike_sa);
	auth->add(auth, AUTH_RULE_IDENTITY, id->clone(id));
	if (skipped_auth(this, FALSE))
	{
		return TRUE;
	}
	return auth->complies(auth, this->other_auth, TRUE);
}

/**
 * Save authentication information after authentication succeeded
 */
static void save_auth_cfg(private_main_mode_t *this, bool local)
{
	auth_cfg_t *auth;

	if (skipped_auth(this, local))
	{
		return;
	}
	auth = auth_cfg_create();
	/* for local config, we _copy_ entires from the config, as it contains
	 * certificates we must send later. */
	auth->merge(auth, this->ike_sa->get_auth_cfg(this->ike_sa, local), local);
	this->ike_sa->add_auth_cfg(this->ike_sa, local, auth);
}

/**
 * Select the best configuration as responder
 */
static peer_cfg_t *select_config(private_main_mode_t *this, identification_t *id)
{
	enumerator_t *enumerator;
	peer_cfg_t *current, *found = NULL;
	host_t *me, *other;

	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	DBG1(DBG_CFG, "looking for %N peer configs matching %H...%H[%Y]",
		 auth_method_names, this->auth_method, me, other, id);
	enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends,
													me, other, NULL, id, IKEV1);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (get_auth_method(this, current) == this->auth_method)
		{
			found = current->get_ref(current);
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (found)
	{
		DBG2(DBG_CFG, "selected peer config \"%s\"", found->get_name(found));
	}
	return found;
}

/**
 * Check for notify errors, return TRUE if error found
 */
static bool has_notify_errors(private_main_mode_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	bool err = FALSE;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == NOTIFY_V1)
		{
			notify_payload_t *notify;
			notify_type_t type;

			notify = (notify_payload_t*)payload;
			type = notify->get_notify_type(notify);
			if (type < 16384)
			{
				DBG1(DBG_IKE, "received %N error notify",
					 notify_type_names, type);
				err = TRUE;
			}
			else if (type == INITIAL_CONTACT_IKEV1)
			{
				if (!this->initiator && this->state == MM_AUTH)
				{
					/* If authenticated and received INITIAL_CONTACT,
					 * delete any existing IKE_SAs with that peer.
					 * The delete takes place when the SA is checked in due
					 * to other id not known until the 3rd message.*/
					this->ike_sa->set_condition(this->ike_sa,
												COND_INIT_CONTACT_SEEN, TRUE);
				}
			}
			else
			{
				DBG1(DBG_IKE, "received %N notify", notify_type_names, type);
			}
		}
	}
	enumerator->destroy(enumerator);

	return err;
}

/**
 * Queue a task sending a notify in an INFORMATIONAL exchange
 */
static status_t send_notify(private_main_mode_t *this, notify_type_t type)
{
	notify_payload_t *notify;
	ike_sa_id_t *ike_sa_id;
	u_int64_t spi_i, spi_r;
	chunk_t spi;

	notify = notify_payload_create_from_protocol_and_type(NOTIFY_V1,
														  PROTO_IKE, type);
	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	spi_i = ike_sa_id->get_initiator_spi(ike_sa_id);
	spi_r = ike_sa_id->get_responder_spi(ike_sa_id);
	spi = chunk_cata("cc", chunk_from_thing(spi_i), chunk_from_thing(spi_r));
	notify->set_spi_data(notify, spi);

	this->ike_sa->queue_task(this->ike_sa,
						(task_t*)informational_create(this->ike_sa, notify));
	/* cancel all active/passive tasks in favour of informational */
	return ALREADY_DONE;
}

/**
 * Queue a delete task if authentication failed as initiator
 */
static status_t send_delete(private_main_mode_t *this)
{
	this->ike_sa->queue_task(this->ike_sa,
						(task_t*)isakmp_delete_create(this->ike_sa, TRUE));
	/* cancel all active tasks in favour of informational */
	return ALREADY_DONE;
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

			this->my_auth = get_auth_cfg(this->peer_cfg, TRUE);
			this->other_auth = get_auth_cfg(this->peer_cfg, FALSE);
			if (!this->my_auth || !this->other_auth)
			{
				DBG1(DBG_CFG, "no auth config found");
				return FAILED;
			}
			this->auth_method = get_auth_method(this, this->peer_cfg);
			if (this->auth_method == AUTH_NONE)
			{
				DBG1(DBG_CFG, "configuration uses unsupported authentication");
				return FAILED;
			}
			this->lifetime = this->peer_cfg->get_reauth_time(this->peer_cfg,
															FALSE);
			if (!this->lifetime)
			{	/* fall back to rekey time of no rekey time configured */
				this->lifetime = this->peer_cfg->get_rekey_time(this->peer_cfg,
																 FALSE);
			}
			this->lifetime += this->peer_cfg->get_over_time(this->peer_cfg);
			proposals = this->ike_cfg->get_proposals(this->ike_cfg);
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

			if (!this->keymat->create_hasher(this->keymat, this->proposal))
			{
				return send_notify(this, NO_PROPOSAL_CHOSEN);
			}
			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return send_notify(this, NO_PROPOSAL_CHOSEN);
			}
			this->dh = this->keymat->keymat.create_dh(&this->keymat->keymat,
													  group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			if (!add_nonce_ke(this, &this->nonce_i, message))
			{
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			this->state = MM_KE;
			return NEED_MORE;
		}
		case MM_KE:
		{
			authenticator_t *authenticator;
			id_payload_t *id_payload;
			identification_t *id;

			id = this->my_auth->get(this->my_auth, AUTH_RULE_IDENTITY);
			if (!id)
			{
				DBG1(DBG_CFG, "own identity not known");
				return send_notify(this, INVALID_ID_INFORMATION);
			}

			this->ike_sa->set_my_id(this->ike_sa, id->clone(id));

			id_payload = id_payload_create_from_identification(ID_V1, id);
			message->add_payload(message, &id_payload->payload_interface);

			authenticator = create_authenticator(this, id_payload);
			if (!authenticator || authenticator->build(authenticator,
													   message) != SUCCESS)
			{
				DESTROY_IF(authenticator);
				return send_notify(this, AUTHENTICATION_FAILED);
			}
			authenticator->destroy(authenticator);
			save_auth_cfg(this, TRUE);

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
				return send_notify(this, INVALID_PAYLOAD_TYPE);
			}

			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return send_notify(this, NO_PROPOSAL_CHOSEN);
			}

			this->auth_method = sa_payload->get_auth_method(sa_payload);
			this->lifetime = sa_payload->get_lifetime(sa_payload);

			this->state = MM_SA;
			return NEED_MORE;
		}
		case MM_SA:
		{
			u_int16_t group;

			if (!this->keymat->create_hasher(this->keymat, this->proposal))
			{
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			this->dh = lib->crypto->create_dh(lib->crypto, group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			if (!get_nonce_ke(this, &this->nonce_i, message))
			{
				return send_notify(this, INVALID_PAYLOAD_TYPE);
			}
			this->state = MM_KE;
			return NEED_MORE;
		}
		case MM_KE:
		{
			authenticator_t *authenticator;
			id_payload_t *id_payload;
			identification_t *id;

			id_payload = (id_payload_t*)message->get_payload(message, ID_V1);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "IDii payload missing");
				return send_notify(this, INVALID_PAYLOAD_TYPE);
			}

			id = id_payload->get_identification(id_payload);
			this->ike_sa->set_other_id(this->ike_sa, id);
			this->peer_cfg = select_config(this, id);
			if (!this->peer_cfg)
			{
				DBG1(DBG_IKE, "no peer config found");
				return send_notify(this, AUTHENTICATION_FAILED);
			}
			this->ike_sa->set_peer_cfg(this->ike_sa, this->peer_cfg);

			this->my_auth = get_auth_cfg(this->peer_cfg, TRUE);
			this->other_auth = get_auth_cfg(this->peer_cfg, FALSE);
			if (!this->my_auth || !this->other_auth)
			{
				DBG1(DBG_IKE, "auth config missing");
				return send_notify(this, AUTHENTICATION_FAILED);
			}

			authenticator = create_authenticator(this, id_payload);
			if (!authenticator || authenticator->process(authenticator,
														 message) != SUCCESS)
			{
				DESTROY_IF(authenticator);
				return send_notify(this, AUTHENTICATION_FAILED);
			}
			authenticator->destroy(authenticator);
			if (!check_constraints(this))
			{
				return send_notify(this, AUTHENTICATION_FAILED);
			}
			save_auth_cfg(this, FALSE);

			this->state = MM_AUTH;
			if (has_notify_errors(this, message))
			{
				return FAILED;
			}
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
	shared_key_t *shared_key = NULL;

	/* try to get a PSK for IP addresses */
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_id = identification_create_from_sockaddr(me->get_sockaddr(me));
	other_id = identification_create_from_sockaddr(other->get_sockaddr(other));
	if (my_id && other_id)
	{
		shared_key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE,
											  my_id, other_id);
	}
	DESTROY_IF(my_id);
	DESTROY_IF(other_id);
	if (shared_key)
	{
		return shared_key;
	}

	if (this->my_auth && this->other_auth)
	{	/* as initiator, use identities from configuraiton */
		my_id = this->my_auth->get(this->my_auth, AUTH_RULE_IDENTITY);
		other_id = this->other_auth->get(this->other_auth, AUTH_RULE_IDENTITY);
		if (my_id && other_id)
		{
			shared_key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE,
												  my_id, other_id);
			if (!shared_key)
			{
				DBG1(DBG_IKE, "no shared key found for '%Y'[%H] - '%Y'[%H]",
					 my_id, me, other_id, other);
			}
		}
	}
	else
	{	/* as responder, we try to find a config by IP */
		enumerator_t *enumerator;
		auth_cfg_t *my_auth, *other_auth;
		peer_cfg_t *peer_cfg = NULL;

		enumerator = charon->backends->create_peer_cfg_enumerator(
								charon->backends, me, other, NULL, NULL, IKEV1);
		while (enumerator->enumerate(enumerator, &peer_cfg))
		{
			my_auth = get_auth_cfg(peer_cfg, TRUE);
			other_auth = get_auth_cfg(peer_cfg, FALSE);
			if (my_auth && other_auth)
			{
				my_id = my_auth->get(my_auth, AUTH_RULE_IDENTITY);
				other_id = other_auth->get(other_auth, AUTH_RULE_IDENTITY);
				if (my_id && other_id)
				{
					shared_key = lib->credmgr->get_shared(lib->credmgr,
												SHARED_IKE, my_id, other_id);
					if (shared_key)
					{
						break;
					}
					else
					{
						DBG1(DBG_IKE, "no shared key found for "
							"'%Y'[%H] - '%Y'[%H]", my_id, me, other_id, other);
					}
				}
			}
		}
		enumerator->destroy(enumerator);
		if (!peer_cfg)
		{
			DBG1(DBG_IKE, "no shared key found for %H - %H", me, other);
		}
	}
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
		case AUTH_XAUTH_RESP_PSK:
			shared_key = lookup_shared_key(this);
			if (!shared_key)
			{
				return FALSE;
			}
			break;
		default:
			break;
	}
	if (!this->keymat->derive_ike_keys(this->keymat, this->proposal, this->dh,
			this->dh_value, nonce_i, nonce_r, id, this->auth_method, shared_key))
	{
		DESTROY_IF(shared_key);
		DBG1(DBG_IKE, "key derivation for %N failed",
			 auth_method_names, this->auth_method);
		return FALSE;
	}
	DESTROY_IF(shared_key);
	charon->bus->ike_keys(charon->bus, this->ike_sa, this->dh, nonce_i, nonce_r,
						  NULL);

	return TRUE;
}

/**
 * Set IKE_SA to established state
 */
static void establish(private_main_mode_t *this)
{
	DBG0(DBG_IKE, "IKE_SA %s[%d] established between %H[%Y]...%H[%Y]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_my_host(this->ike_sa),
		 this->ike_sa->get_my_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa),
		 this->ike_sa->get_other_id(this->ike_sa));

	this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
	charon->bus->ike_updown(charon->bus, this->ike_sa, TRUE);
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
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			if (!derive_keys(this, this->nonce_i, this->nonce_r))
			{
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			return NEED_MORE;
		}
		case MM_AUTH:
		{
			authenticator_t *authenticator;
			id_payload_t *id_payload;
			identification_t *id;

			id = this->my_auth->get(this->my_auth, AUTH_RULE_IDENTITY);
			if (!id)
			{
				DBG1(DBG_CFG, "own identity not known");
				return send_notify(this, INVALID_ID_INFORMATION);
			}
			this->ike_sa->set_my_id(this->ike_sa, id->clone(id));

			id_payload = id_payload_create_from_identification(ID_V1, id);
			message->add_payload(message, &id_payload->payload_interface);

			authenticator = create_authenticator(this, id_payload);
			if (!authenticator || authenticator->build(authenticator,
													   message) != SUCCESS)
			{
				DESTROY_IF(authenticator);
				return send_notify(this, AUTHENTICATION_FAILED);
			}
			authenticator->destroy(authenticator);
			save_auth_cfg(this, TRUE);

			switch (this->auth_method)
			{
				case AUTH_XAUTH_INIT_PSK:
				case AUTH_XAUTH_INIT_RSA:
				case AUTH_HYBRID_INIT_RSA:
					this->ike_sa->queue_task(this->ike_sa,
									(task_t*)xauth_create(this->ike_sa, TRUE));
					return SUCCESS;
				case AUTH_XAUTH_RESP_PSK:
				case AUTH_XAUTH_RESP_RSA:
				case AUTH_HYBRID_RESP_RSA:
					/* TODO-IKEv1: not yet supported */
					return FAILED;
				default:
					establish(this);
					lib->processor->queue_job(lib->processor, (job_t*)
									adopt_children_job_create(
										this->ike_sa->get_id(this->ike_sa)));
					return SUCCESS;
			}
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
				return send_notify(this, INVALID_PAYLOAD_TYPE);
			}
			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return send_notify(this, NO_PROPOSAL_CHOSEN);
			}

			lifetime = sa_payload->get_lifetime(sa_payload);
			if (lifetime != this->lifetime)
			{
				DBG1(DBG_IKE, "received lifetime %us does not match configured "
					 "lifetime %us", lifetime, this->lifetime);
			}
			this->lifetime = lifetime;
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
				return send_notify(this, INVALID_PAYLOAD_TYPE);
			}
			if (!derive_keys(this, this->nonce_i, this->nonce_r))
			{
				return send_notify(this, INVALID_KEY_INFORMATION);
			}
			return NEED_MORE;
		}
		case MM_AUTH:
		{
			authenticator_t *authenticator;
			id_payload_t *id_payload;
			identification_t *id;

			id_payload = (id_payload_t*)message->get_payload(message, ID_V1);
			if (!id_payload)
			{
				DBG1(DBG_IKE, "IDir payload missing");
				return send_delete(this);
			}
			id = id_payload->get_identification(id_payload);
			if (!id->matches(id, this->other_auth->get(this->other_auth,
													   AUTH_RULE_IDENTITY)))
			{
				DBG1(DBG_IKE, "IDir does not match");
				id->destroy(id);
				return send_delete(this);
			}
			this->ike_sa->set_other_id(this->ike_sa, id);

			authenticator = create_authenticator(this, id_payload);
			if (!authenticator || authenticator->process(authenticator,
														 message) != SUCCESS)
			{
				DESTROY_IF(authenticator);
				return send_delete(this);
			}
			authenticator->destroy(authenticator);
			if (!check_constraints(this))
			{
				return send_delete(this);
			}
			save_auth_cfg(this, FALSE);

			if (this->peer_cfg->get_virtual_ip(this->peer_cfg))
			{
				this->ike_sa->queue_task(this->ike_sa,
							(task_t*)mode_config_create(this->ike_sa, TRUE));
			}

			switch (this->auth_method)
			{
				case AUTH_XAUTH_INIT_PSK:
				case AUTH_XAUTH_INIT_RSA:
				case AUTH_HYBRID_INIT_RSA:
					/* wait for XAUTH request */
					return SUCCESS;
				case AUTH_XAUTH_RESP_PSK:
				case AUTH_XAUTH_RESP_RSA:
				case AUTH_HYBRID_RESP_RSA:
					/* TODO-IKEv1: not yet */
					return FAILED;
				default:
					establish(this);
					return SUCCESS;
			}
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
	DESTROY_IF(this->peer_cfg);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->dh);
	chunk_free(&this->dh_value);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	chunk_free(&this->sa_payload);

	this->ike_sa = ike_sa;
	this->keymat = (keymat_v1_t*)ike_sa->get_keymat(ike_sa);
	this->state = MM_INIT;
	this->peer_cfg = NULL;
	this->proposal = NULL;
	this->dh = NULL;
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
