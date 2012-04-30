/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include "stroke_config.h"

#include <hydra.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <utils/lexparser.h>

typedef struct private_stroke_config_t private_stroke_config_t;

/**
 * private data of stroke_config
 */
struct private_stroke_config_t {

	/**
	 * public functions
	 */
	stroke_config_t public;

	/**
	 * list of peer_cfg_t
	 */
	linked_list_t *list;

	/**
	 * mutex to lock config list
	 */
	mutex_t *mutex;

	/**
	 * ca sections
	 */
	stroke_ca_t *ca;

	/**
	 * credentials
	 */
	stroke_cred_t *cred;
};

METHOD(backend_t, create_peer_cfg_enumerator, enumerator_t*,
	private_stroke_config_t *this, identification_t *me, identification_t *other)
{
	this->mutex->lock(this->mutex);
	return enumerator_create_cleaner(this->list->create_enumerator(this->list),
									 (void*)this->mutex->unlock, this->mutex);
}

/**
 * filter function for ike configs
 */
static bool ike_filter(void *data, peer_cfg_t **in, ike_cfg_t **out)
{
	*out = (*in)->get_ike_cfg(*in);
	return TRUE;
}

METHOD(backend_t, create_ike_cfg_enumerator, enumerator_t*,
	private_stroke_config_t *this, host_t *me, host_t *other)
{
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->list->create_enumerator(this->list),
									(void*)ike_filter, this->mutex,
									(void*)this->mutex->unlock);
}

METHOD(backend_t, get_peer_cfg_by_name, peer_cfg_t*,
	private_stroke_config_t *this, char *name)
{
	enumerator_t *e1, *e2;
	peer_cfg_t *current, *found = NULL;
	child_cfg_t *child;

	this->mutex->lock(this->mutex);
	e1 = this->list->create_enumerator(this->list);
	while (e1->enumerate(e1, &current))
	{
		/* compare peer_cfgs name first */
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
		/* compare all child_cfg names otherwise */
		e2 = current->create_child_cfg_enumerator(current);
		while (e2->enumerate(e2, &child))
		{
			if (streq(child->get_name(child), name))
			{
				found = current;
				found->get_ref(found);
				break;
			}
		}
		e2->destroy(e2);
		if (found)
		{
			break;
		}
	}
	e1->destroy(e1);
	this->mutex->unlock(this->mutex);
	return found;
}

/**
 * parse a proposal string, either into ike_cfg or child_cfg
 */
static void add_proposals(private_stroke_config_t *this, char *string,
						  ike_cfg_t *ike_cfg, child_cfg_t *child_cfg)
{
	if (string)
	{
		char *single;
		char *strict;
		proposal_t *proposal;
		protocol_id_t proto = PROTO_ESP;

		if (ike_cfg)
		{
			proto = PROTO_IKE;
		}
		strict = string + strlen(string) - 1;
		if (*strict == '!')
		{
			*strict = '\0';
		}
		else
		{
			strict = NULL;
		}
		while ((single = strsep(&string, ",")))
		{
			proposal = proposal_create_from_string(proto, single);
			if (proposal)
			{
				if (ike_cfg)
				{
					ike_cfg->add_proposal(ike_cfg, proposal);
				}
				else
				{
					child_cfg->add_proposal(child_cfg, proposal);
				}
				continue;
			}
			DBG1(DBG_CFG, "skipped invalid proposal string: %s", single);
		}
		if (strict)
		{
			return;
		}
		/* add default porposal to the end if not strict */
	}
	if (ike_cfg)
	{
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	}
	else
	{
		child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	}
}

/**
 * Build an IKE config from a stroke message
 */
static ike_cfg_t *build_ike_cfg(private_stroke_config_t *this, stroke_msg_t *msg)
{
	stroke_end_t tmp_end;
	ike_cfg_t *ike_cfg;
	char *interface;
	host_t *host;

	host = host_create_from_dns(msg->add_conn.other.address, 0, 0);
	if (host)
	{
		interface = hydra->kernel_interface->get_interface(
												hydra->kernel_interface, host);
		host->destroy(host);
		if (interface)
		{
			DBG2(DBG_CFG, "left is other host, swapping ends");
			tmp_end = msg->add_conn.me;
			msg->add_conn.me = msg->add_conn.other;
			msg->add_conn.other = tmp_end;
			free(interface);
		}
		else
		{
			host = host_create_from_dns(msg->add_conn.me.address, 0, 0);
			if (host)
			{
				interface = hydra->kernel_interface->get_interface(
												hydra->kernel_interface, host);
				host->destroy(host);
				if (!interface)
				{
					DBG1(DBG_CFG, "left nor right host is our side, "
						 "assuming left=local");
				}
				else
				{
					free(interface);
				}

			}
		}
	}
	ike_cfg = ike_cfg_create(msg->add_conn.other.sendcert != CERT_NEVER_SEND,
					msg->add_conn.force_encap,
					msg->add_conn.me.address, msg->add_conn.me.ikeport,
					msg->add_conn.other.address, msg->add_conn.other.ikeport);
	add_proposals(this, msg->add_conn.algorithms.ike, ike_cfg, NULL);
	return ike_cfg;
}

/**
 * Add CRL constraint to config
 */
static void build_crl_policy(auth_cfg_t *cfg, bool local, int policy)
{
	/* CRL/OCSP policy, for remote config only */
	if (!local)
	{
		switch (policy)
		{
			case CRL_STRICT_YES:
				/* if yes, we require a GOOD validation */
				cfg->add(cfg, AUTH_RULE_CRL_VALIDATION, VALIDATION_GOOD);
				break;
			case CRL_STRICT_IFURI:
				/* for ifuri, a SKIPPED validation is sufficient */
				cfg->add(cfg, AUTH_RULE_CRL_VALIDATION, VALIDATION_SKIPPED);
				break;
			default:
				break;
		}
	}
}

/**
 * build authentication config
 */
static auth_cfg_t *build_auth_cfg(private_stroke_config_t *this,
								  stroke_msg_t *msg, bool local, bool primary)
{
	identification_t *identity;
	certificate_t *certificate;
	char *auth, *id, *pubkey, *cert, *ca;
	stroke_end_t *end, *other_end;
	auth_cfg_t *cfg;
	char eap_buf[32];

	/* select strings */
	if (local)
	{
		end = &msg->add_conn.me;
		other_end = &msg->add_conn.other;
	}
	else
	{
		end = &msg->add_conn.other;
		other_end = &msg->add_conn.me;
	}
	if (primary)
	{
		auth = end->auth;
		id = end->id;
		if (!id)
		{	/* leftid/rightid fallback to address */
			id = end->address;
		}
		cert = end->cert;
		ca = end->ca;
		if (ca && streq(ca, "%same"))
		{
			ca = other_end->ca;
		}
	}
	else
	{
		auth = end->auth2;
		id = end->id2;
		if (local && !id)
		{	/* leftid2 falls back to leftid */
			id = end->id;
		}
		cert = end->cert2;
		ca = end->ca2;
		if (ca && streq(ca, "%same"))
		{
			ca = other_end->ca2;
		}
	}

	if (!auth)
	{
		if (primary)
		{
			if (local)
			{	/* "leftauth" not defined, fall back to deprecated "authby" */
				switch (msg->add_conn.auth_method)
				{
					default:
					case AUTH_CLASS_PUBKEY:
						auth = "pubkey";
						break;
					case AUTH_CLASS_PSK:
						auth = "psk";
						break;
					case AUTH_CLASS_EAP:
						auth = "eap";
						break;
					case AUTH_CLASS_ANY:
						auth = "any";
						break;
				}
			}
			else
			{	/* "rightauth" not defined, fall back to deprecated "eap" */
				if (msg->add_conn.eap_type)
				{
					if (msg->add_conn.eap_vendor)
					{
						snprintf(eap_buf, sizeof(eap_buf), "eap-%d-%d",
								 msg->add_conn.eap_type,
								 msg->add_conn.eap_vendor);
					}
					else
					{
						snprintf(eap_buf, sizeof(eap_buf), "eap-%d",
								 msg->add_conn.eap_type);
					}
					auth = eap_buf;
				}
				else
				{	/* not EAP => no constraints for this peer */
					auth = "any";
				}
			}
		}
		else
		{	/* no second authentication round, fine. But load certificates
			 * for other purposes (EAP-TLS) */
			if (cert)
			{
				certificate = this->cred->load_peer(this->cred, cert);
				if (certificate)
				{
					certificate->destroy(certificate);
				}
			}
			return NULL;
		}
	}

	cfg = auth_cfg_create();

	/* add identity and peer certifcate */
	identity = identification_create_from_string(id);
	if (cert)
	{
		certificate = this->cred->load_peer(this->cred, cert);
		if (certificate)
		{
			if (local)
			{
				this->ca->check_for_hash_and_url(this->ca, certificate);
			}
			cfg->add(cfg, AUTH_RULE_SUBJECT_CERT, certificate);
			if (identity->get_type(identity) == ID_ANY ||
				!certificate->has_subject(certificate, identity))
			{
				DBG1(DBG_CFG, "  id '%Y' not confirmed by certificate, "
					 "defaulting to '%Y'", identity,
					 certificate->get_subject(certificate));
				identity->destroy(identity);
				identity = certificate->get_subject(certificate);
				identity = identity->clone(identity);
			}
		}
	}
	cfg->add(cfg, AUTH_RULE_IDENTITY, identity);

	/* add raw RSA public key */
	pubkey = end->rsakey;
	if (pubkey && !streq(pubkey, "") && !streq(pubkey, "%cert"))
	{
		certificate = this->cred->load_pubkey(this->cred, KEY_RSA, pubkey,
											  identity);
		if (certificate)
		{
			cfg->add(cfg, AUTH_RULE_SUBJECT_CERT, certificate);
		}
	}

	/* CA constraint */
	if (ca)
	{
		identity = identification_create_from_string(ca);
		certificate = lib->credmgr->get_cert(lib->credmgr, CERT_X509,
											 KEY_ANY, identity, TRUE);
		identity->destroy(identity);
		if (certificate)
		{
			cfg->add(cfg, AUTH_RULE_CA_CERT, certificate);
		}
		else
		{
			DBG1(DBG_CFG, "CA certificate \"%s\" not found, discarding CA "
				 "constraint", ca);
		}
	}

	/* groups */
	if (end->groups)
	{
		enumerator_t *enumerator;
		char *group;

		enumerator = enumerator_create_token(end->groups, ",", " ");
		while (enumerator->enumerate(enumerator, &group))
		{
			cfg->add(cfg, AUTH_RULE_GROUP,
					 identification_create_from_string(group));
		}
		enumerator->destroy(enumerator);
	}

	/* certificatePolicies */
	if (end->cert_policy)
	{
		enumerator_t *enumerator;
		char *policy;

		enumerator = enumerator_create_token(end->cert_policy, ",", " ");
		while (enumerator->enumerate(enumerator, &policy))
		{
			cfg->add(cfg, AUTH_RULE_CERT_POLICY, strdup(policy));
		}
		enumerator->destroy(enumerator);
	}

	/* authentication metod (class, actually) */
	if (streq(auth, "pubkey") ||
		strneq(auth, "rsa", strlen("rsa")) ||
		strneq(auth, "ecdsa", strlen("ecdsa")))
	{
		u_int strength;

		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
		build_crl_policy(cfg, local, msg->add_conn.crl_policy);

		if (sscanf(auth, "rsa-%d", &strength) == 1)
		{
			cfg->add(cfg, AUTH_RULE_RSA_STRENGTH, (uintptr_t)strength);
		}
		if (sscanf(auth, "ecdsa-%d", &strength) == 1)
		{
			cfg->add(cfg, AUTH_RULE_ECDSA_STRENGTH, (uintptr_t)strength);
		}
	}
	else if (streq(auth, "psk") || streq(auth, "secret"))
	{
		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	}
	else if (strneq(auth, "eap", 3))
	{
		enumerator_t *enumerator;
		char *str;
		int i = 0, type = 0, vendor;

		cfg->add(cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_EAP);

		/* parse EAP string, format: eap[-type[-vendor]] */
		enumerator = enumerator_create_token(auth, "-", " ");
		while (enumerator->enumerate(enumerator, &str))
		{
			switch (i)
			{
				case 1:
					type = eap_type_from_string(str);
					if (!type)
					{
						type = atoi(str);
						if (!type)
						{
							DBG1(DBG_CFG, "unknown EAP method: %s", str);
							break;
						}
					}
					cfg->add(cfg, AUTH_RULE_EAP_TYPE, type);
					break;
				case 2:
					if (type)
					{
						vendor = atoi(str);
						if (vendor)
						{
							cfg->add(cfg, AUTH_RULE_EAP_VENDOR, vendor);
						}
						else
						{
							DBG1(DBG_CFG, "unknown EAP vendor: %s", str);
						}
					}
					break;
				default:
					break;
			}
			i++;
		}
		enumerator->destroy(enumerator);

		if (msg->add_conn.eap_identity)
		{
			if (streq(msg->add_conn.eap_identity, "%identity"))
			{
				identity = identification_create_from_encoding(ID_ANY,
															   chunk_empty);
			}
			else
			{
				identity = identification_create_from_string(
													msg->add_conn.eap_identity);
			}
			cfg->add(cfg, AUTH_RULE_EAP_IDENTITY, identity);
		}
		if (msg->add_conn.aaa_identity)
		{
			cfg->add(cfg, AUTH_RULE_AAA_IDENTITY,
				identification_create_from_string(msg->add_conn.aaa_identity));
		}
	}
	else
	{
		if (!streq(auth, "any"))
		{
			DBG1(DBG_CFG, "authentication method %s unknown, fallback to any",
				 auth);
		}
		build_crl_policy(cfg, local, msg->add_conn.crl_policy);
	}
	return cfg;
}

/**
 * build a peer_cfg from a stroke msg
 */
static peer_cfg_t *build_peer_cfg(private_stroke_config_t *this,
								  stroke_msg_t *msg, ike_cfg_t *ike_cfg)
{
	identification_t *peer_id = NULL;
	peer_cfg_t *mediated_by = NULL;
	host_t *vip = NULL;
	unique_policy_t unique;
	u_int32_t rekey = 0, reauth = 0, over, jitter;
	peer_cfg_t *peer_cfg;
	auth_cfg_t *auth_cfg;

#ifdef ME
	if (msg->add_conn.ikeme.mediation && msg->add_conn.ikeme.mediated_by)
	{
		DBG1(DBG_CFG, "a mediation connection cannot be a mediated connection "
			 "at the same time, aborting");
		return NULL;
	}

	if (msg->add_conn.ikeme.mediation)
	{
		/* force unique connections for mediation connections */
		msg->add_conn.unique = 1;
	}

	if (msg->add_conn.ikeme.mediated_by)
	{
		mediated_by = charon->backends->get_peer_cfg_by_name(charon->backends,
											msg->add_conn.ikeme.mediated_by);
		if (!mediated_by)
		{
			DBG1(DBG_CFG, "mediation connection '%s' not found, aborting",
				 msg->add_conn.ikeme.mediated_by);
			return NULL;
		}
		if (!mediated_by->is_mediation(mediated_by))
		{
			DBG1(DBG_CFG, "connection '%s' as referred to by '%s' is "
				 "no mediation connection, aborting",
				 msg->add_conn.ikeme.mediated_by, msg->add_conn.name);
			mediated_by->destroy(mediated_by);
			return NULL;
		}
		if (msg->add_conn.ikeme.peerid)
		{
			peer_id = identification_create_from_string(msg->add_conn.ikeme.peerid);
		}
		else if (msg->add_conn.other.id)
		{
			peer_id = identification_create_from_string(msg->add_conn.other.id);
		}
	}
#endif /* ME */

	jitter = msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100;
	over = msg->add_conn.rekey.margin;
	if (msg->add_conn.rekey.reauth)
	{
		reauth = msg->add_conn.rekey.ike_lifetime - over;
	}
	else
	{
		rekey = msg->add_conn.rekey.ike_lifetime - over;
	}
	if (msg->add_conn.me.sourceip_mask)
	{
		if (msg->add_conn.me.sourceip)
		{
			vip = host_create_from_string(msg->add_conn.me.sourceip, 0);
		}
		if (!vip)
		{	/* if it is set to something like %poolname, request an address */
			if (msg->add_conn.me.subnets)
			{	/* use the same address as in subnet, if any */
				if (strchr(msg->add_conn.me.subnets, '.'))
				{
					vip = host_create_any(AF_INET);
				}
				else
				{
					vip = host_create_any(AF_INET6);
				}
			}
			else
			{
				if (strchr(ike_cfg->get_my_addr(ike_cfg), ':'))
				{
					vip = host_create_any(AF_INET6);
				}
				else
				{
					vip = host_create_any(AF_INET);
				}
			}
		}
	}
	switch (msg->add_conn.unique)
	{
		case 1: /* yes */
		case 2: /* replace */
			unique = UNIQUE_REPLACE;
			break;
		case 3: /* keep */
			unique = UNIQUE_KEEP;
			break;
		default: /* no */
			unique = UNIQUE_NO;
			break;
	}
	if (msg->add_conn.dpd.action == 0)
	{	/* dpdaction=none disables DPD */
		msg->add_conn.dpd.delay = 0;
	}

	/* other.sourceip is managed in stroke_attributes. If it is set, we define
	 * the pool name as the connection name, which the attribute provider
	 * uses to serve pool addresses. */
	peer_cfg = peer_cfg_create(msg->add_conn.name,
		msg->add_conn.ikev2 ? 2 : 1, ike_cfg,
		msg->add_conn.me.sendcert, unique,
		msg->add_conn.rekey.tries, rekey, reauth, jitter, over,
		msg->add_conn.mobike, msg->add_conn.dpd.delay,
		vip, msg->add_conn.other.sourceip_mask ?
							msg->add_conn.name : msg->add_conn.other.sourceip,
		msg->add_conn.ikeme.mediation, mediated_by, peer_id);

	/* build leftauth= */
	auth_cfg = build_auth_cfg(this, msg, TRUE, TRUE);
	if (auth_cfg)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, TRUE);
	}
	else
	{	/* we require at least one config on our side */
		peer_cfg->destroy(peer_cfg);
		return NULL;
	}
	/* build leftauth2= */
	auth_cfg = build_auth_cfg(this, msg, TRUE, FALSE);
	if (auth_cfg)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, TRUE);
	}
	/* build rightauth= */
	auth_cfg = build_auth_cfg(this, msg, FALSE, TRUE);
	if (auth_cfg)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, FALSE);
	}
	/* build rightauth2= */
	auth_cfg = build_auth_cfg(this, msg, FALSE, FALSE);
	if (auth_cfg)
	{
		peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, FALSE);
	}
	return peer_cfg;
}

/**
 * build a traffic selector from a stroke_end
 */
static void add_ts(private_stroke_config_t *this,
				   stroke_end_t *end, child_cfg_t *child_cfg, bool local)
{
	traffic_selector_t *ts;

	if (end->tohost)
	{
		ts = traffic_selector_create_dynamic(end->protocol,
					end->port ? end->port : 0, end->port ? end->port : 65535);
		child_cfg->add_traffic_selector(child_cfg, local, ts);
	}
	else
	{
		host_t *net;

		if (!end->subnets)
		{
			net = host_create_from_string(end->address, 0);
			if (net)
			{
				ts = traffic_selector_create_from_subnet(net, 0, end->protocol,
														 end->port);
				child_cfg->add_traffic_selector(child_cfg, local, ts);
			}
		}
		else
		{
			char *del, *start, *bits;

			start = end->subnets;
			do
			{
				int intbits = 0;

				del = strchr(start, ',');
				if (del)
				{
					*del = '\0';
				}
				bits = strchr(start, '/');
				if (bits)
				{
					*bits = '\0';
					intbits = atoi(bits + 1);
				}

				net = host_create_from_string(start, 0);
				if (net)
				{
					ts = traffic_selector_create_from_subnet(net, intbits,
												end->protocol, end->port);
					child_cfg->add_traffic_selector(child_cfg, local, ts);
				}
				else
				{
					DBG1(DBG_CFG, "invalid subnet: %s, skipped", start);
				}
				start = del + 1;
			}
			while (del);
		}
	}
}

/**
 * map starter magic values to our action type
 */
static action_t map_action(int starter_action)
{
	switch (starter_action)
	{
		case 2: /* =hold */
			return ACTION_ROUTE;
		case 3: /* =restart */
			return ACTION_RESTART;
		default:
			return ACTION_NONE;
	}
}

/**
 * build a child config from the stroke message
 */
static child_cfg_t *build_child_cfg(private_stroke_config_t *this,
									stroke_msg_t *msg)
{
	child_cfg_t *child_cfg;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = msg->add_conn.rekey.ipsec_lifetime,
			.rekey = msg->add_conn.rekey.ipsec_lifetime - msg->add_conn.rekey.margin,
			.jitter = msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100
		},
		.bytes = {
			.life = msg->add_conn.rekey.life_bytes,
			.rekey = msg->add_conn.rekey.life_bytes - msg->add_conn.rekey.margin_bytes,
			.jitter = msg->add_conn.rekey.margin_bytes * msg->add_conn.rekey.fuzz / 100
		},
		.packets = {
			.life = msg->add_conn.rekey.life_packets,
			.rekey = msg->add_conn.rekey.life_packets - msg->add_conn.rekey.margin_packets,
			.jitter = msg->add_conn.rekey.margin_packets * msg->add_conn.rekey.fuzz / 100
		}
	};
	mark_t mark_in = {
		.value = msg->add_conn.mark_in.value,
		.mask = msg->add_conn.mark_in.mask
	};
	mark_t mark_out = {
		.value = msg->add_conn.mark_out.value,
		.mask = msg->add_conn.mark_out.mask
	};

	child_cfg = child_cfg_create(
				msg->add_conn.name, &lifetime, msg->add_conn.me.updown,
				msg->add_conn.me.hostaccess, msg->add_conn.mode, ACTION_NONE,
				map_action(msg->add_conn.dpd.action),
				map_action(msg->add_conn.close_action), msg->add_conn.ipcomp,
				msg->add_conn.inactivity, msg->add_conn.reqid,
				&mark_in, &mark_out, msg->add_conn.tfc);
	child_cfg->set_mipv6_options(child_cfg, msg->add_conn.proxy_mode,
											msg->add_conn.install_policy);
	add_ts(this, &msg->add_conn.me, child_cfg, TRUE);
	add_ts(this, &msg->add_conn.other, child_cfg, FALSE);

	add_proposals(this, msg->add_conn.algorithms.esp, NULL, child_cfg);

	return child_cfg;
}

METHOD(stroke_config_t, add, void,
	private_stroke_config_t *this, stroke_msg_t *msg)
{
	ike_cfg_t *ike_cfg, *existing_ike;
	peer_cfg_t *peer_cfg, *existing;
	child_cfg_t *child_cfg;
	enumerator_t *enumerator;
	bool use_existing = FALSE;

	ike_cfg = build_ike_cfg(this, msg);
	if (!ike_cfg)
	{
		return;
	}
	peer_cfg = build_peer_cfg(this, msg, ike_cfg);
	if (!peer_cfg)
	{
		ike_cfg->destroy(ike_cfg);
		return;
	}

	enumerator = create_peer_cfg_enumerator(this, NULL, NULL);
	while (enumerator->enumerate(enumerator, &existing))
	{
		existing_ike = existing->get_ike_cfg(existing);
		if (existing->equals(existing, peer_cfg) &&
			existing_ike->equals(existing_ike, peer_cfg->get_ike_cfg(peer_cfg)))
		{
			use_existing = TRUE;
			peer_cfg->destroy(peer_cfg);
			peer_cfg = existing;
			peer_cfg->get_ref(peer_cfg);
			DBG1(DBG_CFG, "added child to existing configuration '%s'",
				 peer_cfg->get_name(peer_cfg));
			break;
		}
	}
	enumerator->destroy(enumerator);

	child_cfg = build_child_cfg(this, msg);
	if (!child_cfg)
	{
		peer_cfg->destroy(peer_cfg);
		return;
	}
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);

	if (use_existing)
	{
		peer_cfg->destroy(peer_cfg);
	}
	else
	{
		/* add config to backend */
		DBG1(DBG_CFG, "added configuration '%s'", msg->add_conn.name);
		this->mutex->lock(this->mutex);
		this->list->insert_last(this->list, peer_cfg);
		this->mutex->unlock(this->mutex);
	}
}

METHOD(stroke_config_t, del, void,
	private_stroke_config_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator, *children;
	peer_cfg_t *peer;
	child_cfg_t *child;
	bool deleted = FALSE;

	this->mutex->lock(this->mutex);
	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, (void**)&peer))
	{
		bool keep = FALSE;

		/* remove any child with such a name */
		children = peer->create_child_cfg_enumerator(peer);
		while (children->enumerate(children, &child))
		{
			if (streq(child->get_name(child), msg->del_conn.name))
			{
				peer->remove_child_cfg(peer, children);
				child->destroy(child);
				deleted = TRUE;
			}
			else
			{
				keep = TRUE;
			}
		}
		children->destroy(children);

		/* if peer config matches, or has no children anymore, remove it */
		if (!keep || streq(peer->get_name(peer), msg->del_conn.name))
		{
			this->list->remove_at(this->list, enumerator);
			peer->destroy(peer);
			deleted = TRUE;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (deleted)
	{
		DBG1(DBG_CFG, "deleted connection '%s'", msg->del_conn.name);
	}
	else
	{
		DBG1(DBG_CFG, "connection '%s' not found", msg->del_conn.name);
	}
}

METHOD(stroke_config_t, set_user_credentials, void,
	private_stroke_config_t *this, stroke_msg_t *msg, FILE *prompt)
{
	enumerator_t *enumerator, *children, *remote_auth;
	peer_cfg_t *peer, *found = NULL;
	auth_cfg_t *auth_cfg, *remote_cfg;
	auth_class_t auth_class;
	child_cfg_t *child;
	identification_t *id, *identity, *gw = NULL;
	shared_key_type_t type = SHARED_ANY;
	chunk_t password = chunk_empty;

	this->mutex->lock(this->mutex);
	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, (void**)&peer))
	{	/* find the peer (or child) config with the given name */
		if (streq(peer->get_name(peer), msg->user_creds.name))
		{
			found = peer;
		}
		else
		{
			children = peer->create_child_cfg_enumerator(peer);
			while (children->enumerate(children, &child))
			{
				if (streq(child->get_name(child), msg->user_creds.name))
				{
					found = peer;
					break;
				}
			}
			children->destroy(children);
		}

		if (found)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		DBG1(DBG_CFG, "  no config named '%s'", msg->user_creds.name);
		fprintf(prompt, "no config named '%s'\n", msg->user_creds.name);
		this->mutex->unlock(this->mutex);
		return;
	}

	id = identification_create_from_string(msg->user_creds.username);
	if (strlen(msg->user_creds.username) == 0 ||
		!id || id->get_type(id) == ID_ANY)
	{
		DBG1(DBG_CFG, "  invalid username '%s'", msg->user_creds.username);
		fprintf(prompt, "invalid username '%s'\n", msg->user_creds.username);
		this->mutex->unlock(this->mutex);
		DESTROY_IF(id);
		return;
	}

	/* replace/set the username in the first EAP auth_cfg, also look for a
	 * suitable remote ID.
	 * note that adding the identity here is not fully thread-safe as the
	 * peer_cfg and in turn the auth_cfg could be in use. for the default use
	 * case (setting user credentials before upping the connection) this will
	 * not be a problem, though. */
	enumerator = found->create_auth_cfg_enumerator(found, TRUE);
	remote_auth = found->create_auth_cfg_enumerator(found, FALSE);
	while (enumerator->enumerate(enumerator, (void**)&auth_cfg))
	{
		if (remote_auth->enumerate(remote_auth, (void**)&remote_cfg))
		{	/* fall back on rightid, in case aaa_identity is not specified */
			identity = remote_cfg->get(remote_cfg, AUTH_RULE_IDENTITY);
			if (identity && identity->get_type(identity) != ID_ANY)
			{
				gw = identity;
			}
		}

		auth_class = (uintptr_t)auth_cfg->get(auth_cfg, AUTH_RULE_AUTH_CLASS);
		if (auth_class == AUTH_CLASS_EAP)
		{
			auth_cfg->add(auth_cfg, AUTH_RULE_EAP_IDENTITY, id->clone(id));
			/* if aaa_identity is specified use that as remote ID */
			identity = auth_cfg->get(auth_cfg, AUTH_RULE_AAA_IDENTITY);
			if (identity && identity->get_type(identity) != ID_ANY)
			{
				gw = identity;
			}
			DBG1(DBG_CFG, "  configured EAP-Identity %Y", id);
			type = SHARED_EAP;
			break;
		}
	}
	enumerator->destroy(enumerator);
	remote_auth->destroy(remote_auth);
	/* clone the gw ID before unlocking the mutex */
	if (gw)
	{
		gw = gw->clone(gw);
	}
	this->mutex->unlock(this->mutex);

	if (type == SHARED_ANY)
	{
		DBG1(DBG_CFG, "  config '%s' unsuitable for user credentials",
			 msg->user_creds.name);
		fprintf(prompt, "config '%s' unsuitable for user credentials\n",
				msg->user_creds.name);
		id->destroy(id);
		DESTROY_IF(gw);
		return;
	}

	if (msg->user_creds.password)
	{
		char *pass;

		pass = msg->user_creds.password;
		password = chunk_clone(chunk_create(pass, strlen(pass)));
		memwipe(pass, strlen(pass));
	}
	else
	{	/* prompt the user for the password */
		char buf[256];

		fprintf(prompt, "Password:\n");
		if (fgets(buf, sizeof(buf), prompt))
		{
			password = chunk_clone(chunk_create(buf, strlen(buf)));
			if (password.len > 0)
			{	/* trim trailing \n */
				password.len--;
			}
			memwipe(buf, sizeof(buf));
		}
	}

	if (password.len)
	{
		shared_key_t *shared;
		linked_list_t *owners;

		shared = shared_key_create(type, password);

		owners = linked_list_create();
		owners->insert_last(owners, id->clone(id));
		if (gw && gw->get_type(gw) != ID_ANY)
		{
			owners->insert_last(owners, gw->clone(gw));
			DBG1(DBG_CFG, "  added %N secret for %Y %Y", shared_key_type_names,
				 type, id, gw);
		}
		else
		{
			DBG1(DBG_CFG, "  added %N secret for %Y", shared_key_type_names,
				 type, id);
		}
		this->cred->add_shared(this->cred, shared, owners);
		DBG4(DBG_CFG, "  secret: %#B", &password);
	}
	else
	{	/* in case a user answers the password prompt by just pressing enter */
		chunk_clear(&password);
	}
	id->destroy(id);
	DESTROY_IF(gw);
}

METHOD(stroke_config_t, destroy, void,
	private_stroke_config_t *this)
{
	this->list->destroy_offset(this->list, offsetof(peer_cfg_t, destroy));
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
stroke_config_t *stroke_config_create(stroke_ca_t *ca, stroke_cred_t *cred)
{
	private_stroke_config_t *this;

	INIT(this,
		.public = {
			.backend = {
				.create_peer_cfg_enumerator = _create_peer_cfg_enumerator,
				.create_ike_cfg_enumerator = _create_ike_cfg_enumerator,
				.get_peer_cfg_by_name = _get_peer_cfg_by_name,
			},
			.add = _add,
			.del = _del,
			.set_user_credentials = _set_user_credentials,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.ca = ca,
		.cred = cred,
	);

	return &this->public;
}

