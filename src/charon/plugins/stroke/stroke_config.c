/*
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
 *
 * $Id$
 */

#include "stroke_config.h"

#include <daemon.h>
#include <utils/mutex.h>

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
	 * credentials
	 */
	stroke_cred_t *cred;
};

/**
 * data to pass peer_filter
 */
typedef struct {
	private_stroke_config_t *this;
	identification_t *me;
	identification_t *other;
} peer_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void peer_data_destroy(peer_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter function for peer configs
 */
static bool peer_filter(peer_data_t *data, peer_cfg_t **in, peer_cfg_t **out)
{
	bool match_me = FALSE, match_other = FALSE;
	identification_t *me, *other;
	
	me = (*in)->get_my_id(*in);
	other = (*in)->get_other_id(*in);
	
	/* own ID may have wildcards in data (no IDr payload) or in config */
	match_me = (!data->me || data->me->matches(data->me, me) ||
				me->matches(me, data->me));
	/* others ID has wildcards in config only */
	match_other = (!data->other || data->other->matches(data->other, other));
	
	if (match_me && match_other)
	{
		*out = *in;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(private_stroke_config_t *this,
												identification_t *me,
												identification_t *other)
{
	peer_data_t *data;
	
	data = malloc_thing(peer_data_t);
	data->this = this;
	data->me = me;
	data->other = other;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->list->create_enumerator(this->list),
									(void*)peer_filter, data,
									(void*)peer_data_destroy);
}

/**
 * data to pass ike_filter
 */
typedef struct {
	private_stroke_config_t *this;
	host_t *me;
	host_t *other;
} ike_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void ike_data_destroy(ike_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter function for ike configs
 */
static bool ike_filter(ike_data_t *data, peer_cfg_t **in, ike_cfg_t **out)
{
	ike_cfg_t *ike_cfg;
	host_t *me, *other;
	
	ike_cfg = (*in)->get_ike_cfg(*in);
	
	me = ike_cfg->get_my_host(ike_cfg);
	other = ike_cfg->get_other_host(ike_cfg);
	if ((!data->me || me->is_anyaddr(me) || me->ip_equals(me, data->me)) &&
		(!data->other || other->is_anyaddr(other) || other->ip_equals(other, data->other)))
	{
		*out = ike_cfg;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(private_stroke_config_t *this,
											   host_t *me, host_t *other)
{
	ike_data_t *data;
	
	data = malloc_thing(ike_data_t);
	data->this = this;
	data->me = me;
	data->other = other;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->list->create_enumerator(this->list),
									(void*)ike_filter, data,
									(void*)ike_data_destroy);
}

/**
 * implements backend_t.get_peer_cfg_by_name.
 */
static peer_cfg_t *get_peer_cfg_by_name(private_stroke_config_t *this, char *name)
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
 * check if a certificate has an ID
 */
static identification_t *update_peerid(certificate_t *cert, identification_t *id)
{
	if (!cert->has_subject(cert, id))
	{
		DBG1(DBG_CFG, "  peerid %D not confirmed by certificate, "
			 "defaulting to subject DN", id);
		id->destroy(id);
		id = cert->get_subject(cert);
		return id->clone(id);
	}
	return id;
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
	host_t *me = NULL, *other = NULL, *tmp;
	stroke_end_t tmp_end;
	ike_cfg_t *ike_cfg;
	char *interface;

	if (msg->add_conn.me.address)
	{
		me = host_create_from_string(msg->add_conn.me.address, IKEV2_UDP_PORT);
	}
	if (!me)
	{
		DBG1(DBG_CFG, "invalid left host: %s", msg->add_conn.me.address);
		return NULL;
	}
	if (msg->add_conn.other.address)
	{
		other = host_create_from_string(msg->add_conn.other.address, IKEV2_UDP_PORT);
	}
	if (!other)
	{
		DBG1(DBG_CFG, "invalid right host: %s", msg->add_conn.other.address);
		me->destroy(me);
		return NULL;
	}
	interface = charon->kernel_interface->get_interface(
											charon->kernel_interface, other);
	if (interface)
	{
		DBG2(DBG_CFG, "left is other host, swapping ends");
		tmp = me;
		me = other;
		other = tmp;
		tmp_end = msg->add_conn.me;
		msg->add_conn.me = msg->add_conn.other;
		msg->add_conn.other = tmp_end;
		free(interface);
	}
	else
	{
		interface = charon->kernel_interface->get_interface(
												charon->kernel_interface, me);
		if (!interface)
		{
			DBG1(DBG_CFG, "left nor right host is our side, assuming left=local");
		}
		else
		{
			free(interface);
		}
	}
	ike_cfg = ike_cfg_create(msg->add_conn.other.sendcert != CERT_NEVER_SEND,
							 msg->add_conn.force_encap, me, other);
	add_proposals(this, msg->add_conn.algorithms.ike, ike_cfg, NULL);
	return ike_cfg;					 
}
/**
 * build a peer_cfg from a stroke msg
 */
static peer_cfg_t *build_peer_cfg(private_stroke_config_t *this,
								  stroke_msg_t *msg, ike_cfg_t *ike_cfg)
{
	identification_t *me, *other, *peer_id = NULL;
	peer_cfg_t *mediated_by = NULL;
	host_t *my_vip = NULL, *other_vip = NULL;
	certificate_t *cert;
	u_int32_t rekey = 0, reauth = 0, over, jitter;
	
	me = identification_create_from_string(msg->add_conn.me.id ?
						msg->add_conn.me.id : msg->add_conn.me.address);
	if (!me)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.me.id);
		return NULL;
	}
	other = identification_create_from_string(msg->add_conn.other.id ?
						msg->add_conn.other.id : msg->add_conn.other.address);
	if (!other)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.other.id);
		me->destroy(me);
		return NULL;
	}
	
	
#ifdef P2P
	if (msg->add_conn.p2p.mediation && msg->add_conn.p2p.mediated_by)
	{
		DBG1(DBG_CFG, "a mediation connection cannot be a"
				" mediated connection at the same time, aborting");
		me->destroy(me);
		other->destroy(other);
		return NULL;
	}
	
	if (msg->add_conn.p2p.mediated_by)
	{
		mediated_by = charon->backends->get_peer_cfg_by_name(charon->backends,
												msg->add_conn.p2p.mediated_by);
		if (!mediated_by)
		{
			DBG1(DBG_CFG, "mediation connection '%s' not found, aborting",
				 msg->add_conn.p2p.mediated_by);
			me->destroy(me);
			other->destroy(other);
			return NULL;
		}
		
		if (!mediated_by->is_mediation(mediated_by))
		{
			DBG1(DBG_CFG, "connection '%s' as referred to by '%s' is"
				 "no mediation connection, aborting", 
				msg->add_conn.p2p.mediated_by, msg->add_conn.name);
			mediated_by->destroy(mediated_by);
			me->destroy(me);
			other->destroy(other);
			return NULL;
		}
	}
	
	if (msg->add_conn.p2p.peerid)
	{
		peer_id = identification_create_from_string(msg->add_conn.p2p.peerid);
		if (!peer_id)
		{
			DBG1(DBG_CFG, "invalid peer ID: %s\n", msg->add_conn.p2p.peerid);
			mediated_by->destroy(mediated_by);
			me->destroy(me);
			other->destroy(other);
			return NULL;
		}
	}
	else
	{
		/* no peer ID supplied, assume right ID */
		peer_id = other_id->clone(other_id);
	}
#endif /* P2P */
	
	if (msg->add_conn.me.cert)
	{
		cert = this->cred->load_peer(this->cred, msg->add_conn.me.cert);
		if (cert)
		{
			me = update_peerid(cert, me);
			cert->destroy(cert);
		}
	}
	if (msg->add_conn.other.cert)
	{
		cert = this->cred->load_peer(this->cred, msg->add_conn.other.cert);
		if (cert)
		{
			other = update_peerid(cert, other);
			cert->destroy(cert);
		}
	}
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
	if (msg->add_conn.me.virtual_ip && msg->add_conn.me.sourceip)
	{
		my_vip = host_create_from_string(msg->add_conn.me.sourceip, 0);
	}
	if (msg->add_conn.other.virtual_ip && msg->add_conn.other.sourceip)
	{
		other_vip = host_create_from_string(msg->add_conn.other.sourceip, 0);
	}
	return peer_cfg_create(msg->add_conn.name,
		msg->add_conn.ikev2 ? 2 : 1, ike_cfg, me, other,
		msg->add_conn.me.sendcert, msg->add_conn.auth_method,
		msg->add_conn.eap_type,	msg->add_conn.eap_vendor,
		msg->add_conn.rekey.tries, rekey, reauth, jitter, over,
		msg->add_conn.mobike, msg->add_conn.dpd.delay, msg->add_conn.dpd.action,
		my_vip, other_vip, msg->add_conn.p2p.mediation, mediated_by, peer_id);
}

/**
 * fill in auth_info from stroke message
 */
static void build_auth_info(private_stroke_config_t *this,
							stroke_msg_t *msg, auth_info_t *auth)
{
	identification_t *my_ca = NULL, *other_ca = NULL;
	bool my_ca_same = FALSE;
	bool other_ca_same = FALSE;
	cert_validation_t valid;

	if (msg->add_conn.other.groups)
	{
		/* TODO: AC groups */
	}
	
	switch (msg->add_conn.crl_policy)
	{
		case CRL_STRICT_YES:
			valid = VALIDATION_GOOD;
			auth->add_item(auth, AUTHZ_CRL_VALIDATION, &valid);
			break;
		case CRL_STRICT_IFURI:
			valid = VALIDATION_SKIPPED;
			auth->add_item(auth, AUTHZ_CRL_VALIDATION, &valid);
			break;
		default:
			break;
	}
	
	if (msg->add_conn.me.ca)
	{
		if (streq(msg->add_conn.me.ca, "%same"))
		{
			my_ca_same = TRUE;
		}
		else
		{
			my_ca = identification_create_from_string(msg->add_conn.me.ca);
		}
	}
	if (msg->add_conn.other.ca)
	{
		if (streq(msg->add_conn.other.ca, "%same"))
		{
			other_ca_same = TRUE;
		}
		else
		{
			other_ca = identification_create_from_string(msg->add_conn.other.ca);
		}
	}
	if (other_ca_same && my_ca)
	{
		other_ca = my_ca->clone(my_ca);
	}
	else if (my_ca_same && other_ca)
	{
		my_ca = other_ca->clone(other_ca);
	}
	
	if (other_ca)
	{
		DBG2(DBG_CFG, "  other ca: %D", other_ca);
		certificate_t *cert = charon->credentials->get_cert(charon->credentials, 
									CERT_X509, KEY_ANY, other_ca, TRUE);
		if (cert)
		{
			auth->add_item(auth, AUTHZ_CA_CERT, cert);
			cert->destroy(cert);
		}
		else
		{
			auth->add_item(auth, AUTHZ_CA_CERT_NAME, other_ca);
		}
		other_ca->destroy(other_ca);
	}
	if (my_ca)
	{
		DBG2(DBG_CFG, "  my ca:    %D", my_ca);
		certificate_t *cert = charon->credentials->get_cert(charon->credentials, 
									CERT_X509, KEY_ANY, my_ca, TRUE);
		if (cert)
		{
			auth->add_item(auth, AUTHN_CA_CERT, cert);
			cert->destroy(cert);
		}
		else
		{
			auth->add_item(auth, AUTHN_CA_CERT_NAME, my_ca);
		}
		my_ca->destroy(my_ca);
	}
}

/**
 * build a traffic selector from a stroke_end
 */
static traffic_selector_t *build_ts(private_stroke_config_t *this,
									stroke_end_t *end)
{
	if (end->tohost)
	{
		return traffic_selector_create_dynamic(end->protocol,
					end->port ? end->port : 0, end->port ? end->port : 65535);
	}
	else
	{
		host_t *net;
		
		net = host_create_from_string(end->subnet ? end->subnet : end->address,
									  IKEV2_UDP_PORT);
		if (!net)
		{
			DBG1(DBG_CFG, "invalid subnet: %s", end->subnet);
			return NULL;
		}
		return traffic_selector_create_from_subnet(net,
				end->subnet ? end->subnet_mask : 0, end->protocol, end->port);
	}
}

/**
 * build a child config from the stroke message
 */
static child_cfg_t *build_child_cfg(private_stroke_config_t *this,
									stroke_msg_t *msg)
{
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;
	
	child_cfg = child_cfg_create(
				msg->add_conn.name, msg->add_conn.rekey.ipsec_lifetime,
				msg->add_conn.rekey.ipsec_lifetime - msg->add_conn.rekey.margin,
				msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100, 
				msg->add_conn.me.updown, msg->add_conn.me.hostaccess,
				msg->add_conn.mode);
	
	ts = build_ts(this, &msg->add_conn.me);
	if (!ts)
	{
		child_cfg->destroy(child_cfg);
		return NULL;
	}
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	
	ts = build_ts(this, &msg->add_conn.other);
	if (!ts)
	{
		child_cfg->destroy(child_cfg);
		return NULL;
	}
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	
	add_proposals(this, msg->add_conn.algorithms.esp, NULL, child_cfg);
	
	return child_cfg;
}

/**
 * Implementation of stroke_config_t.add.
 */
static void add(private_stroke_config_t *this, stroke_msg_t *msg)
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
	
	build_auth_info(this, msg, peer_cfg->get_auth(peer_cfg));
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
		DBG1(DBG_CFG, "added configuration '%s': %H[%D]...%H[%D]", msg->add_conn.name,
			 ike_cfg->get_my_host(ike_cfg), peer_cfg->get_my_id(peer_cfg),
			 ike_cfg->get_other_host(ike_cfg), peer_cfg->get_other_id(peer_cfg));
		this->mutex->lock(this->mutex);
		this->list->insert_last(this->list, peer_cfg);
		this->mutex->unlock(this->mutex);
	}
}

/**
 * Implementation of stroke_config_t.del.
 */
static void del(private_stroke_config_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator, *children;
	peer_cfg_t *peer;
	child_cfg_t *child;
	
	this->mutex->lock(this->mutex);
	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, (void**)&peer))
	{
		/* remove peer config with such a name */
		if (streq(peer->get_name(peer), msg->del_conn.name))
		{
			this->list->remove_at(this->list, enumerator);
			peer->destroy(peer);
			continue;
		}
		/* remove any child with such a name */
		children = peer->create_child_cfg_enumerator(peer);
		while (children->enumerate(children, &child))
		{
			if (streq(child->get_name(child), msg->del_conn.name))
			{
				peer->remove_child_cfg(peer, enumerator);
				child->destroy(child);
			}
		}
		children->destroy(children);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	
	DBG1(DBG_CFG, "deleted connection '%s'", msg->del_conn.name);
}

/**
 * Implementation of stroke_config_t.destroy
 */
static void destroy(private_stroke_config_t *this)
{
	this->list->destroy_offset(this->list, offsetof(peer_cfg_t, destroy));
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
stroke_config_t *stroke_config_create(stroke_cred_t *cred)
{
	private_stroke_config_t *this = malloc_thing(private_stroke_config_t);
	
	this->public.backend.create_peer_cfg_enumerator = (enumerator_t*(*)(backend_t*, identification_t *me, identification_t *other))create_peer_cfg_enumerator;
	this->public.backend.create_ike_cfg_enumerator = (enumerator_t*(*)(backend_t*, host_t *me, host_t *other))create_ike_cfg_enumerator;
	this->public.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	this->public.add = (void(*)(stroke_config_t*, stroke_msg_t *msg))add;
	this->public.del = (void(*)(stroke_config_t*, stroke_msg_t *msg))del;
	this->public.destroy = (void(*)(stroke_config_t*))destroy;
	
	this->list = linked_list_create();
	this->mutex = mutex_create(MUTEX_RECURSIVE);
	this->cred = cred;
	
	return &this->public;
}

