/**
 * @file peer_cfg.c
 * 
 * @brief Implementation of peer_cfg_t.
 * 
 */

/*
 * Copyright (C) 2007 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
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

#include <string.h>
#include <pthread.h>

#include "peer_cfg.h"

#include <utils/linked_list.h>
#include <utils/identification.h>
#include <crypto/ietf_attr_list.h>

ENUM(cert_policy_names, CERT_ALWAYS_SEND, CERT_NEVER_SEND,
	"CERT_ALWAYS_SEND",
	"CERT_SEND_IF_ASKED",
	"CERT_NEVER_SEND"
);

ENUM(dpd_action_names, DPD_NONE, DPD_RESTART,
	"DPD_NONE",
	"DPD_CLEAR",
	"DPD_ROUTE",
	"DPD_RESTART"
);

typedef struct private_peer_cfg_t private_peer_cfg_t;

/**
 * Private data of an peer_cfg_t object
 */
struct private_peer_cfg_t {

	/**
	 * Public part
	 */
	peer_cfg_t public;
	
	/**
	 * Number of references hold by others to this peer_cfg
	 */
	refcount_t refcount;
	
	/**
	 * Name of the peer_cfg, used to query it
	 */
	char *name;
	
	/**
	 * IKE version to use for initiation
	 */
	u_int ike_version;
	
	/**
	 * IKE config associated to this peer config
	 */
	ike_cfg_t *ike_cfg;
	
	/**
	 * list of child configs associated to this peer config
	 */
	linked_list_t *child_cfgs;
	
	/**
	 * mutex to lock access to list of child_cfgs
	 */
	pthread_mutex_t mutex;
	
	/**
	 * id to use to identify us
	 */
	identification_t *my_id;
	
	/**
	 * allowed id for other
	 */
	identification_t *other_id;
	
	/**
	 * we have a cert issued by this CA
	 */
	identification_t *my_ca;
	
	/**
	 * we require the other end to have a cert issued by this CA
	 */
	identification_t *other_ca;
	
	/**
	 * we require the other end to belong to at least one group
	 */
	linked_list_t *groups;
	
	/**
	 * should we send a certificate
	 */
	cert_policy_t cert_policy;
	
	/**
	 * Method to use for own authentication data
	 */
	auth_method_t auth_method;
	
	/**
	 * EAP type to use for peer authentication
	 */
	eap_type_t eap_type;
	
	/**
	 * EAP vendor ID if vendor specific type is used
	 */
	u_int32_t eap_vendor;
	
	/**
	 * number of tries after giving up if peer does not respond
	 */
	u_int32_t keyingtries;
	
	/**
	 * enable support for MOBIKE
	 */
	bool use_mobike;
	
	/**
	 * Time before starting rekeying
	 */
	u_int32_t rekey_time;
	
	/**
	 * Time before starting reauthentication
	 */
	u_int32_t reauth_time;
	
	/**
	 * Time, which specifies the range of a random value substracted from above.
	 */
	u_int32_t jitter_time;
	
	/**
	 * Delay before deleting a rekeying/reauthenticating SA
	 */
	u_int32_t over_time;
	
	/**
	 * What to do with an SA when other peer seams to be dead?
	 */
	bool dpd_delay;
	
	/**
	 * What to do with CHILDren when other peer seams to be dead?
	 */
	bool dpd_action;
	
	/**
	 * virtual IP to use locally
	 */
	host_t *my_virtual_ip;
	
	/**
	 * virtual IP to use remotly
	 */
	host_t *other_virtual_ip;

#ifdef P2P	
	/**
	 * Is this a mediation connection?
	 */
	bool p2p_mediation;
	
	/**
	 * Name of the mediation connection to mediate through
	 */
	peer_cfg_t *p2p_mediated_by;
	
	/**
	 * ID of our peer at the mediation server (= leftid of the peer's conn with
	 * the mediation server)
	 */
	identification_t *peer_id;
#endif /* P2P */
};

/**
 * Implementation of peer_cfg_t.get_name
 */
static char *get_name(private_peer_cfg_t *this)
{
	return this->name;
}

/**
 * Implementation of peer_cfg_t.get_ike_version
 */
static u_int get_ike_version(private_peer_cfg_t *this)
{
	return this->ike_version;
}

/**
 * Implementation of peer_cfg_t.get_ike_cfg
 */
static ike_cfg_t* get_ike_cfg(private_peer_cfg_t *this)
{
	return this->ike_cfg;
}

/**
 * Implementation of peer_cfg_t.add_child_cfg.
 */
static void add_child_cfg(private_peer_cfg_t *this, child_cfg_t *child_cfg)
{
	pthread_mutex_lock(&this->mutex);
	this->child_cfgs->insert_last(this->child_cfgs, child_cfg);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of peer_cfg_t.create_child_cfg_iterator.
 */
static iterator_t* create_child_cfg_iterator(private_peer_cfg_t *this)
{
	return this->child_cfgs->create_iterator_locked(this->child_cfgs,
													&this->mutex);
}

/**
 * Check if child_cfg contains traffic selectors
 */
static bool contains_ts(child_cfg_t *child, bool mine, linked_list_t *ts,
						host_t *host)
{
	linked_list_t *selected;
	bool contains = FALSE;
	
	selected = child->get_traffic_selectors(child, mine, ts, host);
	contains = selected->get_count(selected);
	selected->destroy_offset(selected, offsetof(traffic_selector_t, destroy));
	return contains;
}

/**
 * Implementation of peer_cfg_t.select_child_cfg
 */
static child_cfg_t* select_child_cfg(private_peer_cfg_t *this,
									 linked_list_t *my_ts,
									 linked_list_t *other_ts,
									 host_t *my_host, host_t *other_host)
{
	child_cfg_t *current, *found = NULL;
	iterator_t *iterator;
	
	iterator = create_child_cfg_iterator(this);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (contains_ts(current, TRUE, my_ts, my_host) &&
			contains_ts(current, FALSE, other_ts, other_host))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of peer_cfg_t.get_my_id
 */
static identification_t *get_my_id(private_peer_cfg_t *this)
{
	return this->my_id;
}

/**
 * Implementation of peer_cfg_t.get_other_id
 */
static identification_t *get_other_id(private_peer_cfg_t *this)
{
	return this->other_id;
}

/**
 * Implementation of peer_cfg_t.get_my_ca
 */
static identification_t *get_my_ca(private_peer_cfg_t *this)
{
	return this->my_ca;
}

/**
 * Implementation of peer_cfg_t.get_other_ca
 */
static identification_t *get_other_ca(private_peer_cfg_t *this)
{
	return this->other_ca;
}

/**
 * Implementation of peer_cfg_t.get_groups
 */
static linked_list_t *get_groups(private_peer_cfg_t *this)
{
	return this->groups;
}

/**
 * Implementation of peer_cfg_t.get_cert_policy.
 */
static cert_policy_t get_cert_policy(private_peer_cfg_t *this)
{
	return this->cert_policy;
}

/**
 * Implementation of connection_t.auth_method_t.
 */
static auth_method_t get_auth_method(private_peer_cfg_t *this)
{
	return this->auth_method;
}

/**
 * Implementation of connection_t.get_eap_type.
 */
static eap_type_t get_eap_type(private_peer_cfg_t *this, u_int32_t *vendor)
{
	*vendor = this->eap_vendor;
	return this->eap_type;
}

/**
 * Implementation of connection_t.get_keyingtries.
 */
static u_int32_t get_keyingtries(private_peer_cfg_t *this)
{
	return this->keyingtries;
}

/**
 * Implementation of peer_cfg_t.get_rekey_time.
 */
static u_int32_t get_rekey_time(private_peer_cfg_t *this)
{
	if (this->rekey_time == 0)
	{
		return 0;
	}
	if (this->jitter_time == 0)
	{
		return this->rekey_time;
	}
	return this->rekey_time - (random() % this->jitter_time);
}

/**
 * Implementation of peer_cfg_t.get_reauth_time.
 */
static u_int32_t get_reauth_time(private_peer_cfg_t *this)
{
	if (this->reauth_time == 0)
	{
		return 0;
	}
	if (this->jitter_time == 0)
	{
		return this->reauth_time;
	}
	return this->reauth_time - (random() % this->jitter_time);
}

/**
 * Implementation of peer_cfg_t.get_over_time.
 */
static u_int32_t get_over_time(private_peer_cfg_t *this)
{
	return this->over_time;
}

/**
 * Implementation of peer_cfg_t.use_mobike.
 */
static bool use_mobike(private_peer_cfg_t *this)
{
	return this->use_mobike;
}

/**
 * Implements peer_cfg_t.get_dpd_delay
 */
static u_int32_t get_dpd_delay(private_peer_cfg_t *this)
{
	return this->dpd_delay;
}

/**
 * Implements peer_cfg_t.get_dpd_action
 */
static dpd_action_t get_dpd_action(private_peer_cfg_t *this)
{
	return this->dpd_action;
}

/**
 * Implementation of peer_cfg_t.get_my_virtual_ip.
 */
static host_t* get_my_virtual_ip(private_peer_cfg_t *this)
{
	if (this->my_virtual_ip == NULL)
	{
		return NULL;
	}
	return this->my_virtual_ip->clone(this->my_virtual_ip);
}

/**
 * Implementation of peer_cfg_t.get_other_virtual_ip.
 */
static host_t* get_other_virtual_ip(private_peer_cfg_t *this, host_t *suggestion)
{
	if (this->other_virtual_ip == NULL)
	{	/* disallow */
		return NULL;
	}
	if (!this->other_virtual_ip->is_anyaddr(this->other_virtual_ip))
	{	/* force own configuration */
		return this->other_virtual_ip->clone(this->other_virtual_ip);
	}
	if (suggestion == NULL || suggestion->is_anyaddr(suggestion))
	{
		return NULL;
	}
	return suggestion->clone(suggestion);
}

#ifdef P2P
/**
 * Implementation of peer_cfg_t.is_mediation.
 */
static bool is_mediation(private_peer_cfg_t *this)
{
	return this->p2p_mediation;
}

/**
 * Implementation of peer_cfg_t.get_mediated_by.
 */
static peer_cfg_t* get_mediated_by(private_peer_cfg_t *this)
{
	if (this->p2p_mediated_by) {
		this->p2p_mediated_by->get_ref(this->p2p_mediated_by);
		return this->p2p_mediated_by;
	}
	return NULL;
}

/**
 * Implementation of peer_cfg_t.get_peer_id.
 */
static identification_t* get_peer_id(private_peer_cfg_t *this)
{
	return this->peer_id;
}
#endif /* P2P */

/**
 * Implements peer_cfg_t.get_ref.
 */
static void get_ref(private_peer_cfg_t *this)
{
	ref_get(&this->refcount);
}

/**
 * Implements peer_cfg_t.destroy.
 */
static void destroy(private_peer_cfg_t *this)
{
	if (ref_put(&this->refcount))
	{
		this->ike_cfg->destroy(this->ike_cfg);
		this->child_cfgs->destroy_offset(this->child_cfgs, offsetof(child_cfg_t, destroy));
		this->my_id->destroy(this->my_id);
		this->other_id->destroy(this->other_id);
		DESTROY_IF(this->my_ca);
		DESTROY_IF(this->other_ca);
		DESTROY_IF(this->my_virtual_ip);
		DESTROY_IF(this->other_virtual_ip);
#ifdef P2P
		DESTROY_IF(this->p2p_mediated_by);
		DESTROY_IF(this->peer_id);
#endif /* P2P */
		ietfAttr_list_destroy(this->groups);
		free(this->name);
		free(this);
	}
}

/*
 * Described in header-file
 */
peer_cfg_t *peer_cfg_create(char *name, u_int ike_version, ike_cfg_t *ike_cfg,
							identification_t *my_id, identification_t *other_id,
							identification_t *my_ca, identification_t *other_ca,
							linked_list_t *groups, cert_policy_t cert_policy,
							auth_method_t auth_method, eap_type_t eap_type,
							u_int32_t eap_vendor,
							u_int32_t keyingtries, u_int32_t rekey_time,
							u_int32_t reauth_time, u_int32_t jitter_time,
							u_int32_t over_time, bool mobike,
							u_int32_t dpd_delay, dpd_action_t dpd_action,
							host_t *my_virtual_ip, host_t *other_virtual_ip,
							bool p2p_mediation, peer_cfg_t *p2p_mediated_by,
							identification_t *peer_id)
{
	private_peer_cfg_t *this = malloc_thing(private_peer_cfg_t);

	/* public functions */
	this->public.get_name = (char* (*) (peer_cfg_t *))get_name;	
	this->public.get_ike_version = (u_int(*) (peer_cfg_t *))get_ike_version;	
	this->public.get_ike_cfg = (ike_cfg_t* (*) (peer_cfg_t *))get_ike_cfg;
	this->public.add_child_cfg = (void (*) (peer_cfg_t *, child_cfg_t*))add_child_cfg;
	this->public.create_child_cfg_iterator = (iterator_t* (*) (peer_cfg_t *))create_child_cfg_iterator;
	this->public.select_child_cfg = (child_cfg_t* (*) (peer_cfg_t *,linked_list_t*,linked_list_t*,host_t*,host_t*))select_child_cfg;
	this->public.get_my_id = (identification_t* (*)(peer_cfg_t*))get_my_id;
	this->public.get_other_id = (identification_t* (*)(peer_cfg_t *))get_other_id;
	this->public.get_my_ca = (identification_t* (*)(peer_cfg_t *))get_my_ca;
	this->public.get_other_ca = (identification_t* (*)(peer_cfg_t *))get_other_ca;
	this->public.get_groups = (linked_list_t* (*)(peer_cfg_t *))get_groups;
	this->public.get_cert_policy = (cert_policy_t (*) (peer_cfg_t *))get_cert_policy;
	this->public.get_auth_method = (auth_method_t (*) (peer_cfg_t *))get_auth_method;
	this->public.get_eap_type = (eap_type_t (*) (peer_cfg_t *,u_int32_t*))get_eap_type;
	this->public.get_keyingtries = (u_int32_t (*) (peer_cfg_t *))get_keyingtries;
	this->public.get_rekey_time = (u_int32_t(*)(peer_cfg_t*))get_rekey_time;
	this->public.get_reauth_time = (u_int32_t(*)(peer_cfg_t*))get_reauth_time;
	this->public.get_over_time = (u_int32_t(*)(peer_cfg_t*))get_over_time;
	this->public.use_mobike = (bool (*) (peer_cfg_t *))use_mobike;
	this->public.get_dpd_delay = (u_int32_t (*) (peer_cfg_t *))get_dpd_delay;
	this->public.get_dpd_action = (dpd_action_t (*) (peer_cfg_t *))get_dpd_action;
	this->public.get_my_virtual_ip = (host_t* (*) (peer_cfg_t *))get_my_virtual_ip;
	this->public.get_other_virtual_ip = (host_t* (*) (peer_cfg_t *, host_t *))get_other_virtual_ip;
	this->public.get_ref = (void(*)(peer_cfg_t *))get_ref;
	this->public.destroy = (void(*)(peer_cfg_t *))destroy;
#ifdef P2P	
	this->public.is_mediation = (bool (*) (peer_cfg_t *))is_mediation;
	this->public.get_mediated_by = (peer_cfg_t* (*) (peer_cfg_t *))get_mediated_by;
	this->public.get_peer_id = (identification_t* (*) (peer_cfg_t *))get_peer_id;
#endif /* P2P */
	
	/* apply init values */
	this->name = strdup(name);
	this->ike_version = ike_version;
	this->ike_cfg = ike_cfg;
	this->child_cfgs = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	this->my_id = my_id;
	this->other_id = other_id;
	this->my_ca = my_ca;
	this->other_ca = other_ca;
	this->groups = groups;
	this->cert_policy = cert_policy;
	this->auth_method = auth_method;
	this->eap_type = eap_type;
	this->eap_vendor = eap_vendor;
	this->keyingtries = keyingtries;
	this->rekey_time = rekey_time;
	this->reauth_time = reauth_time;
	if (rekey_time && jitter_time > rekey_time)
	{
		jitter_time = rekey_time;
	}
	if (reauth_time && jitter_time > reauth_time)
	{
		jitter_time = reauth_time;
	}
	this->jitter_time = jitter_time;
	this->over_time = over_time;
	this->use_mobike = mobike;
	this->dpd_delay = dpd_delay;
	this->dpd_action = dpd_action;
	this->my_virtual_ip = my_virtual_ip;
	this->other_virtual_ip = other_virtual_ip;
	this->refcount = 1;
#ifdef P2P
	this->p2p_mediation = p2p_mediation;
	this->p2p_mediated_by = p2p_mediated_by;
	this->peer_id = peer_id;
#endif /* P2P */

	return &this->public;
}
