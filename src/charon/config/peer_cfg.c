/*
 * Copyright (C) 2007-2008 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
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

#include "peer_cfg.h"

#include <daemon.h>

#include <utils/mutex.h>
#include <utils/linked_list.h>
#include <utils/identification.h>

ENUM(cert_policy_names, CERT_ALWAYS_SEND, CERT_NEVER_SEND,
	"CERT_ALWAYS_SEND",
	"CERT_SEND_IF_ASKED",
	"CERT_NEVER_SEND",
);

ENUM(unique_policy_names, UNIQUE_NO, UNIQUE_KEEP,
	"UNIQUE_NO",
	"UNIQUE_REPLACE",
	"UNIQUE_KEEP",
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
	mutex_t *mutex;
	
	/**
	 * should we send a certificate
	 */
	cert_policy_t cert_policy;
	
	/**
	 * uniqueness of an IKE_SA
	 */
	unique_policy_t unique;
	
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
	 * DPD check intervall
	 */
	u_int32_t dpd;
	
	/**
	 * virtual IP to use locally
	 */
	host_t *virtual_ip;
	
	/**
	 * pool to acquire configuration attributes from
	 */
	char *pool;
	
	/**
	 * local authentication configs (rulesets)
	 */
	linked_list_t *local_auth;
	
	/**
	 * remote authentication configs (constraints)
	 */
	linked_list_t *remote_auth;
	
#ifdef ME	
	/**
	 * Is this a mediation connection?
	 */
	bool mediation;
	
	/**
	 * Name of the mediation connection to mediate through
	 */
	peer_cfg_t *mediated_by;
	
	/**
	 * ID of our peer at the mediation server (= leftid of the peer's conn with
	 * the mediation server)
	 */
	identification_t *peer_id;
#endif /* ME */
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
	this->mutex->lock(this->mutex);
	this->child_cfgs->insert_last(this->child_cfgs, child_cfg);
	this->mutex->unlock(this->mutex);
}

/**
 * child_cfg enumerator
 */
typedef struct {
	enumerator_t public;
	enumerator_t *wrapped;
	mutex_t *mutex;
} child_cfg_enumerator_t;

/**
 * Implementation of peer_cfg_t.remove_child_cfg.
 */
static void remove_child_cfg(private_peer_cfg_t *this,
							 child_cfg_enumerator_t *enumerator)
{
	this->child_cfgs->remove_at(this->child_cfgs, enumerator->wrapped);
}

/**
 * Implementation of child_cfg_enumerator_t.destroy
 */
static void child_cfg_enumerator_destroy(child_cfg_enumerator_t *this)
{
	this->mutex->unlock(this->mutex);
	this->wrapped->destroy(this->wrapped);
	free(this);
}

/**
 * Implementation of child_cfg_enumerator_t.enumerate
 */
static bool child_cfg_enumerate(child_cfg_enumerator_t *this, child_cfg_t **chd)
{
	return this->wrapped->enumerate(this->wrapped, chd);
}

/**
 * Implementation of peer_cfg_t.create_child_cfg_enumerator.
 */
static enumerator_t* create_child_cfg_enumerator(private_peer_cfg_t *this)
{
	child_cfg_enumerator_t *enumerator = malloc_thing(child_cfg_enumerator_t);
	
	enumerator->public.enumerate = (void*)child_cfg_enumerate;
	enumerator->public.destroy = (void*)child_cfg_enumerator_destroy;
	enumerator->mutex = this->mutex;
	enumerator->wrapped = this->child_cfgs->create_enumerator(this->child_cfgs);
	
	this->mutex->lock(this->mutex);
	return &enumerator->public;
}

/**
 * Check how good a list of TS matches a given child config
 */
static int get_ts_match(child_cfg_t *cfg, bool local,
						linked_list_t *sup_list, host_t *host)
{
	linked_list_t *cfg_list;
	enumerator_t *sup_enum, *cfg_enum;
	traffic_selector_t *sup_ts, *cfg_ts;
	int match = 0, round;
	
	/* fetch configured TS list, narrowing dynamic TS */
	cfg_list = cfg->get_traffic_selectors(cfg, local, NULL, host);
	
	/* use a round counter to rate leading TS with higher priority */
	round = sup_list->get_count(sup_list);
	
	sup_enum = sup_list->create_enumerator(sup_list);
	while (sup_enum->enumerate(sup_enum, &sup_ts))
	{
		cfg_enum = cfg_list->create_enumerator(cfg_list);
		while (cfg_enum->enumerate(cfg_enum, &cfg_ts))
		{
			if (cfg_ts->equals(cfg_ts, sup_ts))
			{	/* equality is honored better than matches */
				match += round * 5;
			}
			else if (cfg_ts->is_contained_in(cfg_ts, sup_ts) ||
					 sup_ts->is_contained_in(sup_ts, cfg_ts))
			{
				match += round * 1;
			}
		}
		cfg_enum->destroy(cfg_enum);
		round--;
	}
	sup_enum->destroy(sup_enum);
	
	cfg_list->destroy_offset(cfg_list, offsetof(traffic_selector_t, destroy));
	
	return match;
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
	enumerator_t *enumerator;
	int best = 0;
	
	DBG2(DBG_CFG, "looking for a child config for %#R=== %#R", my_ts, other_ts);
	enumerator = create_child_cfg_enumerator(this);
	while (enumerator->enumerate(enumerator, &current))
	{
		int my_prio, other_prio;
		
		my_prio = get_ts_match(current, TRUE, my_ts, my_host);
		other_prio = get_ts_match(current, FALSE, other_ts, other_host);
		
		if (my_prio && other_prio)
		{
			DBG2(DBG_CFG, "  candidate \"%s\" with prio %d+%d",
				 current->get_name(current), my_prio, other_prio);
			if (my_prio + other_prio > best)
			{
				best = my_prio + other_prio;
				DESTROY_IF(found);
				found = current->get_ref(current);
			}
		}
	}
	enumerator->destroy(enumerator);
	if (found)
	{
		DBG2(DBG_CFG, "found matching child config \"%s\" with prio %d",
			 found->get_name(found), best);
	}
	return found;
}

/**
 * Implementation of peer_cfg_t.get_cert_policy.
 */
static cert_policy_t get_cert_policy(private_peer_cfg_t *this)
{
	return this->cert_policy;
}

/**
 * Implementation of peer_cfg_t.get_unique_policy.
 */
static unique_policy_t get_unique_policy(private_peer_cfg_t *this)
{
	return this->unique;
}

/**
 * Implementation of peer_cfg_t.get_keyingtries.
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
 * Implements peer_cfg_t.get_dpd
 */
static u_int32_t get_dpd(private_peer_cfg_t *this)
{
	return this->dpd;
}

/**
 * Implementation of peer_cfg_t.get_virtual_ip.
 */
static host_t* get_virtual_ip(private_peer_cfg_t *this)
{
	return this->virtual_ip;
}
	
/**
 * Implementation of peer_cfg_t.get_pool.
 */
static char* get_pool(private_peer_cfg_t *this)
{
	return this->pool;
}

/**
 * Implementation of peer_cfg_t.add_auth_cfg
 */
static void add_auth_cfg(private_peer_cfg_t *this,
						 auth_cfg_t *cfg, bool local)
{
	if (local)
	{
		this->local_auth->insert_last(this->local_auth, cfg);
	}
	else
	{
		this->remote_auth->insert_last(this->remote_auth, cfg);
	}
}

/**
 * Implementation of peer_cfg_t.create_auth_cfg_enumerator
 */
static enumerator_t* create_auth_cfg_enumerator(private_peer_cfg_t *this,
												 bool local)
{
	if (local)
	{
		return this->local_auth->create_enumerator(this->local_auth);
	}
	return this->remote_auth->create_enumerator(this->remote_auth);
}

#ifdef ME
/**
 * Implementation of peer_cfg_t.is_mediation.
 */
static bool is_mediation(private_peer_cfg_t *this)
{
	return this->mediation;
}

/**
 * Implementation of peer_cfg_t.get_mediated_by.
 */
static peer_cfg_t* get_mediated_by(private_peer_cfg_t *this)
{
	return this->mediated_by;
}

/**
 * Implementation of peer_cfg_t.get_peer_id.
 */
static identification_t* get_peer_id(private_peer_cfg_t *this)
{
	return this->peer_id;
}
#endif /* ME */

/**
 * check auth configs for equality
 */
static bool auth_cfg_equal(private_peer_cfg_t *this, private_peer_cfg_t *other)
{
	enumerator_t *e1, *e2;
	auth_cfg_t *cfg1, *cfg2;
	bool equal = TRUE;
	
	if (this->local_auth->get_count(this->local_auth) !=
		other->local_auth->get_count(other->local_auth))
	{
		return FALSE;
	}
	if (this->remote_auth->get_count(this->remote_auth) !=
		other->remote_auth->get_count(other->remote_auth))
	{
		return FALSE;
	}
	
	e1 = this->local_auth->create_enumerator(this->local_auth);
	e2 = other->local_auth->create_enumerator(other->local_auth);
	while (e1->enumerate(e1, &cfg1) && e2->enumerate(e2, &cfg2))
	{
		if (!cfg1->equals(cfg1, cfg2))
		{
			equal = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);
	
	if (!equal)
	{
		return FALSE;
	}
	
	e1 = this->remote_auth->create_enumerator(this->remote_auth);
	e2 = other->remote_auth->create_enumerator(other->remote_auth);
	while (e1->enumerate(e1, &cfg1) && e2->enumerate(e2, &cfg2))
	{
		if (!cfg1->equals(cfg1, cfg2))
		{
			equal = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);
	
	return equal;
}

/**
 * Implementation of peer_cfg_t.equals.
 */
static bool equals(private_peer_cfg_t *this, private_peer_cfg_t *other)
{
	if (this == other)
	{
		return TRUE;
	}
	if (this->public.equals != other->public.equals)
	{
		return FALSE;
	}
	
	return (
		this->ike_version == other->ike_version &&
		this->cert_policy == other->cert_policy &&
		this->unique == other->unique &&
		this->keyingtries == other->keyingtries &&
		this->use_mobike == other->use_mobike &&
		this->rekey_time == other->rekey_time &&
		this->reauth_time == other->reauth_time &&
		this->jitter_time == other->jitter_time &&
		this->over_time == other->over_time &&
		this->dpd == other->dpd &&
		(this->virtual_ip == other->virtual_ip ||
		 (this->virtual_ip && other->virtual_ip &&
		  this->virtual_ip->equals(this->virtual_ip, other->virtual_ip))) &&
		(this->pool == other->pool || 
		 (this->pool && other->pool && streq(this->pool, other->pool))) &&
		auth_cfg_equal(this, other)
#ifdef ME
		&& this->mediation == other->mediation &&
		this->mediated_by == other->mediated_by &&
		(this->peer_id == other->peer_id ||
		 (this->peer_id && other->peer_id &&
		  this->peer_id->equals(this->peer_id, other->peer_id)))
#endif /* ME */
		);
}

/**
 * Implements peer_cfg_t.get_ref.
 */
static peer_cfg_t* get_ref(private_peer_cfg_t *this)
{
	ref_get(&this->refcount);
	return &this->public;
}

/**
 * Implements peer_cfg_t.destroy.
 */
static void destroy(private_peer_cfg_t *this)
{
	if (ref_put(&this->refcount))
	{
		this->ike_cfg->destroy(this->ike_cfg);
		this->child_cfgs->destroy_offset(this->child_cfgs,
										offsetof(child_cfg_t, destroy));
		DESTROY_IF(this->virtual_ip);
		this->local_auth->destroy_offset(this->local_auth,
										offsetof(auth_cfg_t, destroy));
		this->remote_auth->destroy_offset(this->remote_auth,
										offsetof(auth_cfg_t, destroy));
#ifdef ME
		DESTROY_IF(this->mediated_by);
		DESTROY_IF(this->peer_id);
#endif /* ME */
		this->mutex->destroy(this->mutex);
		free(this->name);
		free(this->pool);
		free(this);
	}
}

/*
 * Described in header-file
 */
peer_cfg_t *peer_cfg_create(char *name, u_int ike_version, ike_cfg_t *ike_cfg,
							cert_policy_t cert_policy, unique_policy_t unique,
							u_int32_t keyingtries, u_int32_t rekey_time,
							u_int32_t reauth_time, u_int32_t jitter_time,
							u_int32_t over_time, bool mobike, u_int32_t dpd,
							host_t *virtual_ip, char *pool,
							bool mediation, peer_cfg_t *mediated_by,
							identification_t *peer_id)
{
	private_peer_cfg_t *this = malloc_thing(private_peer_cfg_t);

	/* public functions */
	this->public.get_name = (char* (*) (peer_cfg_t *))get_name;	
	this->public.get_ike_version = (u_int(*) (peer_cfg_t *))get_ike_version;	
	this->public.get_ike_cfg = (ike_cfg_t* (*) (peer_cfg_t *))get_ike_cfg;
	this->public.add_child_cfg = (void (*) (peer_cfg_t *, child_cfg_t*))add_child_cfg;
	this->public.remove_child_cfg = (void(*)(peer_cfg_t*, enumerator_t*))remove_child_cfg;
	this->public.create_child_cfg_enumerator = (enumerator_t* (*) (peer_cfg_t *))create_child_cfg_enumerator;
	this->public.select_child_cfg = (child_cfg_t* (*) (peer_cfg_t *,linked_list_t*,linked_list_t*,host_t*,host_t*))select_child_cfg;
	this->public.get_cert_policy = (cert_policy_t (*) (peer_cfg_t *))get_cert_policy;
	this->public.get_unique_policy = (unique_policy_t (*) (peer_cfg_t *))get_unique_policy;
	this->public.get_keyingtries = (u_int32_t (*) (peer_cfg_t *))get_keyingtries;
	this->public.get_rekey_time = (u_int32_t(*)(peer_cfg_t*))get_rekey_time;
	this->public.get_reauth_time = (u_int32_t(*)(peer_cfg_t*))get_reauth_time;
	this->public.get_over_time = (u_int32_t(*)(peer_cfg_t*))get_over_time;
	this->public.use_mobike = (bool (*) (peer_cfg_t *))use_mobike;
	this->public.get_dpd = (u_int32_t (*) (peer_cfg_t *))get_dpd;
	this->public.get_virtual_ip = (host_t* (*) (peer_cfg_t *))get_virtual_ip;
	this->public.get_pool = (char*(*)(peer_cfg_t*))get_pool;
	this->public.add_auth_cfg = (void(*)(peer_cfg_t*, auth_cfg_t *cfg, bool local))add_auth_cfg;
	this->public.create_auth_cfg_enumerator = (enumerator_t*(*)(peer_cfg_t*, bool local))create_auth_cfg_enumerator;
	this->public.equals = (bool(*)(peer_cfg_t*, peer_cfg_t *other))equals;
	this->public.get_ref = (peer_cfg_t*(*)(peer_cfg_t *))get_ref;
	this->public.destroy = (void(*)(peer_cfg_t *))destroy;
#ifdef ME
	this->public.is_mediation = (bool (*) (peer_cfg_t *))is_mediation;
	this->public.get_mediated_by = (peer_cfg_t* (*) (peer_cfg_t *))get_mediated_by;
	this->public.get_peer_id = (identification_t* (*) (peer_cfg_t *))get_peer_id;
#endif /* ME */
	
	/* apply init values */
	this->name = strdup(name);
	this->ike_version = ike_version;
	this->ike_cfg = ike_cfg;
	this->child_cfgs = linked_list_create();
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->cert_policy = cert_policy;
	this->unique = unique;
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
	this->dpd = dpd;
	this->virtual_ip = virtual_ip;
	this->pool = pool ? strdup(pool) : NULL;
	this->local_auth = linked_list_create();
	this->remote_auth = linked_list_create();
	this->refcount = 1;
#ifdef ME
	this->mediation = mediation;
	this->mediated_by = mediated_by;
	this->peer_id = peer_id;
#else /* ME */
	DESTROY_IF(mediated_by);
	DESTROY_IF(peer_id);
#endif /* ME */

	return &this->public;
}
