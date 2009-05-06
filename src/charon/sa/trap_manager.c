/*
 * Copyright (C) 2009 Martin Willi
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

#include "trap_manager.h"

#include <daemon.h>
#include <utils/mutex.h>
#include <utils/linked_list.h>


typedef struct private_trap_manager_t private_trap_manager_t;

/**
 * Private data of an trap_manager_t object.
 */
struct private_trap_manager_t {
	
	/**
	 * Public trap_manager_t interface.
	 */
	trap_manager_t public;
	
	/**
	 * Installed traps, as entry_t
	 */
	linked_list_t *traps;
	
	/**
	 * mutex to lock traps list
	 */
	mutex_t *mutex;
};

/**
 * A installed trap entry
 */
typedef struct {
	/** ref to peer_cfg to initiate */
	peer_cfg_t *peer_cfg;
	/** ref to instanciated CHILD_SA */
	child_sa_t *child_sa;
} entry_t;

/**
 * actually uninstall and destroy an installed entry
 */
static void destroy_entry(entry_t *entry)
{
	entry->child_sa->destroy(entry->child_sa);
	entry->peer_cfg->destroy(entry->peer_cfg);
	free(entry);
}

/**
 * Implementation of trap_manager_t.install
 */
static u_int install(private_trap_manager_t *this, peer_cfg_t *peer,
					 child_cfg_t *child)
{
	entry_t *entry;
	ike_cfg_t *ike_cfg;
	child_sa_t *child_sa;
	host_t *me, *other;
	linked_list_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	bool found = FALSE;
	status_t status;
	u_int reqid;
	
	/* check if not already done */
	this->mutex->lock(this->mutex);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(entry->child_sa->get_name(entry->child_sa),
				  child->get_name(child)))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	if (found)
	{
		DBG1(DBG_CFG, "CHILD_SA named '%s' already routed",
			 child->get_name(child));
		return 0;
	}
	
	/* try to resolve addresses */
	ike_cfg = peer->get_ike_cfg(peer);
	other = host_create_from_dns(ike_cfg->get_other_addr(ike_cfg), 
								 0, IKEV2_UDP_PORT);
	if (!other)
	{
		DBG1(DBG_CFG, "installing trap failed, remote address unknown");
		return 0;
	}
	me = host_create_from_dns(ike_cfg->get_my_addr(ike_cfg),
							  other->get_family(other), IKEV2_UDP_PORT);
	if (!me || me->is_anyaddr(me))
	{
		DESTROY_IF(me);
		me = charon->kernel_interface->get_source_addr(
									charon->kernel_interface, other, NULL);
		if (!me)
		{
			DBG1(DBG_CFG, "installing trap failed, local address unknown");
			other->destroy(other);
			return 0;
		}
		me->set_port(me, IKEV2_UDP_PORT);
	}
	
	/* create and route CHILD_SA */
	child_sa = child_sa_create(me, other, child, 0, FALSE);
	my_ts = child->get_traffic_selectors(child, TRUE, NULL, me);
	other_ts = child->get_traffic_selectors(child, FALSE, NULL, other);
	me->destroy(me);
	other->destroy(other);
	
	child_sa->set_mode(child_sa, child->get_mode(child));
	status = child_sa->add_policies(child_sa, my_ts, other_ts);
	my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
	other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
	if (status != SUCCESS)
	{
		child_sa->destroy(child_sa);
		DBG1(DBG_CFG, "installing trap failed");
		return 0;
	}
	
	reqid = child_sa->get_reqid(child_sa);
	entry = malloc_thing(entry_t);
	entry->child_sa = child_sa;
	entry->peer_cfg = peer->get_ref(peer);
	
	this->mutex->lock(this->mutex);
	this->traps->insert_last(this->traps, entry);
	this->mutex->unlock(this->mutex);
	
	return reqid;
}

/**
 * Implementation of trap_manager_t.uninstall
 */
static bool uninstall(private_trap_manager_t *this, u_int reqid)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;
	
	this->mutex->lock(this->mutex);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->child_sa->get_reqid(entry->child_sa) == reqid)
		{
			this->traps->remove_at(this->traps, enumerator);
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	
	if (!found)
	{
		DBG1(DBG_CFG, "trap %d not found to uninstall", reqid);
		return FALSE;
	}
	
	destroy_entry(found);
	return TRUE;
}

/**
 * convert enumerated entries to peer_cfg, child_sa
 */
static bool trap_filter(mutex_t *mutex, entry_t **entry, peer_cfg_t **peer_cfg,
						void *none, child_sa_t **child_sa)
{
	if (peer_cfg)
	{
		*peer_cfg = (*entry)->peer_cfg;
	}
	if (child_sa)
	{
		*child_sa = (*entry)->child_sa;
	}
	return TRUE;
}

/**
 * Implementation of trap_manager_t.create_enumerator
 */
static enumerator_t* create_enumerator(private_trap_manager_t *this)
{
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->traps->create_enumerator(this->traps),
									(void*)trap_filter, this->mutex,
									(void*)this->mutex->unlock);
}

/**
 * Implementation of trap_manager_t.acquire
 */
static void acquire(private_trap_manager_t *this, u_int reqid,
					traffic_selector_t *src, traffic_selector_t *dst)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;
	peer_cfg_t *peer;
	child_cfg_t *child;
	ike_sa_t *ike_sa;
	
	this->mutex->lock(this->mutex);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->child_sa->get_reqid(entry->child_sa) == reqid)
		{
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);
	
	if (!found)
	{
		DBG1(DBG_CFG, "trap not found, unable to acquire reqid %d",reqid);
		return;
	}
	
	child = found->child_sa->get_config(found->child_sa);
	peer = found->peer_cfg;
	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,	
														peer);
	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer);
	}
	child->get_ref(child);
	this->mutex->unlock(this->mutex);
	if (ike_sa->initiate(ike_sa, child) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of trap_manager_t.destroy.
 */
static void destroy(private_trap_manager_t *this)
{
	this->traps->invoke_function(this->traps, (void*)destroy_entry);
	this->traps->destroy(this->traps);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
trap_manager_t *trap_manager_create()
{
	private_trap_manager_t *this = malloc_thing(private_trap_manager_t);
	
	this->public.install = (u_int(*)(trap_manager_t*, peer_cfg_t *peer, child_cfg_t *child))install;
	this->public.uninstall = (bool(*)(trap_manager_t*, u_int id))uninstall;
	this->public.create_enumerator = (enumerator_t*(*)(trap_manager_t*))create_enumerator;
	this->public.acquire = (void(*)(trap_manager_t*, u_int reqid, traffic_selector_t *src, traffic_selector_t *dst))acquire;
	this->public.destroy = (void(*)(trap_manager_t*))destroy;
	
	this->traps = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	return &this->public;
}

