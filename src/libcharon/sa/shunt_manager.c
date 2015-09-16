/*
 * Copyright (C) 2015 Tobias Brunner
 * Copyright (C) 2011 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "shunt_manager.h"

#include <hydra.h>
#include <daemon.h>
#include <threading/rwlock.h>
#include <threading/rwlock_condvar.h>
#include <collections/linked_list.h>

#define INSTALL_DISABLED ((u_int)~0)

typedef struct private_shunt_manager_t private_shunt_manager_t;

/**
 * Private data of an shunt_manager_t object.
 */
struct private_shunt_manager_t {

	/**
	 * Public shunt_manager_t interface.
	 */
	shunt_manager_t public;

	/**
	 * Installed shunts, as child_cfg_t
	 */
	linked_list_t *shunts;

	/**
	 * Lock to safely access the list of shunts
	 */
	rwlock_t *lock;

	/**
	 * Number of threads currently installing shunts, or INSTALL_DISABLED
	 */
	u_int installing;

	/**
	 * Condvar to signal shunt installation
	 */
	rwlock_condvar_t *condvar;
};

/**
 * Install in and out shunt policies in the kernel
 */
static bool install_shunt_policy(child_cfg_t *child)
{
	enumerator_t *e_my_ts, *e_other_ts;
	linked_list_t *my_ts_list, *other_ts_list, *hosts;
	traffic_selector_t *my_ts, *other_ts;
	host_t *host_any, *host_any6;
	policy_type_t policy_type;
	policy_priority_t policy_prio;
	status_t status = SUCCESS;
	ipsec_sa_cfg_t sa = { .mode = MODE_TRANSPORT };

	switch (child->get_mode(child))
	{
		case MODE_PASS:
			policy_type = POLICY_PASS;
			policy_prio = POLICY_PRIORITY_PASS;
			break;
		case MODE_DROP:
			policy_type = POLICY_DROP;
			policy_prio = POLICY_PRIORITY_FALLBACK;
			break;
		default:
			return FALSE;
	}

	host_any = host_create_any(AF_INET);
	host_any6 = host_create_any(AF_INET6);

	hosts = linked_list_create_with_items(host_any, host_any6, NULL);
	my_ts_list =    child->get_traffic_selectors(child, TRUE,  NULL, hosts);
	other_ts_list = child->get_traffic_selectors(child, FALSE, NULL, hosts);
	hosts->destroy(hosts);

	/* enumerate pairs of traffic selectors */
	e_my_ts = my_ts_list->create_enumerator(my_ts_list);
	while (e_my_ts->enumerate(e_my_ts, &my_ts))
	{
		e_other_ts = other_ts_list->create_enumerator(other_ts_list);
		while (e_other_ts->enumerate(e_other_ts, &other_ts))
		{
			if (my_ts->get_type(my_ts) != other_ts->get_type(other_ts))
			{
				continue;
			}
			if (my_ts->get_protocol(my_ts) &&
				other_ts->get_protocol(other_ts) &&
				my_ts->get_protocol(my_ts) != other_ts->get_protocol(other_ts))
			{
				continue;
			}
			/* install out policy */
			status |= hydra->kernel_interface->add_policy(
								hydra->kernel_interface, host_any, host_any,
								my_ts, other_ts, POLICY_OUT, policy_type,
								&sa, child->get_mark(child, FALSE),
								policy_prio);

			/* install in policy */
			status |= hydra->kernel_interface->add_policy(
								hydra->kernel_interface, host_any, host_any,
								other_ts, my_ts, POLICY_IN, policy_type,
								&sa, child->get_mark(child, TRUE),
								policy_prio);

			/* install forward policy */
			status |= hydra->kernel_interface->add_policy(
								hydra->kernel_interface, host_any, host_any,
								other_ts, my_ts, POLICY_FWD, policy_type,
								&sa, child->get_mark(child, TRUE),
								policy_prio);
		}
		e_other_ts->destroy(e_other_ts);
	}
	e_my_ts->destroy(e_my_ts);

	my_ts_list->destroy_offset(my_ts_list,
							   offsetof(traffic_selector_t, destroy));
	other_ts_list->destroy_offset(other_ts_list,
							   offsetof(traffic_selector_t, destroy));
	host_any6->destroy(host_any6);
	host_any->destroy(host_any);

	return status == SUCCESS;
}

METHOD(shunt_manager_t, install, bool,
	private_shunt_manager_t *this, child_cfg_t *child)
{
	enumerator_t *enumerator;
	child_cfg_t *child_cfg;
	bool found = FALSE, success;

	/* check if not already installed */
	this->lock->write_lock(this->lock);
	if (this->installing == INSTALL_DISABLED)
	{	/* flush() has been called */
		this->lock->unlock(this->lock);
		return FALSE;
	}
	enumerator = this->shunts->create_enumerator(this->shunts);
	while (enumerator->enumerate(enumerator, &child_cfg))
	{
		if (streq(child_cfg->get_name(child_cfg), child->get_name(child)))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (found)
	{
		DBG1(DBG_CFG, "shunt %N policy '%s' already installed",
			 ipsec_mode_names, child->get_mode(child), child->get_name(child));
		this->lock->unlock(this->lock);
		return TRUE;
	}
	this->shunts->insert_last(this->shunts, child->get_ref(child));
	this->installing++;
	this->lock->unlock(this->lock);

	success = install_shunt_policy(child);

	this->lock->write_lock(this->lock);
	if (!success)
	{
		this->shunts->remove(this->shunts, child, NULL);
		child->destroy(child);
	}
	this->installing--;
	this->condvar->signal(this->condvar);
	this->lock->unlock(this->lock);
	return success;
}

/**
 * Uninstall in and out shunt policies in the kernel
 */
static void uninstall_shunt_policy(child_cfg_t *child)
{
	enumerator_t *e_my_ts, *e_other_ts;
	linked_list_t *my_ts_list, *other_ts_list, *hosts;
	traffic_selector_t *my_ts, *other_ts;
	host_t *host_any, *host_any6;
	policy_type_t policy_type;
	policy_priority_t policy_prio;
	status_t status = SUCCESS;
	ipsec_sa_cfg_t sa = { .mode = MODE_TRANSPORT };

	switch (child->get_mode(child))
	{
		case MODE_PASS:
			policy_type = POLICY_PASS;
			policy_prio = POLICY_PRIORITY_PASS;
			break;
		case MODE_DROP:
			policy_type = POLICY_DROP;
			policy_prio = POLICY_PRIORITY_FALLBACK;
			break;
		default:
			return;
	}

	host_any = host_create_any(AF_INET);
	host_any6 = host_create_any(AF_INET6);

	hosts = linked_list_create_with_items(host_any, host_any6, NULL);
	my_ts_list =    child->get_traffic_selectors(child, TRUE,  NULL, hosts);
	other_ts_list = child->get_traffic_selectors(child, FALSE, NULL, hosts);
	hosts->destroy(hosts);

	/* enumerate pairs of traffic selectors */
	e_my_ts = my_ts_list->create_enumerator(my_ts_list);
	while (e_my_ts->enumerate(e_my_ts, &my_ts))
	{
		e_other_ts = other_ts_list->create_enumerator(other_ts_list);
		while (e_other_ts->enumerate(e_other_ts, &other_ts))
		{
			if (my_ts->get_type(my_ts) != other_ts->get_type(other_ts))
			{
				continue;
			}
			if (my_ts->get_protocol(my_ts) &&
				other_ts->get_protocol(other_ts) &&
				my_ts->get_protocol(my_ts) != other_ts->get_protocol(other_ts))
			{
				continue;
			}
			/* uninstall out policy */
			status |= hydra->kernel_interface->del_policy(
							hydra->kernel_interface, host_any, host_any,
							my_ts, other_ts, POLICY_OUT, policy_type,
							&sa, child->get_mark(child, FALSE),
							policy_prio);

			/* uninstall in policy */
			status |= hydra->kernel_interface->del_policy(
							hydra->kernel_interface, host_any, host_any,
							other_ts, my_ts, POLICY_IN, policy_type,
							&sa, child->get_mark(child, TRUE),
							policy_prio);

			/* uninstall forward policy */
			status |= hydra->kernel_interface->del_policy(
							hydra->kernel_interface, host_any, host_any,
							other_ts, my_ts, POLICY_FWD, policy_type,
							&sa, child->get_mark(child, TRUE),
							policy_prio);
		}
		e_other_ts->destroy(e_other_ts);
	}
	e_my_ts->destroy(e_my_ts);

	my_ts_list->destroy_offset(my_ts_list,
							   offsetof(traffic_selector_t, destroy));
	other_ts_list->destroy_offset(other_ts_list,
							   offsetof(traffic_selector_t, destroy));
	host_any6->destroy(host_any6);
	host_any->destroy(host_any);

	if (status != SUCCESS)
	{
		DBG1(DBG_CFG, "uninstalling shunt %N 'policy %s' failed",
			 ipsec_mode_names, child->get_mode(child), child->get_name(child));
	}
}

METHOD(shunt_manager_t, uninstall, bool,
	private_shunt_manager_t *this, char *name)
{
	enumerator_t *enumerator;
	child_cfg_t *child, *found = NULL;

	this->lock->write_lock(this->lock);
	enumerator = this->shunts->create_enumerator(this->shunts);
	while (enumerator->enumerate(enumerator, &child))
	{
		if (streq(name, child->get_name(child)))
		{
			this->shunts->remove_at(this->shunts, enumerator);
			found = child;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!found)
	{
		return FALSE;
	}
	uninstall_shunt_policy(child);
	child->destroy(child);
	return TRUE;
}

METHOD(shunt_manager_t, create_enumerator, enumerator_t*,
	private_shunt_manager_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(
							this->shunts->create_enumerator(this->shunts),
							(void*)this->lock->unlock, this->lock);
}

METHOD(shunt_manager_t, flush, void,
	private_shunt_manager_t *this)
{
	child_cfg_t *child;

	this->lock->write_lock(this->lock);
	while (this->installing)
	{
		this->condvar->wait(this->condvar, this->lock);
	}
	while (this->shunts->remove_last(this->shunts, (void**)&child) == SUCCESS)
	{
		uninstall_shunt_policy(child);
		child->destroy(child);
	}
	this->installing = INSTALL_DISABLED;
	this->lock->unlock(this->lock);
}

METHOD(shunt_manager_t, destroy, void,
	private_shunt_manager_t *this)
{
	this->shunts->destroy_offset(this->shunts, offsetof(child_cfg_t, destroy));
	this->lock->destroy(this->lock);
	this->condvar->destroy(this->condvar);
	free(this);
}

/**
 * See header
 */
shunt_manager_t *shunt_manager_create()
{
	private_shunt_manager_t *this;

	INIT(this,
		.public = {
			.install = _install,
			.uninstall = _uninstall,
			.create_enumerator = _create_enumerator,
			.flush = _flush,
			.destroy = _destroy,
		},
		.shunts = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.condvar = rwlock_condvar_create(),
	);

	return &this->public;
}
