/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

#include "ipsec_policy_mgr.h"
#include "ipsec_policy.h"

#include <debug.h>
#include <library.h>
#include <ipsec/ipsec_types.h>
#include <selectors/traffic_selector.h>
#include <threading/rwlock.h>
#include <utils/host.h>
#include <utils/linked_list.h>

typedef struct private_ipsec_policy_mgr_t private_ipsec_policy_mgr_t;

/**
 * Private additions to ipsec_policy_mgr_t.
 */
struct private_ipsec_policy_mgr_t {

	/**
	 * Public members of ipsec_policy_mgr_t.
	 */
	ipsec_policy_mgr_t public;

	/**
	 * Installed policies
	 */
	linked_list_t *policies;

	/**
	 * Lock to safely access policies
	 */
	rwlock_t *lock;

};

static bool match_policy(ipsec_policy_t *policy, ipsec_policy_t *other_policy)
{
	return policy->match(policy, other_policy->get_source_ts(other_policy),
						 other_policy->get_destination_ts(other_policy),
						 other_policy->get_direction(other_policy),
						 other_policy->get_reqid(other_policy),
						 (mark_t){ .value = 0, },
						 other_policy->get_priority(other_policy));
}

METHOD(ipsec_policy_mgr_t, add_policy, status_t,
	private_ipsec_policy_mgr_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa, mark_t mark,
	policy_priority_t priority)
{
	ipsec_policy_t *policy;

	policy = ipsec_policy_create(src, dst, src_ts, dst_ts, direction, type, sa,
								 mark, priority);
	this->lock->write_lock(this->lock);
	if (this->policies->find_first(this->policies, (void*)match_policy,
								   NULL, policy) != SUCCESS)
	{
		this->policies->insert_last(this->policies, policy);
	}
	else
	{
		policy->destroy(policy);
	}
	this->lock->unlock(this->lock);
	return SUCCESS;
}

METHOD(ipsec_policy_mgr_t, del_policy, status_t,
	private_ipsec_policy_mgr_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t priority)
{
	enumerator_t *enumerator;
	ipsec_policy_t *current, *found = NULL;

	this->lock->write_lock(this->lock);
	enumerator = this->policies->create_enumerator(this->policies);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current->match(current, src_ts, dst_ts, direction, reqid,
						   mark, priority))
		{
			this->policies->remove_at(this->policies, enumerator);
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	if (found)
	{
		found->destroy(found);
		return SUCCESS;
	}
	return FAILED;
}

METHOD(ipsec_policy_mgr_t, flush_policies, status_t,
	private_ipsec_policy_mgr_t *this)
{
	ipsec_policy_t *policy;

	DBG2(DBG_ESP, "flushing policies");

	this->lock->write_lock(this->lock);
	while (this->policies->remove_last(this->policies,
									  (void**)&policy) == SUCCESS)
	{
		policy->destroy(policy);
	}
	this->lock->unlock(this->lock);
	return SUCCESS;
}

METHOD(ipsec_policy_mgr_t, destroy, void,
	private_ipsec_policy_mgr_t *this)
{
	flush_policies(this);
	this->policies->destroy(this->policies);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * Described in header.
 */
ipsec_policy_mgr_t *ipsec_policy_mgr_create()
{
	private_ipsec_policy_mgr_t *this;

	INIT(this,
		.public = {
			.add_policy = _add_policy,
			.del_policy = _del_policy,
			.flush_policies = _flush_policies,
			.destroy = _destroy,
		},
		.policies = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
