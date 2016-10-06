/*
 * Copyright (C) 2016 Andreas Steffen
 * Copyright (C) 2008-2016 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

/**
 * @defgroup child_cfg child_cfg
 * @{ @ingroup config
 */

#ifndef CHILD_CFG_H_
#define CHILD_CFG_H_

typedef enum action_t action_t;
typedef struct child_cfg_t child_cfg_t;
typedef struct child_cfg_create_t child_cfg_create_t;

#include <library.h>
#include <selectors/traffic_selector.h>
#include <config/proposal.h>
#include <kernel/kernel_ipsec.h>

/**
 * Action to take when connection is loaded, DPD is detected or
 * connection gets closed by peer.
 */
enum action_t {
	/** No action */
	ACTION_NONE,
	/** Route config to establish or reestablish on demand */
	ACTION_ROUTE,
	/** Start or restart config immediately */
	ACTION_RESTART,
};

/**
 * enum names for action_t.
 */
extern enum_name_t *action_names;

/**
 * A child_cfg_t defines the config template for a CHILD_SA.
 *
 * After creation, proposals and traffic selectors may be added to the config.
 * A child_cfg object is referenced multiple times, and is not thread save.
 * Reading from the object is save, adding things is not allowed while other
 * threads may access the object.
 * A reference counter handles the number of references hold to this config.
 *
 * @see peer_cfg_t to get an overview over the configurations.
 */
struct child_cfg_t {

	/**
	 * Get the name of the child_cfg.
	 *
	 * @return				child_cfg's name
	 */
	char *(*get_name) (child_cfg_t *this);

	/**
	 * Add a proposal to the list.
	 *
	 * The proposals are stored by priority, first added
	 * is the most preferred. It is safe to add NULL as proposal, which has no
	 * effect. After add, proposal is owned by child_cfg.
	 *
	 * @param proposal		proposal to add, or NULL
	 */
	void (*add_proposal) (child_cfg_t *this, proposal_t *proposal);

	/**
	 * Get the list of proposals for the CHILD_SA.
	 *
	 * Resulting list and all of its proposals must be freed after use.
	 *
	 * @param strip_dh		TRUE strip out diffie hellman groups
	 * @return				list of proposals
	 */
	linked_list_t* (*get_proposals)(child_cfg_t *this, bool strip_dh);

	/**
	 * Select a proposal from a supplied list.
	 *
	 * Returned propsal is newly created and must be destroyed after usage.
	 *
	 * @param proposals		list from which proposals are selected
	 * @param strip_dh		TRUE strip out diffie hellman groups
	 * @param private		accept algorithms from a private range
	 * @param prefer_self	whether to prefer configured or supplied proposals
	 * @return				selected proposal, or NULL if nothing matches
	 */
	proposal_t* (*select_proposal)(child_cfg_t*this, linked_list_t *proposals,
								   bool strip_dh, bool private,
								   bool prefer_self);

	/**
	 * Add a traffic selector to the config.
	 *
	 * Use the "local" parameter to add it for the local or the remote side.
	 * After add, traffic selector is owned by child_cfg.
	 *
	 * @param local			TRUE for local side, FALSE for remote
	 * @param ts			traffic_selector to add
	 */
	void (*add_traffic_selector)(child_cfg_t *this, bool local,
								 traffic_selector_t *ts);

	/**
	 * Get a list of traffic selectors to use for the CHILD_SA.
	 *
	 * The config contains two set of traffic selectors, one for the local
	 * side, one for the remote side.
	 * If a list with traffic selectors is supplied, these are used to narrow
	 * down the traffic selector list to the greatest common divisor.
	 * Some traffic selector may be "dymamic", meaning they are narrowed down
	 * to a specific address (host-to-host or virtual-IP setups). Use
	 * the "host" parameter to narrow such traffic selectors to that address.
	 * Resulted list and its traffic selectors must be destroyed after use.
	 *
	 * @param local			TRUE for TS on local side, FALSE for remote
	 * @param supplied		list with TS to select from, or NULL
	 * @param hosts			addresses to use for narrowing "dynamic" TS', host_t
	 * @return				list containing the traffic selectors
	 */
	linked_list_t *(*get_traffic_selectors)(child_cfg_t *this, bool local,
											linked_list_t *supplied,
											linked_list_t *hosts);
	/**
	 * Get the updown script to run for the CHILD_SA.
	 *
	 * @return				path to updown script
	 */
	char* (*get_updown)(child_cfg_t *this);

	/**
	 * Should we allow access to the local host (gateway)?
	 *
	 * @return				value of hostaccess flag
	 */
	bool (*get_hostaccess) (child_cfg_t *this);

	/**
	 * Get the lifetime configuration of a CHILD_SA.
	 *
	 * The rekey limits automatically contain a jitter to avoid simultaneous
	 * rekeying. These values will change with each call to this function.
	 *
	 * @param jitter		subtract jitter value to randomize lifetimes
	 * @return				lifetime_cfg_t (has to be freed)
	 */
	lifetime_cfg_t* (*get_lifetime) (child_cfg_t *this, bool jitter);

	/**
	 * Get the mode to use for the CHILD_SA.
	 *
	 * The mode is either tunnel, transport or BEET. The peer must agree
	 * on the method, fallback is tunnel mode.
	 *
	 * @return				ipsec mode
	 */
	ipsec_mode_t (*get_mode) (child_cfg_t *this);

	/**
	 * Action to take to start CHILD_SA.
	 *
	 * @return				start action
	 */
	action_t (*get_start_action) (child_cfg_t *this);

	/**
	 * Action to take on DPD.
	 *
	 * @return				DPD action
	 */
	action_t (*get_dpd_action) (child_cfg_t *this);

	/**
	 * Action to take if CHILD_SA gets closed.
	 *
	 * @return				close action
	 */
	action_t (*get_close_action) (child_cfg_t *this);

	/**
	 * Get the DH group to use for CHILD_SA setup.
	 *
	 * @return				dh group to use
	 */
	diffie_hellman_group_t (*get_dh_group)(child_cfg_t *this);

	/**
	 * Check whether IPComp should be used, if the other peer supports it.
	 *
	 * @return				TRUE, if IPComp should be used
	 *						FALSE, otherwise
	 */
	bool (*use_ipcomp)(child_cfg_t *this);

	/**
	 * Get the inactivity timeout value.
	 *
	 * @return				inactivity timeout in s
	 */
	uint32_t (*get_inactivity)(child_cfg_t *this);

	/**
	 * Specific reqid to use for CHILD_SA.
	 *
	 * @return				reqid
	 */
	uint32_t (*get_reqid)(child_cfg_t *this);

	/**
	 * Optional mark for CHILD_SA.
	 *
	 * @param inbound		TRUE for inbound, FALSE for outbound
	 * @return				mark
	 */
	mark_t (*get_mark)(child_cfg_t *this, bool inbound);

	/**
	 * Get the TFC padding value to use for CHILD_SA.
	 *
	 * @return				TFC padding, 0 to disable, -1 for MTU
	 */
	uint32_t (*get_tfc)(child_cfg_t *this);

	/**
	 * Get optional manually-set IPsec policy priority
	 *
	 * @return				manually-set IPsec policy priority (automatic if 0)
	 */
	uint32_t (*get_manual_prio)(child_cfg_t *this);

	/**
	 * Get optional network interface restricting IPsec policy
	 *
	 * @return				network interface)
	 */
	char* (*get_interface)(child_cfg_t *this);

	/**
	 * Get anti-replay window size
	 *
	 * @return				anti-replay window size
	 */
	uint32_t (*get_replay_window)(child_cfg_t *this);

	/**
	 * Set anti-replay window size
	 *
	 * @param window		anti-replay window size
	 */
	void (*set_replay_window)(child_cfg_t *this, uint32_t window);

	/**
	 * Check whether IPsec transport SA should be set up in proxy mode.
	 *
	 * @return				TRUE, if proxy mode should be used
	 *						FALSE, otherwise
	 */
	bool (*use_proxy_mode)(child_cfg_t *this);

	/**
	 * Check whether IPsec policies should be installed in the kernel.
	 *
	 * @return				TRUE, if IPsec kernel policies should be installed
	 *						FALSE, otherwise
	 */
	bool (*install_policy)(child_cfg_t *this);

	/**
	 * Check whether outbound FWD IPsec policies should be installed.
	 *
	 * @return				TRUE, if outbound FWD policies should be installed
	 *						FALSE, otherwise
	 */
	bool (*install_fwd_out_policy)(child_cfg_t *this);

	/**
	 * Check if two child_cfg objects are equal.
	 *
	 * @param other			candidate to check for equality against this
	 * @return				TRUE if equal
	 */
	bool (*equals)(child_cfg_t *this, child_cfg_t *other);

	/**
	 * Increase the reference count.
	 *
	 * @return				reference to this
	 */
	child_cfg_t* (*get_ref) (child_cfg_t *this);

	/**
	 * Destroys the child_cfg object.
	 *
	 * Decrements the internal reference counter and
	 * destroys the child_cfg when it reaches zero.
	 */
	void (*destroy) (child_cfg_t *this);
};


/**
 * Data passed to the constructor of a child_cfg_t object.
 */
struct child_cfg_create_t {
	/** Specific reqid to use for CHILD_SA, 0 for auto assignment */
	uint32_t reqid;
	/** Optional inbound mark */
	mark_t mark_in;
	/** Optional outbound mark */
	mark_t mark_out;
	/** Mode to propose for CHILD_SA */
	ipsec_mode_t mode;
	/** Use IPsec transport proxy mode */
	bool proxy_mode;
	/** Use IPComp, if peer supports it */
	bool ipcomp;
	/** TFC padding size, 0 to disable, -1 to pad to PMTU */
	uint32_t tfc;
	/** Optional manually-set IPsec policy priority */
	uint32_t priority;
	/** Optional network interface restricting IPsec policy (cloned) */
	char *interface;
	/** lifetime_cfg_t for this child_cfg */
	lifetime_cfg_t lifetime;
	/** Inactivity timeout in s before closing a CHILD_SA */
	uint32_t inactivity;
	/** Start action */
	action_t start_action;
	/** DPD action */
	action_t dpd_action;
	/** Close action */
	action_t close_action;
	/** updown script to execute on up/down event (cloned) */
	char *updown;
	/** TRUE to allow access to the local host */
	bool hostaccess;
	/** Don't install IPsec policies */
	bool suppress_policies;
	/** Install outbound FWD IPsec policies to bypass drop policies */
	bool fwd_out_policies;
};

/**
 * Create a configuration template for CHILD_SA setup.
 *
 * After a call to create, a reference is obtained (refcount = 1).
 *
 * @param name				name of the child_cfg (cloned)
 * @param data				data for this child_cfg
 * @return					child_cfg_t object
 */
child_cfg_t *child_cfg_create(char *name, child_cfg_create_t *data);

#endif /** CHILD_CFG_H_ @}*/
