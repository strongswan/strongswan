/*
 * Copyright (C) 2008-2009 Tobias Brunner
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

/**
 * @defgroup child_cfg child_cfg
 * @{ @ingroup config
 */

#ifndef CHILD_CFG_H_
#define CHILD_CFG_H_

typedef enum action_t action_t;
typedef enum ipcomp_transform_t ipcomp_transform_t;
typedef struct lifetime_cfg_t lifetime_cfg_t;
typedef struct child_cfg_t child_cfg_t;

#include <library.h>
#include <selectors/traffic_selector.h>
#include <config/proposal.h>
#include <kernel/kernel_ipsec.h>

/**
 * Action to take when DPD detected/connection gets closed by peer.
 */
enum action_t {
	/** No action */
	ACTION_NONE,
	/** Route config to reestablish on demand */
	ACTION_ROUTE,
	/** Restart config immediately */
	ACTION_RESTART,
};

/**
 * enum names for action_t.
 */
extern enum_name_t *action_names;

/**
 * IPComp transform IDs, as in RFC 4306
 */
enum ipcomp_transform_t {
	IPCOMP_NONE = 241,
	IPCOMP_OUI = 1,
	IPCOMP_DEFLATE = 2,
	IPCOMP_LZS = 3,
	IPCOMP_LZJH = 4,
};

/**
 * enum strings for ipcomp_transform_t.
 */
extern enum_name_t *ipcomp_transform_names;

/**
 * A lifetime_cfg_t defines the lifetime limits of a CHILD_SA.
 *
 * Set any of these values to 0 to ignore.
 */
struct lifetime_cfg_t {
	struct {
		/** Limit before the CHILD_SA gets invalid. */
		u_int64_t	life;
		/** Limit before the CHILD_SA gets rekeyed. */
		u_int64_t	rekey;
		/** The range of a random value subtracted from rekey. */
		u_int64_t	jitter;
	} time, bytes, packets;
};

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
	 * is the most prefered.
	 * After add, proposal is owned by child_cfg.
	 *
	 * @param proposal		proposal to add
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
	 * @param proposals		list from from wich proposals are selected
	 * @param strip_dh		TRUE strip out diffie hellman groups
	 * @param private		accept algorithms from a private range
	 * @return				selected proposal, or NULL if nothing matches
	 */
	proposal_t* (*select_proposal)(child_cfg_t*this, linked_list_t *proposals,
								   bool strip_dh, bool private);

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
	 * @param host			address to use for narrowing "dynamic" TS', or NULL
	 * @return				list containing the traffic selectors
	 */
	linked_list_t *(*get_traffic_selectors)(child_cfg_t *this, bool local,
											linked_list_t *supplied,
											host_t *host);
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
	 * @return				lifetime_cfg_t (has to be freed)
	 */
	lifetime_cfg_t* (*get_lifetime) (child_cfg_t *this);

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
	 * 						FALSE, otherwise
	 */
	bool (*use_ipcomp)(child_cfg_t *this);

	/**
	 * Get the inactivity timeout value.
	 *
	 * @return				inactivity timeout in s
	 */
	u_int32_t (*get_inactivity)(child_cfg_t *this);

	/**
	 * Sets two options needed for Mobile IPv6 interoperability
	 *
	 * @param proxy_mode	use IPsec transport proxy mode (default FALSE)
	 * @param install_policy install IPsec kernel policies (default TRUE)
	 */
	void (*set_mipv6_options)(child_cfg_t *this, bool proxy_mode,
												 bool install_policy);

	/**
	 * Check whether IPsec transport SA should be set up in proxy mode
	 *
	 * @return				TRUE, if proxy mode should be used
	 * 						FALSE, otherwise
	 */
	bool (*use_proxy_mode)(child_cfg_t *this);

	/**
	 * Check whether IPsec policies should be installed in the kernel
	 *
	 * @return				TRUE, if IPsec kernel policies should be installed
	 * 						FALSE, otherwise
	 */
	bool (*install_policy)(child_cfg_t *this);

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
 * Create a configuration template for CHILD_SA setup.
 *
 * The "name" string gets cloned.
 *
 * The lifetime_cfg_t object gets cloned.
 * To prevent two peers to start rekeying at the same time, a jitter may be
 * specified. Rekeying of an SA starts at (x.rekey - random(0, x.jitter)).
 *
 * After a call to create, a reference is obtained (refcount = 1).
 *
 * @param name				name of the child_cfg
 * @param lifetime			lifetime_cfg_t for this child_cfg
 * @param updown			updown script to execute on up/down event
 * @param hostaccess		TRUE to allow access to the local host
 * @param mode				mode to propose for CHILD_SA, transport, tunnel or BEET
 * @param dpd_action		DPD action
 * @param close_action		close action
 * @param ipcomp			use IPComp, if peer supports it
 * @param inactivity		inactivity timeout in s before closing a CHILD_SA
 * @return 					child_cfg_t object
 */
child_cfg_t *child_cfg_create(char *name, lifetime_cfg_t *lifetime,
							  char *updown, bool hostaccess,
							  ipsec_mode_t mode, action_t dpd_action,
							  action_t close_action, bool ipcomp,
							  u_int32_t inactivity);

#endif /** CHILD_CFG_H_ @}*/
