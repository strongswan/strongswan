/**
 * @file peer_cfg.h
 * 
 * @brief Interface of peer_cfg_t.
 *
 */

/*
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

#ifndef PEER_CFG_H_
#define PEER_CFG_H_

typedef enum dpd_action_t dpd_action_t;
typedef enum cert_policy_t cert_policy_t;
typedef struct peer_cfg_t peer_cfg_t;

#include <library.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <config/traffic_selector.h>
#include <config/proposal.h>
#include <config/ike_cfg.h>
#include <config/child_cfg.h>
#include <sa/authenticators/authenticator.h>
#include <sa/authenticators/eap/eap_method.h>

/**
 * Certificate sending policy. This is also used for certificate
 * requests when using this definition for the other peer. If
 * it is CERT_NEVER_SEND, a certreq is omitted, otherwise its
 * included.
 *
 * @ingroup config
 * 
 * @warning These definitions must be the same as in pluto/starter,
 * as they are sent over the stroke socket.
 */
enum cert_policy_t {
	/** always send certificates, even when not requested */
	CERT_ALWAYS_SEND   = 0,
	/** send certificate upon cert request */
	CERT_SEND_IF_ASKED = 1,
	/** never send a certificate, even when requested */
	CERT_NEVER_SEND    = 2,
};

/**
 * enum strings for cert_policy_t
 * 
 * @ingroup config
 */
extern enum_name_t *cert_policy_names;

/**
 * @brief Actions to take when a peer does not respond (dead peer detected).
 *
 * These values are the same as in pluto/starter, so do not modify them!
 *
 * @ingroup config
 */
enum dpd_action_t {
	/** DPD disabled */
	DPD_NONE,
	/** remove CHILD_SAs without replacement */
	DPD_CLEAR,
	/** route the CHILD_SAs to resetup when needed */
	DPD_ROUTE,
	/** restart CHILD_SAs in a new IKE_SA, immediately */
	DPD_RESTART,
};

/**
 * enum names for dpd_action_t.
 */
extern enum_name_t *dpd_action_names;

/**
 * @brief Configuration of a peer, specified by IDs.
 *
 * The peer config defines a connection between two given IDs. It contains
 * exactly one ike_cfg_t, which is use for initiation. Additionally, it contains
 * multiple child_cfg_t defining which CHILD_SAs are allowed for this peer.
 * @verbatim

                           +-------------------+           +---------------+
   +---------------+       |     peer_cfg      |         +---------------+ |
   |    ike_cfg    |       +-------------------+         |   child_cfg   | |
   +---------------+       | - ids             |         +---------------+ |
   | - hosts       | 1   1 | - cas             | 1     n | - proposals   | |
   | - proposals   |<------| - auth info       |-------->| - traffic sel | |
   | - ...         |       | - dpd config      |         | - ...         |-+
   +---------------+       | - ...             |         +---------------+
                           +-------------------+
   @endverbatim
 *
 * @b Constructors:
 *   - peer_cfg_create()
 *
 * @ingroup config
 */
struct peer_cfg_t {
	
	/**
	 * @brief Get the name of the peer_cfg.
	 * 
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				peer_cfg's name
	 */
	char* (*get_name) (peer_cfg_t *this);
	
	/**
	 * @brief Get the IKE version to use for initiating.
	 *
	 * @param this			calling object
	 * @return 				IKE major version
	 */
	u_int (*get_ike_version)(peer_cfg_t *this);
	
	/**
	 * @brief Get the IKE config to use for initiaton.
	 * 
	 * @param this			calling object
	 * @return				the IKE config to use
	 */
	ike_cfg_t* (*get_ike_cfg) (peer_cfg_t *this);
	
	/**
	 * @brief Attach a CHILD config.
	 * 
	 * @param this			calling object
	 * @param child_cfg		CHILD config to add
	 */
	void (*add_child_cfg) (peer_cfg_t *this, child_cfg_t *child_cfg);
	
	/**
	 * @brief Create an iterator for all attached CHILD configs.
	 * 
	 * @param this			calling object
	 * @return				an iterator over all CHILD configs.
	 */
	iterator_t* (*create_child_cfg_iterator) (peer_cfg_t *this);
	
	/**
	 * @brief Select a CHILD config from traffic selectors.
	 * 
	 * @param this			calling object
	 * @param my_ts			TS for local side
	 * @param other_ts		TS for remote side
	 * @param my_host		host to narrow down dynamic TS for local side
	 * @param other_host	host to narrow down dynamic TS for remote side
	 * @return				selected CHILD config, or NULL if no match found
	 */
	child_cfg_t* (*select_child_cfg) (peer_cfg_t *this, linked_list_t *my_ts,
									  linked_list_t *other_ts, host_t *my_host,
									  host_t *other_host);
	
	/**
	 * @brief Get own ID.
	 * 
	 * @param this			calling object
	 * @return				own id
	 */
	identification_t* (*get_my_id)(peer_cfg_t *this);
	
	/**
	 * @brief Get peers ID.
	 * 
	 * @param this			calling object
	 * @return				other id
	 */
	identification_t* (*get_other_id)(peer_cfg_t *this);
	
	/**
	 * @brief Get own CA.
	 * 
	 * @param this			calling object
	 * @return				own ca
	 */
	identification_t* (*get_my_ca)(peer_cfg_t *this);

	/**
	 * @brief Get peer CA.
	 * 
	 * @param this			calling object
	 * @return				other ca
	 */
	identification_t* (*get_other_ca)(peer_cfg_t *this);
	
	/**
	 * @brief Get list of group attributes.
	 * 
	 * @param this			calling object
	 * @return				linked list of group attributes
	 */
	linked_list_t* (*get_groups)(peer_cfg_t *this);

	/**
	 * @brief Should be sent a certificate for this connection?
	 *
	 * @param this		calling object
	 * @return			certificate sending policy
	 */
	cert_policy_t (*get_cert_policy) (peer_cfg_t *this);

	/**
	 * @brief Get the authentication method to use to authenticate us.
	 * 
	 * @param this		calling object
	 * @return			authentication method
	 */
	auth_method_t (*get_auth_method) (peer_cfg_t *this);
	
	/**
	 * @brief Get the EAP type to use for peer authentication.
	 * 
	 * @param this		calling object
	 * @return			authentication method
	 */
	eap_type_t (*get_eap_type) (peer_cfg_t *this);
	
	/**
	 * @brief Get the max number of retries after timeout.
	 *
	 * @param this		calling object
	 * @return			max number retries
	 */
	u_int32_t (*get_keyingtries) (peer_cfg_t *this);
	
	/**
	 * @brief Get the lifetime of a IKE_SA.
	 *
	 * If "rekey" is set to TRUE, a lifetime is returned before the first
	 * rekeying should be started. If it is FALSE, the actual lifetime is
	 * returned when the IKE_SA must be deleted.
	 * The rekey time automatically contains a jitter to avoid simlutaneous
	 * rekeying.
	 * 
	 * @param this			child_config 
	 * @param rekey			TRUE to get rekey time
	 * @return				lifetime in seconds
	 */
	u_int32_t (*get_lifetime) (peer_cfg_t *this, bool rekey);
	
	/**
	 * @brief Should a full reauthentication be done instead of rekeying?
	 * 
	 * @param this		calling object
	 * @return			TRUE to use full reauthentication
	 */
	bool (*use_reauth) (peer_cfg_t *this);
	
	/**
	 * @brief Use MOBIKE (RFC4555) if peer supports it?
	 * 
	 * @param this		calling object
	 * @return			TRUE to enable MOBIKE support
	 */
	bool (*use_mobike) (peer_cfg_t *this);
	
	/**
	 * @brief Get the DPD check interval.
	 * 
	 * @param this		calling object
	 * @return			dpd_delay in seconds
	 */
	u_int32_t (*get_dpd_delay) (peer_cfg_t *this);
	
	/**
	 * @brief What should be done with a CHILD_SA, when other peer does not respond.
	 *
	 * @param this 		calling object
	 * @return			dpd action
	 */	
	dpd_action_t (*get_dpd_action) (peer_cfg_t *this);
	
	/**
	 * @brief Get a virtual IP for the local peer.
	 *
	 * If no virtual IP should be used, NULL is returned. %any means to request
	 * a virtual IP using configuration payloads. A specific address is also
	 * used for a request and may be changed by the server.
	 *
	 * @param this			peer_cfg
	 * @param suggestion	NULL, %any or specific
	 * @return				clone of an IP, %any or NULL
	 */
	host_t* (*get_my_virtual_ip) (peer_cfg_t *this);
	
	/**
	 * @brief Get a virtual IP for the remote peer.
	 *
	 * An IP may be supplied, if one was requested by the initiator. However,
	 * the suggestion is not more as it says, any address may be returned, even
	 * NULL to not use virtual IPs.
	 *
	 * @param this			peer_cfg
	 * @param suggestion	NULL, %any or specific
	 * @return				clone of an IP to use
	 */
	host_t* (*get_other_virtual_ip) (peer_cfg_t *this, host_t *suggestion);
	
	/**
	 * @brief Get a new reference.
	 *
	 * Get a new reference to this peer_cfg by increasing
	 * it's internal reference counter.
	 * Do not call get_ref or any other function until you
	 * already have a reference. Otherwise the object may get
	 * destroyed while calling get_ref(),
	 * 
	 * @param this				calling object
	 */
	void (*get_ref) (peer_cfg_t *this);
	
	/**
	 * @brief Destroys the peer_cfg object.
	 *
	 * Decrements the internal reference counter and
	 * destroys the peer_cfg when it reaches zero.
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (peer_cfg_t *this);
};

/**
 * @brief Create a configuration object for IKE_AUTH and later.
 * 
 * name-string gets cloned, ID's not.
 * Virtual IPs are used if they are != NULL. A %any host means the virtual
 * IP should be obtained from the other peer.
 * Lifetimes are in seconds. To prevent to peers to start rekeying at the
 * same time, a jitter may be specified. Rekeying of an SA starts at
 * (rekeylifetime - random(0, jitter)). 
 * 
 * @param name				name of the peer_cfg
 * @param ike_version		which IKE version we sould use for this peer
 * @param ike_cfg			IKE config to use when acting as initiator
 * @param my_id 			identification_t for ourselves
 * @param other_id 			identification_t for the remote guy
 * @param my_ca				CA to use for us
 * @param other_ca			CA to use for other
 * @param groups			list of group memberships
 * @param cert_policy		should we send a certificate payload?
 * @param auth_method		auth method to use to authenticate us
 * @param eap_type			EAP type to use for peer authentication
 * @param keyingtries		how many keying tries should be done before giving up
 * @param lifetime			lifetime before deleting an SA
 * @param rekeytime			lifetime before rekeying an SA
 * @param jitter			range of random to substract from rekeytime
 * @param reauth			sould be done reauthentication instead of rekeying?
 * @param mobike			use MOBIKE (RFC4555) if peer supports it
 * @param dpd_delay			after how many seconds of inactivity to check DPD
 * @param dpd_action		what to do with CHILD_SAs when detected a dead peer
 * @param my_virtual_ip		virtual IP for local host, or NULL
 * @param other_virtual_ip	virtual IP for remote host, or NULL
 * @return 					peer_cfg_t object
 * 
 * @ingroup config
 */
peer_cfg_t *peer_cfg_create(char *name, u_int ikev_version, ike_cfg_t *ike_cfg,
							identification_t *my_id, identification_t *other_id,
							identification_t *my_ca, identification_t *other_ca,
							linked_list_t *groups, cert_policy_t cert_policy,
							auth_method_t auth_method, eap_type_t eap_type,
							u_int32_t keyingtries, u_int32_t lifetime,
							u_int32_t rekeytime, u_int32_t jitter,
							bool reauth, bool mobike,
							u_int32_t dpd_delay, dpd_action_t dpd_action,
							host_t *my_virtual_ip, host_t *other_virtual_ip);

#endif /* PEER_CFG_H_ */
