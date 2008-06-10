/*
 * Copyright (C) 2007-2008 Tobias Brunner
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
 *
 * $Id$
 */

/**
 * @defgroup peer_cfg peer_cfg
 * @{ @ingroup config
 */

#ifndef PEER_CFG_H_
#define PEER_CFG_H_

typedef enum cert_policy_t cert_policy_t;
typedef enum unique_policy_t unique_policy_t;
typedef enum config_auth_method_t config_auth_method_t;
typedef struct peer_cfg_t peer_cfg_t;

#include <library.h>
#include <utils/identification.h>
#include <utils/enumerator.h>
#include <config/traffic_selector.h>
#include <config/proposal.h>
#include <config/ike_cfg.h>
#include <config/child_cfg.h>
#include <sa/authenticators/authenticator.h>
#include <sa/authenticators/eap/eap_method.h>
#include <credentials/auth_info.h>

/**
 * Certificate sending policy. This is also used for certificate
 * requests when using this definition for the other peer. If
 * it is CERT_NEVER_SEND, a certreq is omitted, otherwise its
 * included.
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
 */
extern enum_name_t *cert_policy_names;

/**
 * Uniqueness of an IKE_SA, used to drop multiple connections with one peer.
 */
enum unique_policy_t {
	/** do not check for client uniqueness */
	UNIQUE_NO,
	/** replace unique IKE_SAs if new ones get established */
	UNIQUE_REPLACE,
	/** keep existing IKE_SAs, close the new ones on connection attept */
	UNIQUE_KEEP,
};

/**
 * enum strings for unique_policy_t
 */
extern enum_name_t *unique_policy_names;

/**
 * Authentication method for this IKE_SA.
 */
enum config_auth_method_t {
	/** authentication using public keys (RSA, ECDSA) */
	CONF_AUTH_PUBKEY =	1,
	/** authentication using a pre-shared secret */
	CONF_AUTH_PSK = 	2,
	/** authentication using EAP */
	CONF_AUTH_EAP = 	3,
};

/**
 * enum strings for config_auth_method_t
 */
extern enum_name_t *config_auth_method_names;

/**
 * Configuration of a peer, specified by IDs.
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
                                     ^
                                     |
                           +-------------------+
                           |     auth_info     |
                           +-------------------+
                           |     auth_items    |
                           +-------------------+
   @endverbatim
 * The auth_info_t object associated to the peer_cfg holds additional
 * authorization constraints. A peer who wants to use a config needs to fullfil
 * the requirements defined in auth_info.
 */
struct peer_cfg_t {
	
	/**
	 * Get the name of the peer_cfg.
	 * 
	 * Returned object is not getting cloned.
	 * 
	 * @return				peer_cfg's name
	 */
	char* (*get_name) (peer_cfg_t *this);
	
	/**
	 * Get the IKE version to use for initiating.
	 *
	 * @return 				IKE major version
	 */
	u_int (*get_ike_version)(peer_cfg_t *this);
	
	/**
	 * Get the IKE config to use for initiaton.
	 * 
	 * @return				the IKE config to use
	 */
	ike_cfg_t* (*get_ike_cfg) (peer_cfg_t *this);
	
	/**
	 * Attach a CHILD config.
	 * 
	 * @param child_cfg		CHILD config to add
	 */
	void (*add_child_cfg) (peer_cfg_t *this, child_cfg_t *child_cfg);
	
	/**
	 * Detach a CHILD config, pointed to by an enumerator.
	 *
	 * @param enumerator	enumerator indicating element position
	 */
	void (*remove_child_cfg)(peer_cfg_t *this, enumerator_t *enumerator);
	
	/**
	 * Create an enumerator for all attached CHILD configs.
	 * 
	 * @return				an enumerator over all CHILD configs.
	 */
	enumerator_t* (*create_child_cfg_enumerator) (peer_cfg_t *this);
	
	/**
	 * Select a CHILD config from traffic selectors.
	 * 
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
	 * Get the authentication constraint items.
	 *
	 * @return				auth_info object to manipulate requirements
	 */
	auth_info_t* (*get_auth)(peer_cfg_t *this);
		
	/**
	 * Get own ID.
	 * 
	 * @return				own id
	 */
	identification_t* (*get_my_id)(peer_cfg_t *this);
	
	/**
	 * Get peers ID.
	 * 
	 * @return				other id
	 */
	identification_t* (*get_other_id)(peer_cfg_t *this);

	/**
	 * Should be sent a certificate for this connection?
	 *
	 * @return			certificate sending policy
	 */
	cert_policy_t (*get_cert_policy) (peer_cfg_t *this);

	/**
	 * How to handle uniqueness of IKE_SAs?
	 *
	 * @return			unique policy
	 */
	unique_policy_t (*get_unique_policy) (peer_cfg_t *this);

	/**
	 * Get the authentication method to use to authenticate us.
	 * 
	 * @return			authentication method
	 */
	config_auth_method_t (*get_auth_method) (peer_cfg_t *this);
	
	/**
	 * Get the EAP type to use for peer authentication.
	 *
	 * If vendor specific types are used, a vendor ID != 0 is returned to
	 * to vendor argument. Then the returned type is specific for that 
	 * vendor ID.
	 * 
	 * @param vendor	receives vendor specifier, 0 for predefined EAP types
	 * @return			authentication method
	 */
	eap_type_t (*get_eap_type) (peer_cfg_t *this, u_int32_t *vendor);
	
	/**
	 * Get the max number of retries after timeout.
	 *
	 * @return			max number retries
	 */
	u_int32_t (*get_keyingtries) (peer_cfg_t *this);
	
	/**
	 * Get a time to start rekeying (is randomized with jitter).
	 *
	 * @return			time in s when to start rekeying, 0 disables rekeying
	 */
	u_int32_t (*get_rekey_time)(peer_cfg_t *this);
	
	/**
	 * Get a time to start reauthentication (is randomized with jitter).
	 *
	 * @return			time in s when to start reauthentication, 0 disables it
	 */
	u_int32_t (*get_reauth_time)(peer_cfg_t *this);
	
	/**
	 * Get the timeout of a rekeying/reauthenticating SA.
	 *
	 * @return			timeout in s
	 */
	u_int32_t (*get_over_time)(peer_cfg_t *this);
	
	/**
	 * Use MOBIKE (RFC4555) if peer supports it?
	 * 
	 * @return			TRUE to enable MOBIKE support
	 */
	bool (*use_mobike) (peer_cfg_t *this);
	
	/**
	 * Get the DPD check interval.
	 * 
	 * @return			dpd_delay in seconds
	 */
	u_int32_t (*get_dpd) (peer_cfg_t *this);
	
	/**
	 * Get a virtual IP for the local peer.
	 *
	 * If no virtual IP should be used, NULL is returned. %any means to request
	 * a virtual IP using configuration payloads. A specific address is also
	 * used for a request and may be changed by the server.
	 *
	 * @param suggestion	NULL, %any or specific
	 * @return				virtual IP, %any or NULL
	 */
	host_t* (*get_virtual_ip) (peer_cfg_t *this);
	
	/**
	 * Get the name of the pool to acquire configuration attributes from.
	 *
	 * @return				pool name, NULL if none defined
	 */
	char* (*get_pool)(peer_cfg_t *this);
	
#ifdef ME
	/**
	 * Is this a mediation connection?
	 * 
	 * @return				TRUE, if this is a mediation connection
	 */
	bool (*is_mediation) (peer_cfg_t *this);
	
	/**
	 * Get peer_cfg of the connection this one is mediated through.
	 * 
	 * @return				the peer_cfg of the mediation connection
	 */
	peer_cfg_t* (*get_mediated_by) (peer_cfg_t *this);
	
	/**
	 * Get the id of the other peer at the mediation server.
	 * 
	 * This is the leftid of the peer's connection with the mediation server.
	 * 
	 * If it is not configured, it is assumed to be the same as the right id
	 * of this connection. 
	 * 
	 * @return				the id of the other peer
	 */
	identification_t* (*get_peer_id) (peer_cfg_t *this);
#endif /* ME */

	/**
	 * Check if two peer configurations are equal.
	 *
	 * This method does not compare associated ike/child_cfg.
	 *
	 * @param other			candidate to check for equality against this
	 * @return				TRUE if peer_cfg and ike_cfg are equal
	 */
	bool (*equals)(peer_cfg_t *this, peer_cfg_t *other);
	
	/**
	 * Increase reference count.
	 *
	 * @return				reference to this
	 */
	peer_cfg_t* (*get_ref) (peer_cfg_t *this);
	
	/**
	 * Destroys the peer_cfg object.
	 *
	 * Decrements the internal reference counter and
	 * destroys the peer_cfg when it reaches zero.
	 */
	void (*destroy) (peer_cfg_t *this);
};

/**
 * Create a configuration object for IKE_AUTH and later.
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
 * @param cert_policy		should we send a certificate payload?
 * @param unique			uniqueness of an IKE_SA
 * @param auth_method		auth method to use to authenticate us
 * @param eap_type			EAP type to use for peer authentication
 * @param eap_vendor		EAP vendor identifier, if vendor specific type is used
 * @param keyingtries		how many keying tries should be done before giving up
 * @param rekey_time		timeout before starting rekeying
 * @param reauth_time		timeout before starting reauthentication
 * @param jitter_time		timerange to randomly substract from rekey/reauth time
 * @param over_time			maximum overtime before closing a rekeying/reauth SA
 * @param reauth			sould be done reauthentication instead of rekeying?
 * @param mobike			use MOBIKE (RFC4555) if peer supports it
 * @param dpd				DPD check interval, 0 to disable
 * @param virtual_ip		virtual IP for local host, or NULL
 * @param pool				pool name to get configuration attributes from, or NULL
 * @param mediation			TRUE if this is a mediation connection
 * @param mediated_by		peer_cfg_t of the mediation connection to mediate through
 * @param peer_id			ID that identifies our peer at the mediation server
 * @return 					peer_cfg_t object
 */
peer_cfg_t *peer_cfg_create(char *name, u_int ikev_version, ike_cfg_t *ike_cfg,
							identification_t *my_id, identification_t *other_id,
							cert_policy_t cert_policy, unique_policy_t unique,
							config_auth_method_t auth_method, eap_type_t eap_type,
							u_int32_t eap_vendor,
							u_int32_t keyingtries, u_int32_t rekey_time,
							u_int32_t reauth_time, u_int32_t jitter_time,
							u_int32_t over_time, bool mobike, u_int32_t dpd,
							host_t *virtual_ip, char *pool,
							bool mediation, peer_cfg_t *mediated_by,
							identification_t *peer_id);

#endif /* PEER_CFG_H_ @} */
