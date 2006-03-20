/**
 * @file connection.h
 * 
 * @brief Interface of connection_t.
 *  
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <types.h>
#include <network/host.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <config/proposal.h>
#include <transforms/diffie_hellman.h>


typedef enum auth_method_t auth_method_t;

/**
 * AUTH Method to use.
 * 
 * @ingroup config
 */
enum auth_method_t {
	/**
	 * Computed as specified in section 2.15 of RFC using 
	 * an RSA private key over a PKCS#1 padded hash.
	 */
	RSA_DIGITAL_SIGNATURE = 1,
	
	/** 
	 * Computed as specified in section 2.15 of RFC using the 
	 * shared key associated with the identity in the ID payload 
	 * and the negotiated prf function
	 */
	SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
	
	/**
	 * Computed as specified in section 2.15 of RFC using a 
	 * DSS private key over a SHA-1 hash.
	 */
	DSS_DIGITAL_SIGNATURE = 3,
};

/**
 * string mappings for auth method.
 * 
 * @ingroup config
 */
extern mapping_t auth_method_m[];


typedef struct connection_t connection_t;

/**
 * @brief A connection_t defines the rules to set up an IKE_SA.
 *
 *
 * @b Constructors:
 *  - connection_create()
 * 
 * @ingroup config
 */
struct connection_t {

	/**
	 * @brief Get my ID for this connection.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as identification_t object
	 */
	identification_t *(*get_my_id) (connection_t *this);

	/**
	 * @brief Get others ID for this connection.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as identification_t object
	 */
	identification_t *(*get_other_id) (connection_t *this);

	/**
	 * @brief Get my address as host_t object.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_my_host) (connection_t *this);

	/**
	 * @brief Get others address as host_t object.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_other_host) (connection_t *this);

	/**
	 * @brief Update address of my host.
	 * 
	 * It may be necessary to uptdate own address, as it 
	 * is set to the default route (0.0.0.0) in some cases.
	 * Old host is destroyed, new one NOT cloned.
	 * 
	 * @param this		calling object
	 * @param my_host	new host to set as my_host
	 */
	void (*update_my_host) (connection_t *this, host_t *my_host);

	/**
	 * @brief Update address of remote host.
	 * 
	 * It may be necessary to uptdate remote address, as a
	 * connection may define %any (0.0.0.0) or a subnet.
	 * Old host is destroyed, new one NOT cloned.
	 * 
	 * @param this		calling object
	 * @param my_host	new host to set as other_host
	 */
	void (*update_other_host) (connection_t *this, host_t *other_host);
	
	/**
	 * @brief Returns a list of all supported proposals.
	 * 
	 * Returned list is still owned by connection and MUST NOT
	 * modified or destroyed.
	 * 
	 * @param this				calling object
	 * @return 					list containing all the proposals
	 */
	linked_list_t *(*get_proposals) (connection_t *this);
	
	/**
	 * @brief Adds a proposal to the list..
	 * 
	 * The first added proposal has the highest priority, the last
	 * added the lowest.
	 * 
	 * @param this				calling object
	 * @param proposal			proposal to add
	 */
	void (*add_proposal) (connection_t *this, proposal_t *proposal);
	
	/**
	 * @brief Select a proposed from suggested proposals.
	 * 
	 * Returned proposal must be destroyed after usage.
	 * 
	 * @param this					calling object
	 * @param proposals				list of proposals to select from
	 * @return						selected proposal, or NULL if none matches.
	 */
	proposal_t *(*select_proposal) (connection_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Get the authentication method to use
	 * 
	 * @param this			calling object
	 * @return				authentication method
	 */
	auth_method_t (*get_auth_method) (connection_t *this);
	
	/**
	 * @brief Get the DH group to use for connection initialization.
	 * 
	 * @param this					calling object
	 * @return						dh group to use for initialization
	 */
	diffie_hellman_group_t (*get_dh_group) (connection_t *this);
	
	/**
	 * @brief Check if a suggested dh group is acceptable.
	 * 
	 * If we guess a wrong DH group for IKE_SA_INIT, the other
	 * peer will send us a offer. But is this acceptable for us?
	 * 
	 * @param this					calling object
	 * @return						TRUE if group acceptable
	 */
	bool (*check_dh_group) (connection_t *this, diffie_hellman_group_t dh_group);
	
	/**
	 * @brief Clone a connection_t object.
	 * 
	 * @param this	connection to clone
	 * @return		clone of it
	 */
	connection_t *(*clone) (connection_t *this);
	
	/**
	 * @brief Destroys a connection_t object.
	 * 
	 * @param this	calling object
	 */
	void (*destroy) (connection_t *this);
};

/**
 * @brief Creates a connection_t object.
 * 
 * Supplied hosts/IDs become owned by connection, so 
 * do not modify or destroy them after a call to 
 * connection_create().
 * 
 * @param my_host		host_t representing local address
 * @param other_host	host_t representing remote address
 * @param my_id			identification_t for me
 * @param other_id		identification_t for other
 * @param auth_method	Authentication method to use for our(!) auth data
 * @return 				connection_t object.
 * 
 * @ingroup config
 */
connection_t * connection_create(host_t *my_host, host_t *other_host,
								 identification_t *my_id, 
								 identification_t *other_id,
								 auth_method_t auth_method);

#endif /* CONNECTION_H_ */
