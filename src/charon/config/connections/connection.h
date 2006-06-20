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
#include <utils/host.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <config/proposal.h>
#include <crypto/diffie_hellman.h>


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


typedef enum cert_policy_t cert_policy_t;

/**
 * Certificate sending policy. This is also used for certificate
 * requests when using this definition for the other peer. If
 * it is CERT_NEVER_SEND, a certreq is ommited, otherwise its
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
 * string mappings for certpolicy_t.
 * 
 * @ingroup config
 */
extern mapping_t cert_policy_m[];


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
	 * @param this		calling object
	 * @return 			list containing all the proposals
	 */
	linked_list_t *(*get_proposals) (connection_t *this);
	
	/**
	 * @brief Adds a proposal to the list.
	 * 
	 * The first added proposal has the highest priority, the last
	 * added the lowest.
	 * 
	 * @param this		calling object
	 * @param proposal	proposal to add
	 */
	void (*add_proposal) (connection_t *this, proposal_t *proposal);
	
	/**
	 * @brief Select a proposed from suggested proposals.
	 * 
	 * Returned proposal must be destroyed after usage.
	 * 
	 * @param this		calling object
	 * @param proposals	list of proposals to select from
	 * @return			selected proposal, or NULL if none matches.
	 */
	proposal_t *(*select_proposal) (connection_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Get the authentication method to use
	 * 
	 * @param this		calling object
	 * @return			authentication method
	 */
	auth_method_t (*get_auth_method) (connection_t *this);
	
	/**
	 * @brief Get the connection name.
	 * 
	 * Name must not be freed, since it points to 
	 * internal data.
	 * 
	 * @param this		calling object
	 * @return			name of the connection
	 */
	char* (*get_name) (connection_t *this);
	
	/**
	 * @brief Check if the connection is marked as an IKEv2 connection.
	 * 
	 * Since all connections (IKEv1+2) are loaded, but charon handles 
	 * only those marked with IKEv2, this flag can tell us if we must
	 * ignore a connection on initiaton. Then pluto will do it for us.
	 * 
	 * @param this		calling object
	 * @return			- TRUE, if this is an IKEv2 connection
	 */
	bool (*is_ikev2) (connection_t *this);
	
	/**
	 * @brief Should be sent a certificate request for this connection?
	 *
	 * A certificate request contains serials of our trusted CA certificates.
	 * This flag says if such a request is sent on connection setup to
	 * the peer. It should be ommited when CERT_SEND_NEVER, sended otherwise.
	 *
	 * @param this		calling object
	 * @return			- TRUE, if certificate request should be sent
	 */
	cert_policy_t (*get_cert_req_policy) (connection_t *this);
	
	/**
	 * @brief Should be sent a certificate for this connection?
	 *
	 * Return the policy used to send the certificate.
	 *
	 * @param this		calling object
	 * @return			certificate sending policy
	 */
	cert_policy_t (*get_cert_policy) (connection_t *this);
	
	/**
	 * @brief Get the DH group to use for connection initialization.
	 * 
	 * @param this		calling object
	 * @return			dh group to use for initialization
	 */
	diffie_hellman_group_t (*get_dh_group) (connection_t *this);
	
	/**
	 * @brief Check if a suggested dh group is acceptable.
	 * 
	 * If we guess a wrong DH group for IKE_SA_INIT, the other
	 * peer will send us a offer. But is this acceptable for us?
	 * 
	 * @param this		calling object
	 * @return			TRUE if group acceptable
	 */
	bool (*check_dh_group) (connection_t *this, diffie_hellman_group_t dh_group);
	
	/**
	 * @brief Clone a connection_t object.
	 * 
	 * @param this		connection to clone
	 * @return			clone of it
	 */
	connection_t *(*clone) (connection_t *this);
	
	/**
	 * @brief Destroys a connection_t object.
	 * 
	 * @param this		calling object
	 */
	void (*destroy) (connection_t *this);
};

/**
 * @brief Creates a connection_t object.
 * 
 * Supplied hosts become owned by connection, so 
 * do not modify or destroy them after a call to 
 * connection_create(). Name gets cloned internally.
 *
 * @param name				connection identifier
 * @param ikev2				TRUE if this is an IKEv2 connection
 * @param cert_policy		certificate send policy
 * @param cert_req_policy	certificate request send policy
 * @param my_host			host_t representing local address
 * @param other_host		host_t representing remote address
 * @param auth_method		Authentication method to use for our(!) auth data
 * @return 					connection_t object.
 * 
 * @ingroup config
 */
connection_t * connection_create(char *name, bool ikev2,
								 cert_policy_t cert_pol, cert_policy_t req_pol,
								 host_t *my_host, host_t *other_host,
								 auth_method_t auth_method);

#endif /* CONNECTION_H_ */
