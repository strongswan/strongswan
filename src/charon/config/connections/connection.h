/**
 * @file connection.h
 *
 * @brief Interface of connection_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <types.h>
#include <utils/host.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <config/proposal.h>
#include <crypto/diffie_hellman.h>

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
 * string mappings for certpolic_t.
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
	 * @brief Returns a list of all supported proposals.
	 * 
	 * Returned list and its proposals  must be destroyed after usage.
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
	 * @brief Get the DPD check interval.
	 * 
	 * @param this		calling object
	 * @return			dpd_delay in seconds
	 */
	u_int32_t (*get_dpd_delay) (connection_t *this);
	
	/**
	 * @brief Get the max number of retransmission sequences.
	 *
	 * After this number of sequences, a not responding peer is considered
	 * dead.
	 *
	 * @param this		calling object
	 * @return			max number of retransmission sequences
	 */
	u_int32_t (*get_retrans_seq) (connection_t *this);
	
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
	 * @return			certificate request sending policy
	 */
	cert_policy_t (*get_certreq_policy) (connection_t *this);
	
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
	 * @brief Get the lifetime of a connection, before IKE_SA rekeying starts.
	 * 
	 * A call to this function automatically adds a jitter to
	 * avoid simultanous rekeying.
	 * 
	 * @param this		calling object
	 * @return			lifetime in seconds
	 */
	u_int32_t (*get_soft_lifetime) (connection_t *this);
	
	/**
	 * @brief Get the lifetime of a connection, before IKE_SA gets deleted.
	 * 
	 * @param this		calling object
	 * @return			lifetime in seconds
	 */
	u_int32_t (*get_hard_lifetime) (connection_t *this);
	
	/**
	 * @brief Get a new reference to this connection.
	 *
	 * Get a new reference to this connection by increasing
	 * it's internal reference counter.
	 * Do not call get_ref or any other function until you
	 * already have a reference. Otherwise the object may get
	 * destroyed while calling get_ref(),
	 *
	 * @param this		calling object
	 */
	void (*get_ref) (connection_t *this);
	
	/**
	 * @brief Destroys a connection_t object.
	 * 
	 * Decrements the internal reference counter and
	 * destroys the connection when it reaches zero.
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
 * The retrasmit sequence number says how fast we give up when the peer
 * does not respond. A high value may bridge-over temporary connection 
 * problems, a small value can detect dead peers faster.
 *
 * @param name				connection identifier
 * @param ikev2				TRUE if this is an IKEv2 connection
 * @param cert_policy		certificate send policy
 * @param cert_req_policy	certificate request send policy
 * @param my_host			host_t representing local address
 * @param other_host		host_t representing remote address
 * @param dpd_delay			interval of DPD liveness checks
 * @param retrans_sequences	number of retransmit sequences to use
 * @param hard_lifetime		lifetime before deleting an IKE_SA
 * @param soft_lifetime		lifetime before rekeying an IKE_SA
 * @param jitter			range of randomization time
 * @return 					connection_t object.
 * 
 * @ingroup config
 */
connection_t * connection_create(char *name, bool ikev2,
								 cert_policy_t cert_pol, cert_policy_t req_pol,
								 host_t *my_host, host_t *other_host,
								 u_int32_t dpd_delay, u_int32_t retrans_sequences,
								 u_int32_t hard_lifetime, u_int32_t soft_lifetime, 
								 u_int32_t jitter);

#endif /* CONNECTION_H_ */
