/**
 * @file ike_sa.h
 *
 * @brief Interface of ike_sa_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#ifndef IKE_SA_H_
#define IKE_SA_H_

typedef enum ike_sa_state_t ike_sa_state_t;
typedef struct ike_sa_t ike_sa_t;

#include <library.h>
#include <encoding/message.h>
#include <encoding/payloads/proposal_substructure.h>
#include <sa/ike_sa_id.h>
#include <sa/child_sa.h>
#include <sa/tasks/task.h>
#include <config/configuration.h>
#include <utils/randomizer.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <config/connections/connection.h>
#include <config/policies/policy.h>
#include <config/proposal.h>

/**
 * @brief State of an IKE_SA.
 *
 * An IKE_SA passes various states in its lifetime. A newly created
 * SA is in the state CREATED.
 * @verbatim
                 +----------------+
                 ¦   SA_CREATED   ¦
                 +----------------+
                         ¦
    on initiate()--->    ¦   <----- on IKE_SA_INIT received 
                         V
                 +----------------+
                 ¦ SA_CONNECTING  ¦
                 +----------------+
                         ¦
                         ¦   <----- on IKE_AUTH successfully completed
                         V
                 +----------------+
                 ¦ SA_ESTABLISHED ¦-------------------------+ <-- on rekeying
                 +----------------+                         ¦
                         ¦                                  V
    on delete()--->      ¦   <----- on IKE_SA        +-------------+
                         ¦          delete request   ¦ SA_REKEYING ¦
                         ¦          received         +-------------+
                         V                                  ¦
                 +----------------+                         ¦
                 ¦  SA_DELETING   ¦<------------------------+ <-- after rekeying
                 +----------------+
                         ¦
                         ¦   <----- after delete() acknowledged
                         ¦
                        \V/
                         X
                        / \
   @endverbatim
 *
 * @ingroup sa
 */
enum ike_sa_state_t {
	
	/**
	 * IKE_SA just got created, but is not initiating nor responding yet.
	 */
	IKE_CREATED,
	
	/**
	 * IKE_SA gets initiated actively or passively
	 */
	IKE_CONNECTING,
	
	/**
	 * IKE_SA is fully established
	 */
	IKE_ESTABLISHED,
	
	/**
	 * IKE_SA rekeying in progress
	 */
	IKE_REKEYING,
	
	/**
	 * IKE_SA is in progress of deletion
	 */
	IKE_DELETING,
};

/**
 * enum names for ike_sa_state_t.
 */
extern enum_name_t *ike_sa_state_names;

/**
 * @brief Class ike_sa_t representing an IKE_SA.
 *
 * An IKE_SA contains crypto information related to a connection
 * with a peer. It contains multiple IPsec CHILD_SA, for which
 * it is responsible. All traffic is handled by an IKE_SA, using
 * the task manager and its tasks.
 *
 * @b Constructors:
 * - ike_sa_create()
 * 
 * @ingroup sa
 */
struct ike_sa_t {

	/**
	 * @brief Get the id of the SA.
	 * 
	 * Returned ike_sa_id_t object is not getting cloned!
	 *
	 * @param this 			calling object
	 * @return 				ike_sa's ike_sa_id_t
	 */
	ike_sa_id_t* (*get_id) (ike_sa_t *this);
	
	/**
	 * @brief Get the numerical ID uniquely defining this IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				unique ID
	 */
	u_int32_t (*get_unique_id) (ike_sa_t *this);
	
	/**
	 * @brief Get the state of the IKE_SA.
	 *
	 * @param this			calling object
	 * @return				state of the IKE_SA
	 */
	ike_sa_state_t (*get_state) (ike_sa_t *this);
	
	/**
	 * @brief Set the state of the IKE_SA.
	 *
	 * @param this			calling object
	 * @param state			state to set for the IKE_SA
	 */
	void (*set_state) (ike_sa_t *this, ike_sa_state_t ike_sa);
	
	/**
	 * @brief Get the name of the connection this IKE_SA uses.
	 *
	 * @param this			calling object
	 * @return				name
	 */
	char* (*get_name) (ike_sa_t *this);
	
	/**
	 * @brief Get the own host address.
	 * 
	 * @param this 			calling object
	 * @return				host address
	 */
	host_t* (*get_my_host) (ike_sa_t *this);
	
	/**
	 * @brief Set the own host address.
	 * 
	 * @param this 			calling object
	 * @param me			host address
	 */
	void (*set_my_host) (ike_sa_t *this, host_t *me);
	
	/**
	 * @brief Get the other peers host address.
	 * 
	 * @param this 			calling object
	 * @return				host address
	 */
	host_t* (*get_other_host) (ike_sa_t *this);
	
	/**
	 * @brief Set the others host address.
	 * 
	 * @param this 			calling object
	 * @param other			host address
	 */
	void (*set_other_host) (ike_sa_t *this, host_t *other);
	
	/**
	 * @brief Get the own identification.
	 * 
	 * @param this 			calling object
	 * @return				identification
	 */
	identification_t* (*get_my_id) (ike_sa_t *this);
	
	/**
	 * @brief Set the own identification.
	 * 
	 * @param this 			calling object
	 * @param me			identification
	 */
	void (*set_my_id) (ike_sa_t *this, identification_t *me);
	
	/**
	 * @brief Get the other peers identification.
	 * 
	 * @param this 			calling object
	 * @return				identification
	 */
	identification_t* (*get_other_id) (ike_sa_t *this);
	
	/**
	 * @brief Set the other peers identification.
	 * 
	 * @param this 			calling object
	 * @param other			identification
	 */
	void (*set_other_id) (ike_sa_t *this, identification_t *other);
	
	/**
	 * @brief Get the connection used by this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @return				connection
	 */
	connection_t* (*get_connection) (ike_sa_t *this);
	
	/**
	 * @brief Set the connection to use with this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @param connection	connection to use
	 */
	void (*set_connection) (ike_sa_t *this, connection_t* connection);

	/**
	 * @brief Get the policy used by this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @return				policy
	 */
	policy_t* (*get_policy) (ike_sa_t *this);
	
	/**
	 * @brief Set the policy to use with this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @param policy		policy to use
	 */
	void (*set_policy) (ike_sa_t *this, policy_t *policy);

	/**
	 * @brief Initiate a new connection.
	 *
	 * The policy/connection is owned by the IKE_SA after the call, so
	 * do not modify or destroy it.
	 * 
	 * @param this 			calling object
	 * @param connection	connection to initiate
	 * @param policy		policy to set up
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- DESTROY_ME if initialization failed and IKE_SA MUST be deleted
	 */
	status_t (*initiate) (ike_sa_t *this, connection_t *connection, policy_t *policy);

	/**
	 * @brief Route a policy in the kernel.
	 *
	 * Installs the policies in the kernel. If traffic matches,
	 * the kernel requests connection setup from the IKE_SA via acquire().
	 * 
	 * @param this 			calling object
	 * @param connection	connection definition used for routing
	 * @param policy		policy to route
	 * @return				
	 * 						- SUCCESS if routed successfully
	 * 						- FAILED if routing failed
	 */
	status_t (*route) (ike_sa_t *this, connection_t *connection, policy_t *policy);

	/**
	 * @brief Unroute a policy in the kernel previously routed.
	 *
	 * @param this 			calling object
	 * @param policy		policy to route
	 * @return				
	 * 						- SUCCESS if route removed
	 * 						- DESTROY_ME if last route was removed from
	 * 						  an IKE_SA which was not established
	 */
	status_t (*unroute) (ike_sa_t *this, policy_t *policy);
	
	/**
	 * @brief Acquire connection setup for a policy.
	 *
	 * If an installed policy raises an acquire, the kernel calls
	 * this function to establish the CHILD_SA (and maybe the IKE_SA).
	 *
	 * @param this 			calling object
	 * @param reqid			reqid of the CHILD_SA the policy belongs to.
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- DESTROY_ME if initialization failed and IKE_SA MUST be deleted
	 */
	status_t (*acquire) (ike_sa_t *this, u_int32_t reqid);
	
	/**
	 * @brief Initiates the deletion of an IKE_SA.
	 * 
	 * Sends a delete message to the remote peer and waits for
	 * its response. If the response comes in, or a timeout occurs,
	 * the IKE SA gets deleted.
	 * 
	 * @param this 			calling object
	 * @return
	 * 						- SUCCESS if deletion is initialized
	 * 						- INVALID_STATE, if the IKE_SA is not in 
	 * 						  an established state and can not be
	 * 						  delete (but destroyed).
	 */
	status_t (*delete) (ike_sa_t *this);
	
	/**
	 * @brief Processes a incoming IKEv2-Message.
	 *
	 * Message processing may fail. If a critical failure occurs, 
	 * process_message() return DESTROY_ME. Then the caller must 
	 * destroy the IKE_SA immediatly, as it is unusable.
	 * 
	 * @param this 			calling object
	 * @param message 	message to process
	 * @return 				
	 * 						- SUCCESS
	 * 						- FAILED
	 * 						- DESTROY_ME if this IKE_SA MUST be deleted
	 */
	status_t (*process_message) (ike_sa_t *this, message_t *message);
	
	/**
	 * @brief Generate a IKE message to send it to the peer.
	 * 
	 * This method generates all payloads in the message and encrypts/signs
	 * the packet.
	 * 
	 * @param this 			calling object
	 * @param message 		message to generate
	 * @param packet		generated output packet
	 * @return 				
	 * 						- SUCCESS
	 * 						- FAILED
	 * 						- DESTROY_ME if this IKE_SA MUST be deleted
	 */
	status_t (*generate_message) (ike_sa_t *this, message_t *message,
								  packet_t **packet);
	
	/**
	 * @brief Retransmits a request.
	 * 
	 * @param this 			calling object
	 * @param message_id	ID of the request to retransmit
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND if request doesn't have to be retransmited
	 */
	status_t (*retransmit) (ike_sa_t *this, u_int32_t message_id);
	
	/**
	 * @brief Sends a DPD request to the peer.
	 *
	 * To check if a peer is still alive, periodic
	 * empty INFORMATIONAL messages are sent if no
	 * other traffic was received.
	 * 
	 * @param this			calling object
	 * @return
	 * 						- SUCCESS
	 * 						- DESTROY_ME, if peer did not respond
	 */
	status_t (*send_dpd) (ike_sa_t *this);
	
	/**
	 * @brief Sends a keep alive packet.
	 *
	 * To refresh NAT tables in a NAT router
	 * between the peers, periodic empty
	 * UDP packets are sent if no other traffic
	 * was sent.
	 *
	 * @param this			calling object
	 */
	void (*send_keepalive) (ike_sa_t *this);
	
	/**
	 * @brief Check if NAT traversal is enabled for this IKE_SA.
	 *
	 * @param this 			calling object
	 * @return 				TRUE if NAT traversal enabled
	 */
	bool (*is_natt_enabled) (ike_sa_t *this);

	/**
	 * @brief Enable NAT detection for this IKE_SA.
	 *
	 * If a Network address translation is detected with
	 * NAT_DETECTION notifys, a SA must switch to ports
	 * 4500. To enable this behavior, call enable_natt().
	 * It is relevant which peer is NATted, this is specified
	 * with the "local" parameter. Call it twice when both
	 * are NATted.
	 *
	 * @param this 			calling object
	 * @param local			TRUE, if we are NATted, FALSE if other
	 */
	void (*enable_natt) (ike_sa_t *this, bool local);

	/**
	 * @brief Derive all keys and create the transforms for IKE communication.
	 *
	 * Keys are derived using the diffie hellman secret, nonces and internal
	 * stored SPIs.
	 * Key derivation differs when an IKE_SA is set up to replace an
	 * existing IKE_SA (rekeying). The SK_d key from the old IKE_SA
	 * is included in the derivation process.
	 *
	 * @param this 			calling object
	 * @param proposal		proposal which contains algorithms to use
	 * @param secret		secret derived from DH exchange, gets freed
	 * @param nonce_i		initiators nonce
	 * @param nonce_r		responders nonce
	 * @param initiator		TRUE if initiator, FALSE otherwise
	 * @param child_prf		PRF with SK_d key when rekeying, NULL otherwise
	 * @param old_prf		general purpose PRF of old SA when rekeying
	 */
	status_t (*derive_keys)(ike_sa_t *this, proposal_t* proposal, chunk_t secret,
							chunk_t nonce_i, chunk_t nonce_r,
							bool initiator, prf_t *child_prf, prf_t *old_prf);
	
	/**
	 * @brief Get the multi purpose prf.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	prf_t *(*get_prf) (ike_sa_t *this);
	
	/**
	 * @brief Get the prf-object, which is used to derive keys for child SAs.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	prf_t *(*get_child_prf) (ike_sa_t *this);
	
	/**
	 * @brief Get the prf to build outgoing authentication data.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	prf_t *(*get_auth_build) (ike_sa_t *this);
	
	/**
	 * @brief Get the prf to verify incoming authentication data.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	prf_t *(*get_auth_verify) (ike_sa_t *this);
	
	/**
	 * @brief Associates a child SA to this IKE SA
	 * 
	 * @param this 			calling object
	 * @param child_sa		child_sa to add
	 */
	void (*add_child_sa) (ike_sa_t *this, child_sa_t *child_sa);
	
	/**
	 * @brief Get a CHILD_SA identified by protocol and SPI.
	 * 
	 * @param this 			calling object
	 * @param protocol		protocol of the SA
	 * @param spi			SPI of the CHILD_SA
	 * @param inbound		TRUE if SPI is inbound, FALSE if outbound
	 * @return				child_sa, or NULL if none found
	 */
	child_sa_t* (*get_child_sa) (ike_sa_t *this, protocol_id_t protocol, 
								 u_int32_t spi, bool inbound);
	
	/**
	 * @brief Create an iterator over all CHILD_SAs.
	 * 
	 * @param this 			calling object
	 * @return				iterator
	 */
	iterator_t* (*create_child_sa_iterator) (ike_sa_t *this);
	
	/**
	 * @brief Rekey the CHILD SA with the specified reqid.
	 *
	 * Looks for a CHILD SA owned by this IKE_SA, and start the rekeing.
	 *
	 * @param this 			calling object
	 * @param protocol		protocol of the SA
	 * @param spi			inbound SPI of the CHILD_SA
	 * @return
	 * 						- NOT_FOUND, if IKE_SA has no such CHILD_SA
	 * 						- SUCCESS, if rekeying initiated
	 */
	status_t (*rekey_child_sa) (ike_sa_t *this, protocol_id_t protocol, u_int32_t spi);

	/**
	 * @brief Close the CHILD SA with the specified protocol/SPI.
	 *
	 * Looks for a CHILD SA owned by this IKE_SA, deletes it and
	 * notify's the remote peer about the delete. The associated
	 * states and policies in the kernel get deleted, if they exist.
	 *
	 * @param this 			calling object
	 * @param protocol		protocol of the SA
	 * @param spi			inbound SPI of the CHILD_SA
	 * @return
	 * 						- NOT_FOUND, if IKE_SA has no such CHILD_SA
	 * 						- SUCCESS, if delete message sent
	 */
	status_t (*delete_child_sa) (ike_sa_t *this, protocol_id_t protocol, u_int32_t spi);

	/**
	 * @brief Destroy a CHILD SA with the specified protocol/SPI.
	 *
	 * Looks for a CHILD SA owned by this IKE_SA and destroys it.
	 *
	 * @param this 			calling object
	 * @param protocol		protocol of the SA
	 * @param spi			inbound SPI of the CHILD_SA
	 * @return
	 * 						- NOT_FOUND, if IKE_SA has no such CHILD_SA
	 * 						- SUCCESS
	 */
	status_t (*destroy_child_sa) (ike_sa_t *this, protocol_id_t protocol, u_int32_t spi);

	/**
	 * @brief Rekey the IKE_SA.
	 *
	 * Sets up a new IKE_SA, moves all CHILDs to it and deletes this IKE_SA.
	 *
	 * @param this 			calling object
	 * @return				- SUCCESS, if IKE_SA rekeying initiated
	 */
	status_t (*rekey) (ike_sa_t *this);

	/**
	 * @brief Restablish the IKE_SA.
	 *
	 * Create a completely new IKE_SA with authentication, recreates all children
	 * within the IKE_SA, but lets the old IKE_SA untouched.
	 *
	 * @param this 			calling object
	 */
	void (*reestablish) (ike_sa_t *this);
	
	/**
	 * @brief Set the virtual IP to use for this IKE_SA and its children.
	 *
	 * The virtual IP is assigned per IKE_SA, not per CHILD_SA. It has the same
	 * lifetime as the IKE_SA.
	 *
	 * @param this 			calling object
	 */
	void (*set_virtual_ip) (ike_sa_t *this, bool local, host_t *ip);
	
	/**
	 * @brief Get the virtual IP configured.
	 *
	 * @param this 			calling object
	 * @param local			TRUE to get local virtual IP, FALSE for remote
	 */
	host_t* (*get_virtual_ip) (ike_sa_t *this, bool local);
	
	/**
	 * @brief Add a DNS server to the system.
	 *
	 * An IRAS may send a DNS server. To use it, it is installed on the
	 * system. The DNS entry has a lifetime until the IKE_SA gets closed.
	 *
	 * @param this 			calling object
	 * @param dns			DNS server to install on the system
	 */
	void (*add_dns_server) (ike_sa_t *this, host_t *dns);
	
	/**
	 * @brief Inherit all attributes of other to this after rekeying.
	 *
	 * When rekeying is completed, all CHILD_SAs, the virtual IP and all
	 * outstanding tasks are moved from other to this.
	 *
	 * @param this 			calling object
	 */
	void (*inherit) (ike_sa_t *this, ike_sa_t *other);
		
	/**
	 * @brief Reset the IKE_SA, useable when initiating fails
	 *
	 * @param this 			calling object
	 */
	void (*reset) (ike_sa_t *this);
	
	/**
	 * @brief Destroys a ike_sa_t object.
	 *
	 * @param this 			calling object
	 */
	void (*destroy) (ike_sa_t *this);
};

/**
 * @brief Creates an ike_sa_t object with a specific ID.
 *
 * @param ike_sa_id 	ike_sa_id_t object to associate with new IKE_SA
 * @return 				ike_sa_t object
 * 
 * @ingroup sa
 */
ike_sa_t *ike_sa_create(ike_sa_id_t *ike_sa_id);

#endif /* IKE_SA_H_ */
