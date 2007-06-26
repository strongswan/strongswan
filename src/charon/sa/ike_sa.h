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

typedef enum ike_extension_t ike_extension_t;
typedef enum ike_condition_t ike_condition_t;
typedef enum ike_sa_state_t ike_sa_state_t;
typedef struct ike_sa_t ike_sa_t;

#include <library.h>
#include <encoding/message.h>
#include <encoding/payloads/proposal_substructure.h>
#include <sa/ike_sa_id.h>
#include <sa/child_sa.h>
#include <sa/tasks/task.h>
#include <utils/randomizer.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <crypto/ca.h>
#include <config/peer_cfg.h>
#include <config/ike_cfg.h>

/**
 * Timeout in milliseconds after that a half open IKE_SA gets deleted.
 *
 * @ingroup sa
 */
#define HALF_OPEN_IKE_SA_TIMEOUT 30000

/**
 * Interval to send keepalives when NATed, in seconds.
 *
 * @ingroup sa
 */
#define KEEPALIVE_INTERVAL 20

/**
 * After which time rekeying should be retried if it failed, in seconds.
 *
 * @ingroup sa
 */
#define RETRY_INTERVAL 30

/**
 * Jitter to subtract from RETRY_INTERVAL to randomize rekey retry.
 *
 * @ingroup sa
 */
#define RETRY_JITTER 20

/**
 * @brief Extensions (or optional features) the peer supports
 */
enum ike_extension_t {
	
	/**
	 * peer supports NAT traversal as specified in RFC4306
	 */
	EXT_NATT = (1<<0),

	/**
	 * peer supports MOBIKE (RFC4555)
	 */
	EXT_MOBIKE = (1<<1),
};

/**
 * @brief Conditions of an IKE_SA, change during its lifetime
 */
enum ike_condition_t {
	
	/**
	 * Connection is natted somewhere
	 */
	COND_NAT_ANY = (1<<0),
	
	/**
	 * we are behind NAT
	 */
	COND_NAT_HERE = (1<<1),
	
	/**
	 * other is behind NAT
	 */
	COND_NAT_THERE = (1<<2),

	/**
	 * peer is currently not reachable (due missing route, ...)
	 */
	COND_STALE = (1<<3),
};

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
	 * @brief Get some statistics about this IKE_SA.
	 *
	 * @param next_rekeying			when the next rekeying is scheduled
	 */
	void (*get_stats)(ike_sa_t *this, u_int32_t *next_rekeying);	
	
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
	 * @brief Update the IKE_SAs host.
	 *
	 * Hosts may be NULL to use current host.
	 *
	 * @param this			calling object
	 * @param me			new local host address, or NULL
	 * @param other			new remote host address, or NULL
	 */
	void (*update_hosts)(ike_sa_t *this, host_t *me, host_t *other);
	
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
	 * @brief Get the other peer's identification.
	 * 
	 * @param this 			calling object
	 * @return				identification
	 */
	identification_t* (*get_other_id) (ike_sa_t *this);
	
	/**
	 * @brief Set the other peer's identification.
	 * 
	 * @param this 			calling object
	 * @param other			identification
	 */
	void (*set_other_id) (ike_sa_t *this, identification_t *other);
	
	/**
	 * @brief Get the other peer's certification authority
	 * 
	 * @param this 			calling object
	 * @return			ca_info_t record of other ca
	 */
	ca_info_t* (*get_other_ca) (ike_sa_t *this);
	
	/**
	 * @brief Set the other peer's certification authority
	 * 
	 * @param this 			calling object
	 * @param other_ca		ca_info_t record of other ca
	 */
	void (*set_other_ca) (ike_sa_t *this, ca_info_t *other_ca);
	
	/**
	 * @brief Get the config used to setup this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @return				ike_config
	 */
	ike_cfg_t* (*get_ike_cfg) (ike_sa_t *this);
	
	/**
	 * @brief Set the config to setup this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @param config		ike_config to use
	 */
	void (*set_ike_cfg) (ike_sa_t *this, ike_cfg_t* config);

	/**
	 * @brief Get the peer config used by this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @return				peer_config
	 */
	peer_cfg_t* (*get_peer_cfg) (ike_sa_t *this);
	
	/**
	 * @brief Set the peer config to use with this IKE_SA.
	 * 
	 * @param this 			calling object
	 * @param config		peer_config to use
	 */
	void (*set_peer_cfg) (ike_sa_t *this, peer_cfg_t *config);
	
	/**
	 * @brief Add an additional address for the peer.
	 *
	 * In MOBIKE, a peer may transmit additional addresses where it is
	 * reachable. These are stored in the IKE_SA.
	 * The own list of addresses is not stored, they are queried from
	 * the kernel when required.
	 *
	 * @param this			calling object
	 * @param host			host to add to list
	 */
	void (*add_additional_address)(ike_sa_t *this, host_t *host);
	
	/**
	 * @brief Create an iterator over all additional addresses of the peer.
	 *
	 * @param this			calling object
	 * @return 				iterator over addresses
	 */
	iterator_t* (*create_additional_address_iterator)(ike_sa_t *this);
	
	/**
	 * @brief Enable an extension the peer supports.
	 *
	 * If support for an IKE extension is detected, this method is called
	 * to enable that extension and behave accordingly.
	 *
	 * @param this			calling object
	 * @param extension		extension to enable
	 */
	void (*enable_extension)(ike_sa_t *this, ike_extension_t extension);
	
	/**
	 * @brief Check if the peer supports an extension.
	 *
	 * @param this			calling object
	 * @param extension		extension to check for support
	 * @return				TRUE if peer supports it, FALSE otherwise
	 */
	bool (*supports_extension)(ike_sa_t *this, ike_extension_t extension);
	
	/**
	 * @brief Enable/disable a condition flag for this IKE_SA.
	 *
	 * @param this 			calling object
	 * @param condition		condition to enable/disable
	 * @param enable		TRUE to enable condition, FALSE to disable
	 */
	void (*set_condition) (ike_sa_t *this, ike_condition_t condition, bool enable);

	/**
	 * @brief Check if a condition flag is set.
	 *
	 * @param this 			calling object
	 * @param condition		condition to check
	 * @return				TRUE if condition flag set, FALSE otherwise
	 */
	bool (*has_condition) (ike_sa_t *this, ike_condition_t condition);
	
	/**
	 * @brief Initiate a new connection.
	 *
	 * The configs are owned by the IKE_SA after the call.
	 * 
	 * @param this 			calling object
	 * @param child_cfg		child config to create CHILD from
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- DESTROY_ME if initialization failed
	 */
	status_t (*initiate) (ike_sa_t *this, child_cfg_t *child_cfg);

	/**
	 * @brief Route a policy in the kernel.
	 *
	 * Installs the policies in the kernel. If traffic matches,
	 * the kernel requests connection setup from the IKE_SA via acquire().
	 * 
	 * @param this 			calling object
	 * @param child_cfg		child config to route
	 * @return				
	 * 						- SUCCESS if routed successfully
	 * 						- FAILED if routing failed
	 */
	status_t (*route) (ike_sa_t *this, child_cfg_t *child_cfg);

	/**
	 * @brief Unroute a policy in the kernel previously routed.
	 *
	 * @param this 			calling object
	 * @param reqid			reqid of CHILD_SA to unroute
	 * @return				
	 * 						- SUCCESS if route removed
	 *						- NOT_FOUND if CHILD_SA not found
	 * 						- DESTROY_ME if last CHILD_SA was unrouted
	 */
	status_t (*unroute) (ike_sa_t *this, u_int32_t reqid);
	
	/**
	 * @brief Acquire connection setup for an installed kernel policy.
	 *
	 * If an installed policy raises an acquire, the kernel calls
	 * this function to establish the CHILD_SA (and maybe the IKE_SA).
	 *
	 * @param this 			calling object
	 * @param reqid			reqid of the CHILD_SA the policy belongs to.
	 * @return				
	 * 						- SUCCESS if initialization started
	 * 						- DESTROY_ME if initialization failed
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
	 * @brief Update IKE_SAs after network interfaces have changed.
	 *
	 * Whenever the network interface configuration changes, the kernel
	 * interface calls roam() on each IKE_SA. The IKE_SA then checks if
	 * the new network config requires changes, and handles appropriate.
	 * If MOBIKE is supported, addresses are updated; If not, the tunnel is
	 * restarted.
	 *
	 * @param 
	 * @return
	 */
	status_t (*roam)(ike_sa_t *this);
	
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
	 * @brief Get a multi purpose prf for the negotiated PRF function.
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
	 * @brief Get the key to build outgoing authentication data.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	chunk_t (*get_skp_build) (ike_sa_t *this);
	
	/**
	 * @brief Get the key to verify incoming authentication data.
	 * 
	 * @param this 			calling object
	 * @return				pointer to prf_t object
	 */
	chunk_t (*get_skp_verify) (ike_sa_t *this);
	
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
	 * within the IKE_SA, closes this IKE_SA.
	 *
	 * @param this 			calling object
	 * @return				DESTROY_ME to destroy the IKE_SA
	 */
	status_t (*reestablish) (ike_sa_t *this);
	
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
	 * As this call may initiate inherited tasks, a status is returned.
	 *
	 * @param this 			calling object
	 * @param other			other task to inherit from
	 * @return				DESTROY_ME if initiation of inherited task failed
	 */
	status_t (*inherit) (ike_sa_t *this, ike_sa_t *other);
		
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
