/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   kernel_fc_sp.h
 * Author: cwinkler
 *
 * Created on October 20, 2020, 2:19 PM
 */

#ifndef KERNEL_FC_SP_H
#define KERNEL_FC_SP_H

typedef struct kernel_fc_sp_t kernel_fc_sp_t;
typedef struct kernel_fc_sp_sa_id_t kernel_fc_sp_sa_id_t;
typedef struct kernel_fc_sp_add_sa_t kernel_fc_sp_add_sa_t;
typedef struct kernel_fc_sp_update_sa_t kernel_fc_sp_update_sa_t;
typedef struct kernel_fc_sp_query_sa_t kernel_fc_sp_query_sa_t;
typedef struct kernel_fc_sp_del_sa_t kernel_fc_sp_del_sa_t;
typedef struct kernel_fc_sp_policy_id_t kernel_fc_sp_policy_id_t;
typedef struct kernel_fc_sp_manage_policy_t kernel_fc_sp_manage_policy_t;
typedef struct kernel_fc_sp_query_policy_t kernel_fc_sp_query_policy_t;

#include <networking/host.h>
#include <ipsec/ipsec_types.h>
#include <selectors/traffic_selector.h>
#include <plugins/plugin.h>
#include <kernel/kernel_interface.h>

/**
 * Data required to identify an SA in the kernel
 */
struct kernel_fc_sp_sa_id_t {
	/** Source address */
	host_t *src;
	/** Destination address */
	host_t *dst;
	/** SPI */
	uint32_t spi;
	/** Protocol (ESP/AH) */
	uint8_t proto;
	/** Optional mark */
	mark_t mark;
	/** Optional interface ID */
	uint32_t if_id;
};

/**
 * Data required to add an SA to the kernel
 */
struct kernel_fc_sp_add_sa_t {
	/** Reqid */
	uint32_t reqid;
	/** Mode (tunnel, transport...) */
	ipsec_mode_t mode;
	/** List of source traffic selectors */
	linked_list_t *src_ts;
	/** List of destination traffic selectors */
	linked_list_t *dst_ts;
	/** Network interface restricting policy */
	char *interface;
	/** Lifetime configuration */
	lifetime_cfg_t *lifetime;
	/** Encryption algorithm */
	uint16_t enc_alg;
	/** Encryption key */
	chunk_t enc_key;
	/** Integrity protection algorithm */
	uint16_t int_alg;
	/** Integrity protection key */
	chunk_t int_key;
	/** Anti-replay window size */
	uint32_t replay_window;
	/** Traffic Flow Confidentiality padding */
	uint32_t tfc;
	/** IPComp transform */
	uint16_t ipcomp;
	/** CPI for IPComp */
	uint16_t cpi;
	/** TRUE to enable UDP encapsulation for NAT traversal */
	bool encap;
	/** no (disabled), yes (enabled), auto (enabled if supported) */
	hw_offload_t hw_offload;
	/** Mark the SA should apply to packets after processing */
	mark_t mark;
	/** TRUE to use Extended Sequence Numbers */
	bool esn;
	/** TRUE to copy the DF bit to the outer IPv4 header in tunnel mode */
	bool copy_df;
	/** TRUE to copy the ECN header field to/from the outer header */
	bool copy_ecn;
	/** Whether to copy the DSCP header field to/from the outer header */
	dscp_copy_t copy_dscp;
	/** TRUE if initiator of the exchange creating the SA */
	bool initiator;
	/** TRUE if this is an inbound SA */
	bool inbound;
	/** TRUE if an SPI has already been allocated for this SA */
	bool update;
};

/**
 * Data required to update the hosts of an SA in the kernel
 */
struct kernel_fc_sp_update_sa_t {
	/** CPI in case IPComp is used */
	uint16_t cpi;
	/** New source address */
	host_t *new_src;
	/** New destination address */
	host_t *new_dst;
	/** TRUE if UDP encapsulation is currently enabled */
	bool encap;
	/** TRUE to enable UDP encapsulation */
	bool new_encap;
};

/**
 * Data required to query an SA in the kernel
 */
struct kernel_fc_sp_query_sa_t {
	uint16_t cpi;
};

/**
 * Data required to delete an SA in the kernel
 */
struct kernel_fc_sp_del_sa_t {
	/** CPI in case IPComp is used */
	uint16_t cpi;
};

/**
 * Data identifying a policy in the kernel
 */
struct kernel_fc_sp_policy_id_t {
	/** Direction of traffic */
	policy_dir_t dir;
	/** Source traffic selector */
	traffic_selector_t *src_ts;
	/** Destination traffic selector */
	traffic_selector_t *dst_ts;
	/** Optional mark */
	mark_t mark;
	/** Optional interface ID */
	uint32_t if_id;
	/** Network interface restricting policy */
	char *interface;
};

/**
 * Data required to add/delete a policy to/from the kernel
 */
struct kernel_fc_sp_manage_policy_t {
	/** Type of policy */
	policy_type_t type;
	/** Priority class */
	policy_priority_t prio;
	/** Manually-set priority (automatic if set to 0) */
	uint32_t manual_prio;
	/** Source address of the SA(s) tied to this policy */
	host_t *src;
	/** Destination address of the SA(s) tied to this policy */
	host_t *dst;
	/** Details about the SA(s) tied to this policy */
	ipsec_sa_cfg_t *sa;
};

/**
 * Data required to query a policy in the kernel
 */
struct kernel_fc_sp_query_policy_t {
};


/**
 * Interface to the fc-sp subsystem.
 *
 * The kernel fc-sp interface handles the communication with the FC-SP 
 * module that will communicate to the lower level that handles the SAs.
 * FC-SP does not currently use policies so they are not provided in this
 * implementation of the interface.
 */
struct kernel_fc_sp_t {

	/**
	 * Get the feature set supported by this kernel backend.
	 *
	 * @return				ORed feature-set of backend
	 */
	kernel_feature_t (*get_features)(kernel_fc_sp_t *this);

	/**
	 * Get a SPI from the kernel.
	 *
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param protocol	protocol for SA (ESP/AH)
	 * @param spi		allocated spi
	 * @return			SUCCESS if operation completed
	 */
	status_t (*get_spi)(kernel_fc_sp_t *this, host_t *src, host_t *dst,
						uint8_t protocol, uint32_t *spi);
        
        /**
	 * Get a Compression Parameter Index (CPI) from the kernel.
	 *
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param cpi		allocated cpi
	 * @return			SUCCESS if operation completed
	 */
	status_t (*get_cpi)(kernel_fc_sp_t *this, host_t *src, host_t *dst,
						uint16_t *cpi);

	/**
	 * Add an SA to the SAD.
	 *
	 * This function does install a single SA for a single protocol in one
	 * direction.
	 *
	 * @param id			data identifying this SA
	 * @param data			data for this SA
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_sa)(kernel_fc_sp_t *this, kernel_fc_sp_sa_id_t *id,
					   kernel_fc_sp_add_sa_t *data);
        
        /**
	 * Update the hosts on an installed SA.
	 *
	 * We cannot directly update the destination address as the kernel
	 * requires the spi, the protocol AND the destination address (and family)
	 * to identify SAs. Therefore if the destination address changed we
	 * create a new SA and delete the old one.
	 *
	 * @param id			data identifying this SA
	 * @param data			updated data for this SA
	 * @return				SUCCESS if operation completed, NOT_SUPPORTED if
	 *						the kernel interface can't update the SA
	 */
	status_t (*update_sa)(kernel_fc_sp_t *this, kernel_fc_sp_sa_id_t *id,
						  kernel_fc_sp_update_sa_t *data);

	/**
	 * Query the number of bytes processed by an SA from the SAD.
	 *
	 * @param id			data identifying this SA
	 * @param data			data to query the SA
	 * @param[out] bytes	the number of bytes processed by SA
	 * @param[out] packets	number of packets processed by SA
	 * @param[out] time		last (monotonic) time of SA use
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_sa)(kernel_fc_sp_t *this, kernel_fc_sp_sa_id_t *id,
						 kernel_fc_sp_query_sa_t *data, uint64_t *bytes,
						 uint64_t *packets, time_t *time);

	/**
	 * Delete a previously installed SA from the SAD.
	 *
	 * @param id			data identifying this SA
	 * @param data			data to delete the SA
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_sa)(kernel_fc_sp_t *this, kernel_fc_sp_sa_id_t *id,
					   kernel_fc_sp_del_sa_t *data);
        
        /**
	 * Add a policy to the SPD.
	 *
	 * @param id			data identifying this policy
	 * @param data			data for this policy
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_policy)(kernel_fc_sp_t *this,
						   kernel_fc_sp_policy_id_t *id,
						   kernel_fc_sp_manage_policy_t *data);

	/**
	 * Query the use time of a policy.
	 *
	 * The use time of a policy is the time the policy was used for the last
	 * time. It is not the system time, but a monotonic timestamp as returned
	 * by time_monotonic.
	 *
	 * @param id			data identifying this policy
	 * @param data			data to query the policy
	 * @param[out] use_time	the monotonic timestamp of this SA's last use
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_policy)(kernel_fc_sp_t *this,
							 kernel_fc_sp_policy_id_t *id,
							 kernel_fc_sp_query_policy_t *data,
							 time_t *use_time);

	/**
	 * Remove a policy from the SPD.
	 *
	 * @param id			data identifying this policy
	 * @param data			data for this policy
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_policy)(kernel_fc_sp_t *this,
						   kernel_fc_sp_policy_id_t *id,
						   kernel_fc_sp_manage_policy_t *data);

	/**
	 * Install a bypass policy for the given socket.
	 *
	 * @param fd			socket file descriptor to setup policy for
	 * @param family		protocol family of the socket
	 * @return				TRUE of policy set up successfully
	 */
	bool (*bypass_socket)(kernel_fc_sp_t *this, int fd, int family);

	/**
	 * Enable decapsulation of ESP-in-UDP packets for the given port/socket.
	 *
	 * @param fd			socket file descriptor
	 * @param family		protocol family of the socket
	 * @param port			the UDP port
	 * @return				TRUE if UDP decapsulation was enabled successfully
	 */
	bool (*enable_udp_decap)(kernel_fc_sp_t *this, int fd, int family,
							 uint16_t port);

	/**
	 * Destroy the implementation.
	 */
	void (*destroy)(kernel_fc_sp_t *this);
};

bool kernel_fc_sp_register(plugin_t *plugin, plugin_feature_t *feature,
						   bool reg, void *data);

#endif /* KERNEL_FC_SP_H */

