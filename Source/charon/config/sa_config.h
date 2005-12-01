/**
 * @file sa_config.h
 * 
 * @brief Interface of sa_config_t.
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

#ifndef _SA_CONFIG_H_
#define _SA_CONFIG_H_

#include <types.h>
#include <utils/identification.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <network/host.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>
#include <transforms/diffie_hellman.h>
#include <config/traffic_selector.h>


typedef struct child_proposal_t child_proposal_t;

/**
 * @brief Storage structure for a proposal for a child sa.
 * 
 * A proposal for a child sa contains data for 
 * AH, ESP, or both.
 * 
 * @ingroup config
 */
struct child_proposal_t {
	
	/**
	 * Data for AH, if set
	 */
	struct {
		bool is_set;
		integrity_algorithm_t integrity_algorithm;
		size_t integrity_algorithm_key_size;
		diffie_hellman_group_t diffie_hellman_group;
		extended_sequence_numbers_t extended_sequence_numbers;
		u_int8_t spi[4];
	} ah;
	
	/**
	 * data for ESP, if set
	 */
	struct {
		bool is_set;
		encryption_algorithm_t encryption_algorithm;
		size_t encryption_algorithm_key_size;
		integrity_algorithm_t integrity_algorithm;
		size_t integrity_algorithm_key_size;
		diffie_hellman_group_t diffie_hellman_group;
		extended_sequence_numbers_t extended_sequence_numbers;
		u_int8_t spi[4];
	} esp;
};


typedef struct sa_config_t sa_config_t;

/**
 * @brief Stores configuration of an initialized connection.
 * 
 * During the IKE_AUTH phase, we have enought data to specify a 
 * configuration. 
 * 
 * @warning This config is not thread save.
 * 
 * @ingroup config
 */
struct sa_config_t {
	
	/**
	 * @brief Get own id to use for identification.
	 * 
	 * @param this					calling object
	 * @return						own id
	 */
	identification_t *(*get_my_id) (sa_config_t *this);
	
	/**
	 * @brief Get id of communication partner..
	 * 
	 * @param this					calling object
	 * @return						other id
	 */
	identification_t *(*get_other_id) (sa_config_t *this);
	
	/**
	 * @brief Get authentication method to use for IKE_AUTH.
	 * 
	 * @param this					calling object
	 * @return						authentication methood
	 */
	auth_method_t (*get_auth_method) (sa_config_t *this);
	
	/**
	 * @brief Get configured traffic selectors.
	 * 
	 * @warning Resulting array must be freed!
	 * 
	 * @param this					calling object
	 * @param[out]traffic_selectors	pointer where traffic selectors will be allocated
	 * @return						number of returned traffic selectors
	 */
	size_t (*get_traffic_selectors) (sa_config_t *this, traffic_selector_t ***traffic_selectors);
	
	/**
	 * @brief Select traffic selectors from a supplied list.
	 * 
	 * @warning Resulting array must be freed!
	 * 
	 * @param this					calling object
	 * @param supplied				pointer to an array of ts to select from.
	 * @param count					number of ts stored at supplied
	 * @param[out]traffic_selectors	pointer where selected traffic selectors will be allocated
	 * @return						number of selected traffic selectors
	 */
	size_t (*select_traffic_selectors) (sa_config_t *this, traffic_selector_t **supplied, size_t count, traffic_selector_t ***selected);
	
	/**
	 * @brief Get the list of proposals for this config.
	 * 
	 * @warning Resulting array must be freed!
	 * 
	 * @param this					calling object
	 * @param[out]traffic_selectors	pointer where proposals will be allocated
	 * @return						number of allocated proposals
	 */
	size_t (*get_proposals) (sa_config_t *this, u_int8_t ah_spi[4], u_int8_t esp_spi[4], child_proposal_t **proposals);
	
	/**
	 * @brief Select a proposal from a supplied list
	 * 
	 * @warning Resulting array must be freed!
	 * 
	 * @param this					calling object
	 * @param supplied				pointer to an array of proposals to select from.
	 * @param count					number of proposals stored at supplied
	 * @return						the selected proposal
	 */
	child_proposal_t* (*select_proposal) (sa_config_t *this, u_int8_t ah_spi[4], u_int8_t esp_spi[4], child_proposal_t *supplied, size_t count);
	
	/**
	 * @brief Add a traffic selector to the list. 
	 * 
	 * Added proposal will be cloned.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param traffic_selector		traffic_selector to add
	 */
	void (*add_traffic_selector) (sa_config_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a proposal to the list. 
	 * 
	 * The proposals are stored by priority, first added
	 * is the most prefered.
	 * Added proposal will be cloned.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param proposal				proposal to add
	 */
	void (*add_proposal) (sa_config_t *this, child_proposal_t *proposal);
	
	/**
	 * @brief Destroys the config object
	 * 
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (sa_config_t *this);
};

/**
 * @brief Create a configuration object for IKE_AUTH and later.
 * 
 * @return 		created sa_config_t
 * 
 * @ingroup config
 */
sa_config_t *sa_config_create();

#endif //_SA_CONFIG_H_
