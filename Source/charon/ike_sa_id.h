/**
 * @file ike_sa_id.h
 *
 * @brief Class for identification of an IKE_SA
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


#ifndef IKE_SA_ID_H_
#define IKE_SA_ID_H_

#include "types.h"

/**
 * @brief This class is used to identify an IKE_SA.
 *
 * An IKE_SA is identified by its initiator and responder spi's.
 * Additionaly it contains the role of the actual running IKEv2-Daemon
 * for the specific IKE_SA.
 */
typedef struct ike_sa_id_s ike_sa_id_t;

struct ike_sa_id_s {

	/**
	 * @brief Sets the SPI of the responder.
	 *
	 * This function is called when a request or reply of a IKE_SA_INIT is received.
	 *
	 * @param this ike_sa_id_t object
	 * @param responder_spi SPI of responder to set
	 * @return SUCCESSFUL in any case
	 */
	status_t (*set_responder_spi) (ike_sa_id_t *this, spi_t responder_spi);

	/**
	 * @brief Sets the SPI of the initiator.
	 *
	 *
	 * @param this ike_sa_id_t object
	 * @param initiator_spi SPI to set
	 * @return SUCCESSFUL in any case
	 */
	status_t (*set_initiator_spi) (ike_sa_id_t *this, spi_t initiator_spi);

	/**
	 * @brief Returns TRUE if the initiator spi is set (not zero)
	 *
	 * @param this ike_sa_id_t object
	 * @return TRUE if the initiator spi is set, FALSE otherwise
	 */
	bool (*initiator_spi_is_set) (ike_sa_id_t *this);

	/**
	 * @brief Returns TRUE if the responder spi is set (not zero)
	 *
	 * @param this ike_sa_id_t object
	 * @return TRUE if the responder spi is set, FALSE otherwise
	 */
	bool (*responder_spi_is_set) (ike_sa_id_t *this);

	/**
	 * @brief Check if two ike_sa_ids are equal
	 *
	 * @param this ike_sa_id_t object
 	 * @param other ike_sa_id object to check if equal
 	 * @param are_equal is set to TRUE, if given ike_sa_ids are equal, FALSE otherwise
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*equals) (ike_sa_id_t *this,ike_sa_id_t *other, bool *are_equal);

	/**
	 * @brief Replace the values of a given ike_sa_id_t object with values
	 * from another ike_sa_id_t object
	 *
	 * @param this ike_sa_id_t object
 	 * @param other ike_sa_id_t object which values will be taken
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*replace_values) (ike_sa_id_t *this,ike_sa_id_t *other);

	/**
	 * @brief get spis and role of an ike_sa_id
	 *
	 * @param this ike_sa_id_t object
 	 * @param initiator address to write initator spi
 	 * @param responder address to write responder spi
 	 * @param role address to write role
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*get_values) (ike_sa_id_t *this, spi_t *initiator, spi_t *responder, ike_sa_role_t *role);

	/**
	 * @brief Clones a given ike_sa_id_t object
	 *
	 * @param this ike_sa_id_t object
 	 * @param clone_of_this ike_sa_id_t object which will be created
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*clone) (ike_sa_id_t *this,ike_sa_id_t **clone_of_this);

	/**
	 * @brief Destroys a ike_sa_id_tobject
	 *
	 * @param this ike_sa_id_t object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (ike_sa_id_t *this);
};

/**
 * Creates an ike_sa_id_t object with specific spi's and defined role
 *
 * @warning The initiator SPI and role is not changeable after initiating a ike_sa_id object
 */
ike_sa_id_t * ike_sa_id_create(spi_t initiator_spi, spi_t responder_spi,ike_sa_role_t role);

#endif /*IKE_SA_ID_H_*/
