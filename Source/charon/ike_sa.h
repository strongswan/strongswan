/**
 * @file ike_sa.h
 *
 * @brief Class ike_sa_t. An object of this type is managed by an
 * ike_sa_manager_t object and represents an IKE_SA
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

#ifndef IKE_SA_H_
#define IKE_SA_H_

#include "types.h"
#include "message.h"
#include "configuration.h"
#include "ike_sa_id.h"

/**
 * @brief This class is used to represent an IKE_SA
 *
 */
typedef struct ike_sa_s ike_sa_t;

struct ike_sa_s {

	/**
	 * @brief Processes a incoming IKEv2-Message of type message_t
	 *
	 * @param this ike_sa_t object object
 	 * @param[in] message message_t object to process
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*process_message) (ike_sa_t *this,message_t *message);

	/**
	 * @brief Processes a specific configuration
	 *
	 * This function is called when a new IKE_SA is created
	 *
	 * @param this ike_sa_t-message_t object object
 	 * @param[in] message message_t object to process
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*process_configuration) (ike_sa_t *this,configuration_t *configuration);

	/**
	 * @brief Get the id of the SA
	 *
	 * @param this ike_sa_t-message_t object object
	 * @return ike_sa's ike_sa_id_t
	 */
	ike_sa_id_t* (*get_id) (ike_sa_t *this);

	/**
	 * @brief Destroys a ike_sa_t object
	 *
	 * @param this ike_sa_t object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (ike_sa_t *this);
};

/**
 * Creates an ike_sa_t object with a specific ike_sa_id_t object
 *
 * @param[in] ike_sa_id ike_sa_id_t object to associate with new IKE_SA.
 *  			 			The object is internal getting cloned
 * 			  			and so has to be destroyed by the caller.
 *
 * @warning the Content of internal ike_sa_id_t object can change over time
 * 			e.g. when a IKE_SA_INIT has been finished
 *
 * @return created ike_sa_t object
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id);

#endif /*IKE_SA_H_*/
