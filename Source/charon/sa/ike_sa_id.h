/**
 * @file ike_sa_id.h
 *
 * @brief Interface of ike_sa_id_t.
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

typedef struct ike_sa_id_t ike_sa_id_t;

/**
 * @brief This class is used to identify an IKE_SA.
 *
 * An IKE_SA is identified by its initiator and responder spi's.
 * Additionaly it contains the role of the actual running IKEv2-Daemon
 * for the specific IKE_SA.
 */
struct ike_sa_id_t {

	/**
	 * @brief Sets the SPI of the responder.
	 *
	 * This function is called when a request or reply of a IKE_SA_INIT is received.
	 *
	 * @param this 				ike_sa_id_t object
	 * @param responder_spi 	SPI of responder to set
	 */
	void (*set_responder_spi) (ike_sa_id_t *this, u_int64_t responder_spi);

	/**
	 * @brief Sets the SPI of the initiator.
	 *
	 *
	 * @param this 				ike_sa_id_t object
	 * @param initiator_spi 	SPI to set
	 */
	void (*set_initiator_spi) (ike_sa_id_t *this, u_int64_t initiator_spi);

	/**
	 * @brief Returns the initiator spi.
	 *
	 * @param this 				ike_sa_id_t object
	 * @return 					spi of the initiator
	 */
	u_int64_t (*get_initiator_spi) (ike_sa_id_t *this);

	/**
	 * @brief Returns the responder spi.
	 *
	 * @param this 				ike_sa_id_t object
	 * @return 					spi of the responder
	 */
	u_int64_t (*get_responder_spi) (ike_sa_id_t *this);

	/**
	 * @brief Check if two ike_sa_ids are equal.
	 *
	 * @param this 				ike_sa_id_t object
 	 * @param other 			ike_sa_id object to check if equal
 	 * @return 					TRUE if given ike_sa_ids are equal, FALSE otherwise
	 */
	bool (*equals) (ike_sa_id_t *this, ike_sa_id_t *other);

	/**
	 * @brief Replace the values of a given ike_sa_id_t object with values.
	 * from another ike_sa_id_t object.
	 *
	 * @param this 				ike_sa_id_t object
 	 * @param other 			ike_sa_id_t object which values will be taken
	 */
	void (*replace_values) (ike_sa_id_t *this, ike_sa_id_t *other);

	/**
	 * @brief gets the initiator flag.
	 *
	 * @param this 				ike_sa_id_t object
	 * @return 					TRUE if we are the original initator
	 */
	bool (*is_initiator) (ike_sa_id_t *this);

	/**
	 * @brief switches the initiator flag.
	 * 
	 * @param this 				ike_sa_id_t object
	 * @return 					TRUE if we are the original initator after switch
	 */
	bool (*switch_initiator) (ike_sa_id_t *this);

	/**
	 * @brief Clones a given ike_sa_id_t object.
	 *
	 * @param this				ike_sa_id_t object
	 * @return 					cloned ike_sa_id
	 */
	ike_sa_id_t *(*clone) (ike_sa_id_t *this);

	/**
	 * @brief Destroys a ike_sa_id_tobject.
	 *
	 * @param this 				ike_sa_id_t object
	 */
	void (*destroy) (ike_sa_id_t *this);
};

/**
 * @brief Creates an ike_sa_id_t object with specific spi's and defined role
 *
 * @warning The initiator SPI and role is not changeable after initiating a ike_sa_id object
 * 
 * @param initiator_spi			initiators spi
 * @param responder_spi			responders spi
 * @param is_initiator			TRUE if we are the original initiator
 * @return						created ike_sa_id_t object
 */
ike_sa_id_t * ike_sa_id_create(u_int64_t initiator_spi, u_int64_t responder_spi, bool is_initiaor);

#endif /*IKE_SA_ID_H_*/
