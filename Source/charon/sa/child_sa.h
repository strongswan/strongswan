/**
 * @file child_sa.h
 *
 * @brief Interface of child_sa_t.
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


#ifndef _CHILD_SA_H_
#define _CHILD_SA_H_

#include <types.h>
#include <transforms/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>

typedef struct child_sa_t child_sa_t;

/**
 * @brief Represents a CHILD_SA between to hosts.
 * 
 * An IKE_SA must already be established.
 * 
 * @b Constructors:
 *  - child_sa_create
 * 
 * @ingroup sa
 */
struct child_sa_t {
	
	/**
	 * @brief Returns the SPI value of this CHILD_SA.
	 * 
	 * AH and ESP are using 4 byte SPI values.
	 * 
	 * @param this		calling object
	 * @return 			4 Byte SPI value
	 */
	u_int32_t (*get_spi) (child_sa_t *this);

	/**
	 * @brief Destroys a child_sa.
	 *
	 * @param this 		calling object
	 */
	void (*destroy) (child_sa_t *this);
};

/**
 * @brief Constructor to create a new CHILD_SA.
 * 
 * @param protocol_id	protocol id (AH or ESP) of CHILD_SA
 * @param prf_plus		prf_plus_t object use to derive shared secrets
 * @return				child_sa_t object
 * @ingroup sa
 */
child_sa_t * child_sa_create(protocol_id_t protocol_id, prf_plus_t *prf_plus);

/**
 * @brief Constructor to create a new CHILD_SA.
 * 
 * @param protocol_id	protocol id (AH or ESP) of CHILD_SA
 * @param prf_plus		prf_plus_t object use to derive shared secrets
 * @return				child_sa_t object
 * @ingroup sa
 */
child_sa_t * child_sa_create_with_spi(protocol_id_t protocol_id, prf_plus_t *prf_plus);

#endif /*_CHILD_SA_H_*/
