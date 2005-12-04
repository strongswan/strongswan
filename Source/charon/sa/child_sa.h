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


#ifndef CHILD_SA_H_
#define CHILD_SA_H_

#include <types.h>
#include <transforms/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>

typedef struct child_sa_t child_sa_t;

/**
 * @brief 
 * @ingroup sa
 */
struct child_sa_t {
	
	u_int32_t (*get_spi) (child_sa_t *this);

	/**
	 * @brief Destroys a child_sa.
	 *
	 * @param this 				child_sa_t object
	 */
	void (*destroy) (child_sa_t *this);
};

/**
 * @brief 
 * 
 * @ingroup sa
 */
child_sa_t * child_sa_create(protocol_id_t protocol_id, prf_plus_t *prf_plus);

#endif /*CHILD_SA_H_*/
