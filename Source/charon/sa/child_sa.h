/**
 * @file child_sa.h
 *
 * @brief Interface of child_sa_t.
 *
 */

/*
 * Copyright (C) 2005 Martin Willi
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
 * @brief Represents multiple IPsec SAs between two hosts.
 * 
 * A child_sa_t contains multiple SAs. SAs for both
 * directions are managed in one child_sa_t object, and
 * if both AH and ESP is set up, both protocols are managed
 * by one child_sa_t. This means we can have two or
 * in the AH+ESP case four IPsec-SAs in one child_sa_t.
 * 
 * The procedure for child sa setup is as follows:
 * - A gets SPIs for a proposal via child_sa_t.alloc
 * - A send the updated proposal to B
 * - B selects a suitable proposal
 * - B calls child_sa_t.add to add and update the selected proposal
 * - B sends the updated proposal to A
 * - A calls child_sa_t.update to update the already allocated SPIs with the chosen proposal
 * 
 * 
 * @b Constructors:
 *  - child_sa_create()
 * 
 * @ingroup sa
 */
struct child_sa_t {
	
	/**
	 * @brief Allocate SPIs for a given proposals.
	 * 
	 * Since the kernel manages SPIs for us, we need
	 * to allocate them. If the proposal contains more
	 * than one protocol, for each protocol an SPI is
	 * allocated. SPIs are stored internally and written
	 * back to the proposal.
	 *
	 * @param this 		calling object
	 * @param proposal	proposal for which SPIs are allocated
	 */
	status_t (*alloc)(child_sa_t *this, linked_list_t* proposals);
	
	/**
	 * @brief Install the kernel SAs for a proposal.
	 * 
	 * Since the kernel manages SPIs for us, we need
	 * to allocate them. If the proposal contains more
	 * than one protocol, for each protocol an SPI is
	 * allocated. SPIs are stored internally and written
	 * back to the proposal.
	 *
	 * @param this 		calling object
	 * @param proposal	proposal for which SPIs are allocated
	 * @param prf_plus	key material to use for key derivation
	 */
	status_t (*add)(child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus);
	
	/**
	 * @brief Install the kernel SAs for a proposal, if SPIs already allocated.
	 * 
	 * This one updates the SAs in the kernel, which are
	 * allocated via alloc, with a selected proposals.
	 *
	 * @param this 		calling object
	 * @param proposal	proposal for which SPIs are allocated
	 * @param prf_plus	key material to use for key derivation
	 */
	status_t (*update)(child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus);
	
	/**
	 * @brief Install the policies using some traffic selectors.
	 * 
	 * Spplied lists of traffic_selector_t's specify the policies
	 * to use for this child sa.
	 *
	 * @param this 		calling object
	 * @param my_ts		traffic selectors for local site
	 * @param other_ts	traffic selectors for remote site
	 * @return			SUCCESS or FAILED
	 */	
	status_t (*add_policy) (child_sa_t *this, linked_list_t *my_ts, linked_list_t *other_ts);
	
	/**
	 * @brief Destroys a child_sa.
	 *
	 * @param this 		calling object
	 */
	void (*destroy) (child_sa_t *this);
};

/**
 * @brief Constructor to create a new child_sa_t.
 * 
 * @param me			own address
 * @param other			remote address
 * @return				child_sa_t object
 * 
 * @ingroup sa
 */
child_sa_t * child_sa_create(host_t *me, host_t *other);

#endif /*_CHILD_SA_H_*/
