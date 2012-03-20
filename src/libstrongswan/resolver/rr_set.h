/*
 * Copyright (C) 2012 Reto Guadagnini
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

/**
 * @defgroup rr_set rr_set
 * @{ @ingroup resolver
 */

#ifndef RR_SET_H_
#define RR_SET_H_

typedef struct rr_set_t rr_set_t;

#include <library.h>
#include <collections/enumerator.h>

/**
 * A set of DNS Resource Records.
 *
 * Represents a RRset as defined in RFC 2181. This RRset consists of a set of
 * Resource Records with the same label, class and type but different data.
 *
 * The DNSSEC signature Resource Records (RRSIGs) which sign the RRs of this set
 * are also part of an object of this type.
 */
struct rr_set_t {

	/**
	 * Create an enumerator over all Resource Records of this RRset.
	 *
	 * @note The enumerator's position is invalid before the first call
	 * to enumerate().
	 *
	 * @return			enumerator over Resource Records
	 */
	enumerator_t *(*create_rr_enumerator)(rr_set_t *this);

	/**
	 * Create an enumerator over all RRSIGs of this RRset
	 *
	 * @note The enumerator's position is invalid before the first call
	 * to enumerate().
	 *
	 * @return			enumerator over RRSIG Resource Records,
	 * 					NULL if there are no RRSIGs for this RRset
	 */
	enumerator_t *(*create_rrsig_enumerator)(rr_set_t *this);

	/**
	 * Destroy this RRset with all its Resource Records.
	 */
	void (*destroy) (rr_set_t *this);
};

#endif /** RR_SET_H_ @}*/
