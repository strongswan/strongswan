/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tcg_pts_attr_proto_caps tcg_pts_attr_proto_caps
 * @{ @ingroup tcg_pts_attr_proto_caps
 */

#ifndef TCG_PTS_ATTR_PROTO_CAPS_H_
#define TCG_PTS_ATTR_PROTO_CAPS_H_

typedef struct tcg_pts_attr_proto_caps_t tcg_pts_attr_proto_caps_t;
typedef enum pts_proto_caps_flag_t pts_proto_caps_flag_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Protocol Capabilities Flags
 */
enum pts_proto_caps_flag_t {
	/** XML based Evidence Support flag */
	PTS_PROTO_CAPS_XML =		(1<<0),
	/** Trusted Platform Evidence flag */
	PTS_PROTO_CAPS_T = 			(1<<1),
	/** DH Nonce Negotiation Support flag */
	PTS_PROTO_CAPS_DH = 		(1<<2),
	/** Verification Support flag */
	PTS_PROTO_CAPS_VER = 		(1<<3),
	/** Current (In-Memory) Evidence Support flag */
	PTS_PROTO_CAPS_CURRENT =	(1<<4),
};

/**
 * Class implementing the TCG PTS Protocol Capabilities Attribute
 *
 */
struct tcg_pts_attr_proto_caps_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;

	/**
	 * Get PTS procol capabilities flags
	 *
	 * @return				set of flags
	 */
	pts_proto_caps_flag_t (*get_flags)(tcg_pts_attr_proto_caps_t *this);

	/**
	 * Set PTS procol capabilities flags
	 *
	 * @param flags			set of flags
	 */
	void (*set_flags)(tcg_pts_attr_proto_caps_t *this, 
					  pts_proto_caps_flag_t flags);
	
};

/**
 * Creates an tcg_pts_attr_proto_caps_t object
 *
 * @param flags				set of flags
 */
pa_tnc_attr_t* tcg_pts_attr_proto_caps_create(pts_proto_caps_flag_t flags);

/**
 * Creates an tcg_pts_attr_proto_caps_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_proto_caps_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_PROTO_CAPS_H_ @}*/
