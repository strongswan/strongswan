/*
 * Copyright (C) 2014 Andreas Steffen
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
 * @defgroup tcg_seg_attr_seg_env tcg_seg_attr_seg_env
 * @{ @ingroup tcg_attr
 */

#ifndef TCG_SEG_ATTR_SEG_ENV_H_
#define TCG_SEG_ATTR_SEG_ENV_H_

typedef struct tcg_seg_attr_seg_env_t tcg_seg_attr_seg_env_t;

#include "tcg/tcg_attr.h"

#define TCG_SEG_ATTR_SEG_ENV_HEADER		4

/**
 * Class implementing the TCG Segmentation Envelope Attribute
 */
struct tcg_seg_attr_seg_env_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;

};

/**
 * Creates an tcg_seg_attr_seg_env_t object
 *
 * @param max_attr_size		Maximum IF-M attribute size in octets
 * @param max_seg_size		Maximum IF-M attribute segment size in octets
 * @param request			TRUE for a request, FALSE for a response
 */
pa_tnc_attr_t* tcg_seg_attr_seg_env_create(chunk_t segment, uint8_t flags);

/**
 * Creates an tcg_seg_attr_seg_env_t object from received data
 *
 * @param value				unparsed attribute value
 * @param request			TRUE for a request, FALSE for a response
 */
pa_tnc_attr_t* tcg_seg_attr_seg_env_create_from_data(chunk_t value);

#endif /** TCG_SEG_ATTR_SEG_ENV_H_ @}*/
