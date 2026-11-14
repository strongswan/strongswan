/*
 * Copyright (C) 2026 Manuel Montesdeoca
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
 * @defgroup cfg_subnet_narrow cfg_subnet_narrow
 * @{ @ingroup cfg_subnet
 */

#ifndef CFG_SUBNET_NARROW_H_
#define CFG_SUBNET_NARROW_H_

#include <bus/listeners/listener.h>

#include "cfg_subnet_handler.h"

typedef struct cfg_subnet_narrow_t cfg_subnet_narrow_t;

/**
 * Listener that narrows the remote traffic selector of CHILD_SAs to the
 * subnets received via the INTERNAL_IP4/6_SUBNET attributes.
 */
struct cfg_subnet_narrow_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a cfg_subnet_narrow_t.
	 */
	void (*destroy)(cfg_subnet_narrow_t *this);
};

/**
 * Create a cfg_subnet_narrow instance.
 */
cfg_subnet_narrow_t *cfg_subnet_narrow_create(cfg_subnet_handler_t *handler);

#endif /** CFG_SUBNET_NARROW_H_ @}*/
