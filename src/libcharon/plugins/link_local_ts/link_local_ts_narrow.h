/*
 * Copyright (C) 2019 Tobias Brunner
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
 * @defgroup link_local_ts_narrow link_local_ts_narrow
 * @{ @ingroup link_local_ts
 */

#ifndef LINK_LOCAL_TS_NARROW_H_
#define LINK_LOCAL_TS_NARROW_H_

#include <bus/listeners/listener.h>

typedef struct link_local_ts_narrow_t link_local_ts_narrow_t;

/**
 * Listener that includes a link-local IPv6 address based on a client's assigned
 * virtual IPv6 address.
 */
struct link_local_ts_narrow_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy this instance.
	 */
	void (*destroy)(link_local_ts_narrow_t *this);
};

/**
 * Create a new instance.
 */
link_local_ts_narrow_t *link_local_ts_narrow_create();

#endif /** LINK_LOCAL_TS_NARROW_H_ @}*/
