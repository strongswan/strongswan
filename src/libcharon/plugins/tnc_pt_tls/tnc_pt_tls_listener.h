/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup tnc_pt_tls_listener tnc_pt_tls_listener
 * @{ @ingroup updown
 */

#ifndef TNC_PT_TLS_LISTENER_H_
#define TNC_PT_TLS_LISTENER_H_

#include <bus/bus.h>

#include <pt_tls_manager.h>

typedef struct tnc_pt_tls_listener_t tnc_pt_tls_listener_t;

/**
 * Listener which invokes the scripts on CHILD_SA up/down.
 */
struct tnc_pt_tls_listener_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a tnc_pt_tls_listener_t.
	 */
	void (*destroy)(tnc_pt_tls_listener_t *this);
};

/**
 * Create a tnc_pt_tls_listener instance.
 */
tnc_pt_tls_listener_t *tnc_pt_tls_listener_create(pt_tls_manager_t *mgr);

#endif /** TNC_PT_TLS_LISTENER_H_ @}*/
