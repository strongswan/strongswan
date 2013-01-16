/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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
 * @defgroup pt_tls_dispatcher pt_tls_dispatcher
 * @{ @ingroup pt_tls
 */

#ifndef PT_TLS_DISPATCHER_H_
#define PT_TLS_DISPATCHER_H_

#include <networking/host.h>
#include <utils/identification.h>

typedef struct pt_tls_dispatcher_t pt_tls_dispatcher_t;

/**
 * PT-TLS dispatcher service, handles PT-TLS connections as a server.
 */
struct pt_tls_dispatcher_t {

	/**
	 * Dispatch and handle PT-TLS connections.
	 *
	 * This call is blocking and a thread cancellation point.
	 */
	void (*dispatch)(pt_tls_dispatcher_t *this);

	/**
	 * Destroy a pt_tls_dispatcher_t.
	 */
	void (*destroy)(pt_tls_dispatcher_t *this);
};

/**
 * Create a pt_tls_dispatcher instance.
 *
 * @param address		server address with port to listen on, gets owned
 * @param id			TLS server identity, gets owned
 * @return				dispatcher service
 */
pt_tls_dispatcher_t *pt_tls_dispatcher_create(host_t *address,
											  identification_t *id);

#endif /** PT_TLS_DISPATCHER_H_ @}*/
