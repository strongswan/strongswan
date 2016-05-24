/* vim: set ts=4 sw=4 noexpandtab: */
/*
 * Copyright (C) 2015 Pavel Balaev.
 * Copyright (C) 2015 InfoTeCS JSC.
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
 * @defgroup dead_peer_notify_listener dead_peer_notify_listener
 * @{ @ingroup dead_peer_notify
 */

#ifndef DEAD_PEER_NOTIFY_LISTENER_H_
#define DEAD_PEER_NOTIFY_LISTENER_H_

#include <bus/listeners/listener.h>
#include "dead_peer_notify_mail.h"
#include "dead_peer_notify_exec.h"

typedef struct dead_peer_notify_listener_t dead_peer_notify_listener_t;

/**
 * Listener catching bus alerts.
 */
struct dead_peer_notify_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a dead_peer_notify_listener_t.
	 */
	void (*destroy)(dead_peer_notify_listener_t *this);
};

/**
 * Create a dead_peer_notify_listener instance.
 */
dead_peer_notify_listener_t *dead_peer_notify_listener_create(dead_peer_notify_mail_t *m,
															  dead_peer_notify_exec_t *s);

#endif /** DEAD_PEER_NOTIFY_LISTENER_H_ @}*/
