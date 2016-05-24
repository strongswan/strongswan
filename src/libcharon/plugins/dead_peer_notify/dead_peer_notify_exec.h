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
 * @defgroup dead_peer_notify_exec dead_peer_notify_exec
 * @{ @ingroup dead_peer_notify
 */

#ifndef DEAD_PEER_NOTIFY_EXEC_H_
#define DEAD_PEER_NOTIFY_EXEC_H_

typedef struct dead_peer_notify_exec_t dead_peer_notify_exec_t;

/**
 * Execute command interface.
 */
struct dead_peer_notify_exec_t {

	/**
	 * Execute external command.
	 *
	 * @param peer		peer name
	 * @param host		host address
	 */
	void (*run)(dead_peer_notify_exec_t *this, const char *peer, const char *host);

	/**
	 * Destroy a dead_peer_notify_exec_t.
	 */
	void (*destroy)(dead_peer_notify_exec_t *this);
};

/**
 * Create a dead_peer_notify_exec instance.
 */
dead_peer_notify_exec_t *dead_peer_notify_exec_create();

#endif /** DEAD_PEER_NOTIFY_EXEC_H_ @}*/
