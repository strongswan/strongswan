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
 * @defgroup dead_peer_notify_mail dead_peer_notify_mail
 * @{ @ingroup dead_peer_notify
 */

#ifndef DEAD_PEER_NOTIFY_MAIL_H_
#define DEAD_PEER_NOTIFY_MAIL_H_

#define MAIL_SUBJ "Subject: strongSwan notification"
#define MAIL_BODY " shut down at "
#define MAIL_SIGN "This message was sent by dead-peer-notify plugin"

typedef struct dead_peer_notify_mail_t dead_peer_notify_mail_t;

/**
 * Send email interface.
 */
struct dead_peer_notify_mail_t {

	/**
	 * Send a notification email.
	 *
	 * @param peer		peer name
	 * @param host		host address
	 */
	void (*send_mail)(dead_peer_notify_mail_t *this, const char *peer, const char *host);

	/**
	 * Destroy a dead_peer_notify_mail_t.
	 */
	void (*destroy)(dead_peer_notify_mail_t *this);
};

/**
 * Create a dead_peer_notify_mail instance.
 */
dead_peer_notify_mail_t *dead_peer_notify_mail_create();

#endif /** DEAD_PEER_NOTIFY_MAIL_H_ @}*/
