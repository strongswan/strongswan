/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>
 *
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
 * @defgroup eap_radius_accounting eap_radius_accounting
 * @{ @ingroup eap_radius
 */

#ifndef QUOTA_ACCOUNTING_H_
#define QUOTA_ACCOUNTING_H_

#include <bus/listeners/listener.h>
#include <collections/array.h>
#include <collections/hashtable.h>

/**
 * QUOTA accounting for IKE/IPsec.
 */
typedef struct quota_accounting_t quota_accounting_t;
struct quota_accounting_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a eap_radius_accounting_t.
	 */
	void (*destroy)(quota_accounting_t *this);
};


/**
 * Quota event types
 */
typedef enum {
	QUOTA_START = 1,
	QUOTA_STOP = 2,
	QUOTA_UPDATE = 3,
} quota_event_t;

/**
 * Usage stats for bytes and packets
 */
typedef struct {
	struct {
		u_int64_t sent;
		u_int64_t received;
	} bytes, packets;
} usage_t;

/**
 * Terminate-Cause
 */
typedef enum {
	ACCT_CAUSE_USER_REQUEST = 1,
	ACCT_CAUSE_LOST_CARRIER = 2,
	ACCT_CAUSE_LOST_SERVICE = 3,
	ACCT_CAUSE_IDLE_TIMEOUT = 4,
	ACCT_CAUSE_SESSION_TIMEOUT = 5,
	ACCT_CAUSE_ADMIN_RESET = 6,
	ACCT_CAUSE_ADMIN_REBOOT = 7,
} terminate_cause_t;

/**
 * Accounting hashtable entry with usage stats
 */
typedef struct {
	/** IKE_SA identifier this entry is stored under */
	ike_sa_id_t *id;
	/** number of sent/received octets/packets for expired SAs */
	usage_t usage;
	/** list of cached SAs, sa_entry_t (sorted by their unique ID) */
	array_t *cached;
	/** list of migrated SAs, sa_entry_t (sorted by their unique ID) */
	array_t *migrated;
	/** session creation time */
	time_t created;
	/** terminate cause */
	terminate_cause_t cause;
	/* update interval and timestamp of last update */
	struct {
		u_int32_t interval;
		time_t last;
	} update;
	/** did we send Accounting-Start */
	bool start_sent;
} quota_accounting_entry_t;


/**
 * Create a eap_radius_accounting instance.
 */
quota_accounting_t *quota_accounting_create();

#endif /** QUOTA_ACCOUNTING_H_ @}*/
