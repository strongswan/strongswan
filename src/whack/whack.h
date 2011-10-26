/* Structure of messages from whack to Pluto proper.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#ifndef _WHACK_H
#define _WHACK_H

#include <freeswan.h>

#include <defs.h>
#include <constants.h>

/* copy of smartcard operations, defined in smartcard.h */
#ifndef SC_OP_T
#define SC_OP_T
typedef enum {
	SC_OP_NONE =    0,
	SC_OP_ENCRYPT = 1,
	SC_OP_DECRYPT = 2,
	SC_OP_SIGN =    3,
} sc_op_t;
#endif /* SC_OP_T */

/* Since the message remains on one host, native representation is used.
 * Think of this as horizontal microcode: all selected operations are
 * to be done (in the order declared here).
 *
 * MAGIC is used to help detect version mismatches between whack and Pluto.
 * Whenever the interface (i.e. this struct) changes in form or
 * meaning, change this value (probably by changing the last number).
 *
 * If the command only requires basic actions (status or shutdown),
 * it is likely that the relevant part of the message changes less frequently.
 * Whack uses WHACK_BASIC_MAGIC in those cases.
 *
 * NOTE: no value of WHACK_BASIC_MAGIC may equal any value of WHACK_MAGIC.
 * Otherwise certain version mismatches will not be detected.
 */

#define WHACK_BASIC_MAGIC (((((('w' << 8) + 'h') << 8) + 'k') << 8) + 24)
#define WHACK_MAGIC (((((('w' << 8) + 'h') << 8) + 'k') << 8) + 30)

typedef struct whack_end whack_end_t;

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
	char *id;           /* id string (if any) -- decoded by pluto */
	char *cert;         /* path string (if any) -- loaded by pluto  */
	char *ca;           /* distinguished name string (if any) -- parsed by pluto */
	char *groups;       /* access control groups (if any) -- parsed by pluto */
	char *sourceip;		/* source IP address or pool identifier -- parsed by pluto */
	int   sourceip_mask;
	ip_address host_addr;
	ip_address host_nexthop;
	ip_address host_srcip;
	ip_subnet client;
	bool key_from_DNS_on_demand;
	bool has_client;
	bool has_client_wildcard;
	bool has_port_wildcard;
	bool has_srcip;
	bool has_natip;
	bool modecfg;
	bool hostaccess;
	bool allow_any;
	certpolicy_t sendcert;
	char *updown;               /* string */
	u_int16_t host_port;        /* host order */
	u_int16_t port;             /* host order */
	u_int8_t protocol;
	char *virt;
 };

typedef struct whack_message whack_message_t;

struct whack_message {
	unsigned int magic;

	/* for WHACK_STATUS: */
	bool whack_status;
	bool whack_statusall;


	/* for WHACK_SHUTDOWN */
	bool whack_shutdown;

	/* END OF BASIC COMMANDS
	 * If you change anything earlier in this struct, update WHACK_BASIC_MAGIC.
	 */

	/* name is used in connection, ca and initiate */
	size_t name_len;    /* string 1 */
	char *name;

	/* for WHACK_OPTIONS: */

	bool whack_options;

	lset_t debugging;   /* only used #ifdef DEBUG, but don't want layout to change */

	/* for WHACK_CONNECTION */

	bool whack_connection;
	bool whack_async;
	bool ikev1;

	lset_t policy;
	time_t sa_ike_life_seconds;
	time_t sa_ipsec_life_seconds;
	time_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;
	unsigned long sa_keying_tries;

	/* For DPD 3706 - Dead Peer Detection */
	time_t dpd_delay;
	time_t dpd_timeout;
	dpd_action_t dpd_action;


	/* Assign optional fixed reqid and xfrm marks to IPsec SA */
	u_int32_t reqid;
	struct {
		u_int32_t value;
		u_int32_t mask;
	} mark_in, mark_out;

	/*  note that each end contains string 2/5.id, string 3/6 cert,
	 *  and string 4/7 updown
	 */
	whack_end_t left;
	whack_end_t right;

	/* note: if the client is the gateway, the following must be equal */
	sa_family_t addr_family;    /* between gateways */
	sa_family_t tunnel_addr_family;     /* between clients */

	char *ike;          /* ike algo string (separated by commas) */
	char *pfsgroup;     /* pfsgroup will be "encapsulated" in esp string for pluto */
	char *esp;          /* esp algo string (separated by commas) */

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	char *keyid;        /* string 8 */
	enum pubkey_alg pubkey_alg;
	chunk_t keyval;     /* chunk */

	/* for WHACK_MYID: */
	bool whack_myid;
	char *myid; /* string 7 */

	/* for WHACK_ROUTE: */
	bool whack_route;

	/* for WHACK_UNROUTE: */
	bool whack_unroute;

	/* for WHACK_INITIATE: */
	bool whack_initiate;

	/* for WHACK_OPINITIATE */
	bool whack_oppo_initiate;
	ip_address oppo_my_client, oppo_peer_client;

	/* for WHACK_TERMINATE: */
	bool whack_terminate;

	/* for WHACK_DELETE: */
	bool whack_delete;

	/* for WHACK_DELETESTATE: */
	bool whack_deletestate;
	so_serial_t whack_deletestateno;

	/* for WHACK_LEASES: */
	bool whack_leases;
	char *whack_lease_ip, *whack_lease_id;

	/* for WHACK_LISTEN: */
	bool whack_listen, whack_unlisten;

	/* for WHACK_CRASH - note if a remote peer is known to have rebooted */
	bool whack_crash;
	ip_address whack_crash_peer;

	/* for WHACK_LIST */
	bool whack_utc;
	lset_t whack_list;

	/* for WHACK_PURGEOCSP */
	bool whack_purgeocsp;

	/* for WHACK_REREAD */
	u_char whack_reread;

	/* for WHACK_CA */
	bool whack_ca;
	bool whack_strict;

	char *cacert;
	char *ldaphost;
	char *ldapbase;
	char *crluri;
	char *crluri2;
	char *ocspuri;

	/* for WHACK_SC_OP */
	sc_op_t whack_sc_op;
	int inbase, outbase;
	char *sc_data;

	/* XAUTH user identity */
	char *xauth_identity;

	/* space for strings (hope there is enough room):
	 * Note that pointers don't travel on wire.
	 *  1 connection name
	 *  2 left's id
	 *  3 left's cert
	 *  4 left's ca
	 *  5 left's groups
	 *  6 left's updown
	 *  7 left's source ip
	 *  8 left's virtual ip ranges
	 *  9 right's id
	 * 10 right's cert
	 * 11 right's ca
	 * 12 right's groups
	 * 13 right's updown
	 * 14 right's source ip
	 * 15 right's virtual ip ranges
	 * 16 keyid
	 * 17 myid
	 * 18 cacert
	 * 19 ldaphost
	 * 20 ldapbase
	 * 21 crluri
	 * 22 crluri2
	 * 23 ocspuri
	 * 24 ike
	 * 25 esp
	 * 26 smartcard data
	 * 27 whack leases ip argument
	 * 28 whack leases id argument
	 * 29 xauth identity
	 * plus keyval (limit: 8K bits + overhead), a chunk.
	 */
	size_t str_size;
	char string[2048];
};

/* Codes for status messages returned to whack.
 * These are 3 digit decimal numerals.  The structure
 * is inspired by section 4.2 of RFC959 (FTP).
 * Since these will end up as the exit status of whack, they
 * must be less than 256.
 * NOTE: ipsec_auto(8) knows about some of these numbers -- change carefully.
 */
enum rc_type {
	RC_COMMENT,         /* non-commital utterance (does not affect exit status) */
	RC_WHACK_PROBLEM,   /* whack-detected problem */
	RC_LOG,             /* message aimed at log (does not affect exit status) */
	RC_LOG_SERIOUS,     /* serious message aimed at log (does not affect exit status) */
	RC_SUCCESS,         /* success (exit status 0) */

	/* failure, but not definitive */

	RC_RETRANSMISSION = 10,

	/* improper request */

	RC_DUPNAME = 20,    /* attempt to reuse a connection name */
	RC_UNKNOWN_NAME,    /* connection name unknown or state number */
	RC_ORIENT,          /* cannot orient connection: neither end is us */
	RC_CLASH,           /* clash between two Road Warrior connections OVERLOADED */
	RC_DEAF,            /* need --listen before --initiate */
	RC_ROUTE,           /* cannot route */
	RC_RTBUSY,          /* cannot unroute: route busy */
	RC_BADID,           /* malformed --id */
	RC_NOKEY,           /* no key found through DNS */
	RC_NOPEERIP,        /* cannot initiate when peer IP is unknown */
	RC_INITSHUNT,       /* cannot initiate a shunt-oly connection */
	RC_WILDCARD,        /* cannot initiate when ID has wildcards */
	RC_NOVALIDPIN,      /* cannot initiate without valid PIN */

	/* permanent failure */

	RC_BADWHACKMESSAGE = 30,
	RC_NORETRANSMISSION,
	RC_INTERNALERR,
	RC_OPPOFAILURE,     /* Opportunism failed */

	/* entry of secrets */
	RC_ENTERSECRET = 40,

	/* progress: start of range for successful state transition.
	 * Actual value is RC_NEW_STATE plus the new state code.
	 */
	RC_NEW_STATE = 100,

	/* start of range for notification.
	 * Actual value is RC_NOTIFICATION plus code for notification
	 * that should be generated by this Pluto.
	 */
	RC_NOTIFICATION = 200       /* as per IKE notification messages */
};

/* options of whack --list*** command */

#define LIST_NONE       0x0000  /* don't list anything */
#define LIST_ALGS       0x0001  /* list all registered IKE algorithms */
#define LIST_PUBKEYS    0x0002  /* list all public keys */
#define LIST_CERTS      0x0004  /* list all host/user certs */
#define LIST_CACERTS    0x0008  /* list all ca certs */
#define LIST_ACERTS     0x0010  /* list all attribute certs */
#define LIST_AACERTS    0x0020  /* list all aa certs */
#define LIST_OCSPCERTS  0x0040  /* list all ocsp certs */
#define LIST_GROUPS     0x0080  /* list all access control groups */
#define LIST_CAINFOS    0x0100  /* list all ca information records */
#define LIST_CRLS       0x0200  /* list all crls */
#define LIST_OCSP       0x0400  /* list all ocsp cache entries */
#define LIST_CARDS      0x0800  /* list all smartcard records */
#define LIST_PLUGINS    0x1000  /* list all plugins with dependencies */

#define LIST_ALL        LRANGES(LIST_ALGS, LIST_PLUGINS) /* all list options */

/* options of whack --reread*** command */

#define REREAD_NONE       0x00  /* don't reread anything */
#define REREAD_SECRETS    0x01  /* reread /etc/ipsec.secrets */
#define REREAD_CACERTS    0x02  /* reread certs in /etc/ipsec.d/cacerts */
#define REREAD_AACERTS    0x04  /* reread certs in /etc/ipsec.d/aacerts */
#define REREAD_OCSPCERTS  0x08  /* reread certs in /etc/ipsec.d/ocspcerts */
#define REREAD_ACERTS     0x10  /* reread certs in /etc/ipsec.d/acerts */
#define REREAD_CRLS       0x20  /* reread crls in /etc/ipsec.d/crls */

#define REREAD_ALL      LRANGES(REREAD_SECRETS, REREAD_CRLS)  /* all reread options */

#endif /* _WHACK_H */
