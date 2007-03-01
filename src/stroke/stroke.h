/**
 * @file stroke.h
 *
 * @brief Definition of stroke_msg_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef STROKE_H_
#define STROKE_H_

#include <sys/types.h>

/**
 * Socket which is used to communicate between charon and stroke
 */
#define STROKE_SOCKET "/var/run/charon.ctl"

#define STROKE_BUF_LEN		2048

typedef enum list_flag_t list_flag_t;

/**
 * Definition of the LIST flags, used for
 * the various stroke list* commands.
 */
enum list_flag_t {
	/** don't list anything */
	LIST_NONE =			0x0000,
	/** list all host/user certs */
	LIST_CERTS =		0x0001,
	/** list all ca certs */
	LIST_CACERTS =		0x0002,
	/** list all ocsp signer certs */
	LIST_OCSPCERTS =	0x0004,
	/** list all ca information records */
	LIST_CAINFOS =		0x0008,
	/** list all crls */
	LIST_CRLS =			0x0010,
	/** list all ocsp cache entries */
	LIST_OCSP =			0x0020,
	/** all list options */
	LIST_ALL =			0x003F,
};

typedef enum reread_flag_t reread_flag_t;

/**
 * Definition of the REREAD flags, used for
 * the various stroke reread* commands.
 */
enum reread_flag_t {
	/** don't reread anything */
	REREAD_NONE =		0x0000,
	/** reread all ca certs */
	REREAD_CACERTS =	0x0001,
	/** reread all ocsp signer certs */
	REREAD_OCSPCERTS =	0x0002,
	/** reread all crls */
	REREAD_CRLS =		0x0004,
	/** all reread options */
	REREAD_ALL =		0x0007,
};

typedef enum purge_flag_t purge_flag_t;

/**
 * Definition of the PURGE flags, currently used for
 * the stroke purgeocsp command.
 */
enum purge_flag_t {
	/** don't purge anything */
	PURGE_NONE =		0x0000,
	/** purge ocsp cache entries */
	PURGE_OCSP =		0x0001,
};

typedef struct stroke_end_t stroke_end_t;

/**
 * definition of a peer in a stroke message
 */
struct stroke_end_t {
	char *id;
	char *cert;
	char *ca;
	char *updown;
	char *address;
	char *sourceip;
	u_int8_t virtual_ip;
	char *subnet;
	int subnet_mask;
	int sendcert;
	int hostaccess;
	int tohost;
	u_int8_t protocol;
	u_int16_t port;
};

typedef struct stroke_msg_t stroke_msg_t;

/**
 * @brief A stroke message sent over the unix socket.
 */
struct stroke_msg_t {
	/* length of this message with all strings */
	u_int16_t length;

	/* type of the message */
	enum {
		/* initiate a connection */
		STR_INITIATE,
		/* install SPD entries for a policy */
		STR_ROUTE,
		/* uninstall SPD entries for a policy */
		STR_UNROUTE,
		/* add a connection */
		STR_ADD_CONN,
		/* delete a connection */
		STR_DEL_CONN,
		/* terminate connection */
		STR_TERMINATE,
		/* show connection status */
		STR_STATUS,
		/* show verbose connection status */
		STR_STATUS_ALL,
		/* add a ca information record */
		STR_ADD_CA,
		/* delete ca information record */
		STR_DEL_CA,
		/* set a log type to log/not log */
		STR_LOGLEVEL,
		/* list various objects */
		STR_LIST,
		/* reread various objects */
		STR_REREAD,
		/* purge various objects */
		STR_PURGE
		/* more to come */
	} type;
	
	/* verbosity of output returned from charon (-from -1=silent to 4=private)*/
	int output_verbosity;

	union {
		/* data for STR_INITIATE, STR_ROUTE, STR_UP, STR_DOWN, ... */
		struct {
			char *name;
		} initiate, route, unroute, terminate, status, del_conn, del_ca;

		/* data for STR_ADD_CONN */
		struct {
			char *name;
			int ikev2;
			int auth_method;
			int eap_type;
			int mode;
			struct {
				char *ike;
				char *esp;
			} algorithms;
			struct {
				int reauth;
				time_t ipsec_lifetime;
				time_t ike_lifetime;
				time_t margin;
				unsigned long tries;
				unsigned long fuzz;
			} rekey;
			struct {
				time_t delay;
				int action;
			} dpd;
			stroke_end_t me, other;
		} add_conn;

		/* data for STR_ADD_CA */
		struct {
			char *name;
			char *cacert;
			char *crluri;
			char *crluri2;
			char *ocspuri;
			char *ocspuri2;
		} add_ca;

		/* data for STR_LOGLEVEL */
		struct {
			char *type;
			int level;
		} loglevel;

		/* data for STR_LIST */
		struct {
			list_flag_t flags;
			int utc;
		} list;

		/* data for STR_REREAD */
		struct {
			reread_flag_t flags;
		} reread;

		/* data for STR_PURGE */
		struct {
			purge_flag_t flags;
		} purge;
	};
	char buffer[STROKE_BUF_LEN];
};

#endif /* STROKE_H_ */
