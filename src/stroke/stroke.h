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
	LIST_NONE = 	0x0000,
	/** list all host/user certs */
	LIST_CERTS =	0x0001,
	/** list all ca certs */
	LIST_CACERTS =	0x0002,
	/** list all crls */
	LIST_CRLS =		0x0004,
	/** all list options */
	LIST_ALL =		0x0007,
};

typedef enum reread_flag_t reread_flag_t;

/**
 * Definition of the REREAD flags, used for
 * the various stroke reread* commands.
 */
enum reread_flag_t {
	/** don't reread anything */
	REREAD_NONE = 		0x0000,
	/** reread all ca certs */
	REREAD_CACERTS = 	0x0001,
	/** reread all crls */
	REREAD_CRLS = 		0x0002,
	/** all reread options */
	REREAD_ALL = 		0x0003,
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
	char *subnet;
	int subnet_mask;
	int sendcert;
	bool hostaccess;
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
		/* set a log type to log/not log */
		STR_LOGTYPE,
		/* set the verbosity of a logging context */
		STR_LOGLEVEL,
		/* list various objects */
		STR_LIST,
		/* reread various objects */
		STR_REREAD
		/* more to come */
	} type;

	union {
		/* data for STR_INITIATE, STR_ROUTE, STR_UP, STR_DOWN, ... */
		struct {
			char *name;
		} initiate, route, unroute, terminate, status, del_conn;

		/* data for STR_ADD_CONN */
		struct {
			char *name;
			bool ikev2;
			int auth_method;
			struct {
				char *ike;
				char *esp;
			} algorithms;
			struct {
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

		/* data for STR_LOGTYPE */
		struct {
			char *context;
			char *type;
			int enable;
		} logtype;

		/* data for STR_LOGLEVEL */
		struct {
			char *context;
			int level;
		} loglevel;

		/* data for STR_LIST */
		struct {
			list_flag_t flags;
			bool  utc;
		} list;

		/* data for STR_REREAD */
		struct {
			reread_flag_t flags;
		} reread;

	};
	char buffer[STROKE_BUF_LEN];
};

#endif /* STROKE_H_ */
