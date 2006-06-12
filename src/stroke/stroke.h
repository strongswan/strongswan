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

/**
 * Socket which is used to communicate between charon and stroke
 */
#define STROKE_SOCKET "/var/run/charon.ctl"

#define STROKE_BUF_LEN		2048

typedef struct stroke_end_t stroke_end_t;

struct stroke_end_t {
	char *id;
	char *cert;
	char *ca;
	char *address;
	char *subnet;
	int subnet_mask;
	certpolicy_t sendcert;
};

typedef struct stroke_msg_t stroke_msg_t;

/**
 * @brief A stroke message sent over the unix socket.
 */
struct stroke_msg_t {
	/* length of this message with all strings */
	u_int length;

	/* type of the message */
	enum {
		/* initiate a connection */
		STR_INITIATE,
		/* install SPD entries for a connection */
		STR_INSTALL,
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
		/* show list of locally loaded certificates */
		STR_LIST_CERTS
		/* more to come */
	} type;

	union {
		/* data for STR_INITIATE, STR_INSTALL, STR_UP, STR_DOWN, ... */
		struct {
			char *name;
		} initiate, install, terminate, status, del_conn;

		/* data for STR_ADD_CONN */
		struct {
			char *name;
			bool ikev2;
			struct {
				time_t ipsec_lifetime;
				time_t ike_lifetime;
				time_t margin;
				unsigned long tries;
				unsigned long fuzz;
			} rekey;
			stroke_end_t me, other;
		} add_conn;

		struct {
			char *context;
			char *type;
			int enable;
		} logtype;

		struct {
			char *context;
			int level;
		} loglevel;
	};
	char buffer[STROKE_BUF_LEN];
};

#endif /* STROKE_H_ */
