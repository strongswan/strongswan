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
 * @defgroup lookip_msg lookip_msg
 * @{ @ingroup lookip
 */

#ifndef LOOKIP_MSG_H_
#define LOOKIP_MSG_H_

#define LOOKIP_SOCKET IPSEC_PIDDIR "/charon.lkp"

typedef struct lookip_request_t lookip_request_t;
typedef struct lookip_response_t lookip_response_t;

/**
 * Message type.
 *
 * The client can send a batch of request messages, containing DUMP, LOOKUP or
 * REGISTER_* messages. The server immediately starts sending responses for
 * these messages, using ENTRY or NOTIFY_* messages.
 * A client MUST send an END message to complete a batch. The server will
 * send any remaining responses, but will not accept new requests and closes
 * the connection when complete.
 */
enum {
	/** request a dump of all entries */
	LOOKIP_DUMP = 1,
	/** lookup a specific virtual IP */
	LOOKIP_LOOKUP = 2,
	/** reply message for DUMP and LOOKUP */
	LOOKIP_ENTRY = 3,
	/** register for notifications about new virtual IPs */
	LOOKIP_REGISTER_UP = 4,
	/** register for notifications about virtual IPs released */
	LOOKIP_REGISTER_DOWN = 5,
	/** notify reply message for REGISTER_UP */
	LOOKIP_NOTIFY_UP = 6,
	/** notify reply message for REGISTER_DOWN */
	LOOKIP_NOTIFY_DOWN = 7,
	/** end of request batch */
	LOOKIP_END = 8,
};

/**
 * Request message sent from client.
 *
 * Valid request message types are DUMP, LOOKUP, REGISTER_UP/DOWN and END.
 *
 * The vip field is used only in LOOKUP requests, but ignored otherwise.
 */
struct lookip_request_t {
	/** request message type */
	int type;
	/** null terminated string representation of virtual IP */
	char vip[40];
};

/**
 * Response message sent to client.
 *
 * Valid response message types are ENTRY and NOTIFY_UP/DOWN.
 */
struct lookip_response_t {
	/** response message type */
	int type;
	/** null terminated string representation of virtual IP */
	char vip[40];
	/** null terminated string representation of outer IP */
	char ip[40];
	/** null terminated peer identity */
	char id[128];
	/** null connection name */
	char name[44];
};

#endif /** LOOKIP_MSG_H_ @}*/
