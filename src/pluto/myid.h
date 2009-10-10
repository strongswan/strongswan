/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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

#ifndef _MYID_H
#define _MYID_H

#include <utils/identification.h>

extern void init_myid(void);
extern void free_myid(void);

enum myid_state {
	MYID_UNKNOWN,       /* not yet figured out */
	MYID_HOSTNAME,      /* our current hostname */
	MYID_IP,            /* our default IP address */
	MYID_SPECIFIED      /* as specified by ipsec.conf */
};

extern enum myid_state myid_state;
extern identification_t* myids[MYID_SPECIFIED+1];  /* %myid */
extern void set_myid(enum myid_state s, char *);
extern void show_myid_status(void);
extern void set_myFQDN(void);

#define resolve_myid(id) ((id)->get_type(id) == ID_MYID? myids[myid_state] : (id))

#endif /* _MYID_H */
