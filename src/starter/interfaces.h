/* strongSwan IPsec interfaces management
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef _STARTER_INTERFACES_H_
#define _STARTER_INTERFACES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include "../pluto/constants.h"

typedef struct {
	bool defined;
	char iface[IFNAMSIZ];
	ip_address addr;
	ip_address nexthop;
} defaultroute_t;

extern void get_defaultroute(defaultroute_t *defaultroute);


#endif /* _STARTER_INTERFACES_H_ */

