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
 *
 * RCSID $Id: interfaces.h,v 1.6 2006/01/06 20:24:07 as Exp $
 */

#ifndef _STARTER_INTERFACES_H_
#define _STARTER_INTERFACES_H_

#include <linux/if.h>

#include "../pluto/constants.h"

typedef struct {
    bool defined;
    char iface[IFNAMSIZ];
    ip_address addr;
    ip_address nexthop;
} defaultroute_t;

extern void starter_ifaces_init (void);
extern int starter_iface_find(char *iface, int af, ip_address *dst
    , ip_address *nh);
extern int starter_ifaces_load (char **ifaces, unsigned int omtu, bool nat_t
    , defaultroute_t *defaultroute);
extern void starter_ifaces_clear (void);
extern void get_defaultroute(defaultroute_t *defaultroute);


#endif /* _STARTER_INTERFACES_H_ */

