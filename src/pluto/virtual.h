/* FreeS/WAN Virtual IP Management
 * Copyright (C) 2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id$
 */

#ifndef _VIRTUAL_IP_H
#define _VIRTUAL_IP_H

extern void init_virtual_ip(const char *private_list);

extern struct virtual_t *create_virtual(const struct connection *c,
    const char *string);

extern bool is_virtual_end(const struct end *that);
extern bool is_virtual_connection(const struct connection *c);
extern bool is_virtual_net_allowed(const struct connection *c,
    const ip_subnet *peer_net, const ip_address *his_addr);

#endif /* _VIRTUAL_IP_H */

