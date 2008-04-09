/* strongSwan IPsec starter comparison functions
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
 * RCSID $Id$
 */

#include <string.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"

#include "confread.h"
#include "args.h"
#include "interfaces.h"
#include "cmp.h"

#define VARCMP(obj) if (c1->obj != c2->obj) return FALSE
#define ADDCMP(obj) if (!sameaddr(&c1->obj,&c2->obj)) return FALSE
#define SUBCMP(obj) if (!samesubnet(&c1->obj,&c2->obj)) return FALSE
#define STRCMP(obj) if (strcmp(c1->obj,c2->obj)) return FALSE

static bool
starter_cmp_end(starter_end_t *c1, starter_end_t *c2)
{
    if ((c1 == NULL) || (c2 == NULL))
	return FALSE;

    if (c2->dns_failed)
    {
	c2->addr = c1->addr;
    }
    else
    {
	ADDCMP(addr);
    }
    ADDCMP(nexthop);
    STRCMP(srcip);
    SUBCMP(subnet);
    VARCMP(has_client);
    VARCMP(has_client_wildcard);
    VARCMP(has_port_wildcard);
    VARCMP(modecfg);
    VARCMP(port);
    VARCMP(protocol);

    return cmp_args(KW_END_FIRST, KW_END_LAST, (char *)c1, (char *)c2);
 }

bool
starter_cmp_conn(starter_conn_t *c1, starter_conn_t *c2)
{
    if ((c1 == NULL) || (c2 == NULL))
	return FALSE;

    VARCMP(policy);
    VARCMP(addr_family);
    VARCMP(tunnel_addr_family);

    if (!starter_cmp_end(&c1->left, &c2->left))
	return FALSE;
    if (!starter_cmp_end(&c1->right, &c2->right))
	return FALSE;

    return cmp_args(KW_CONN_NAME, KW_CONN_LAST, (char *)c1, (char *)c2);
}

bool
starter_cmp_ca(starter_ca_t *c1, starter_ca_t *c2)
{
    if (c1 ==  NULL || c2 == NULL)
	return FALSE;

    return cmp_args(KW_CA_NAME, KW_CA_LAST, (char *)c1, (char *)c2);
}

bool
starter_cmp_klips(starter_config_t *c1, starter_config_t *c2)
{
    if ((c1 == NULL) || (c2 == NULL))
	return FALSE;

    return cmp_args(KW_KLIPS_FIRST, KW_KLIPS_LAST, (char *)c1, (char *)c2);
}

bool
starter_cmp_pluto(starter_config_t *c1, starter_config_t *c2)
{
    if ((c1 == NULL) || (c2 == NULL))
	return FALSE;

    return cmp_args(KW_PLUTO_FIRST, KW_PLUTO_LAST, (char *)c1, (char *)c2);
}

bool
starter_cmp_defaultroute(defaultroute_t *d1, defaultroute_t *d2)
{
    if ((d1 == NULL) || (d2 == NULL))
	return FALSE;
    return memcmp(d1, d2, sizeof(defaultroute_t)) == 0;
}
