/*
 * initialize address structure
 * Copyright (C) 2000  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id$
 */
#include <sys/socket.h>

#include "internal.h"
#include "freeswan.h"

/*
 - initaddr - initialize ip_address from bytes
 */
err_t				/* NULL for success, else string literal */
initaddr(src, srclen, af, dst)
const unsigned char *src;
size_t srclen;
int af;				/* address family */
ip_address *dst;
{
	switch (af) {
	case AF_INET:
		if (srclen != 4)
			return "IPv4 address must be exactly 4 bytes";
		dst->u.v4.sin_family = af;
		dst->u.v4.sin_port = 0;		/* unused */
		memcpy((char *)&dst->u.v4.sin_addr.s_addr, src, srclen);
		break;
	case AF_INET6:
		if (srclen != 16)
			return "IPv6 address must be exactly 16 bytes";
		dst->u.v6.sin6_family = af;
		dst->u.v6.sin6_flowinfo = 0;		/* unused */
		dst->u.v6.sin6_port = 0;		/* unused */
		memcpy((char *)&dst->u.v6.sin6_addr, src, srclen);
		break;
	default:
		return "unknown address family in initaddr";
		break;
	}
	return NULL;
}
