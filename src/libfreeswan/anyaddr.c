/*
 * special addresses
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

/* these are mostly fallbacks for the no-IPv6-support-in-library case */
#ifndef IN6ADDR_ANY_INIT
#define	IN6ADDR_ANY_INIT	{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }}
#endif
#ifndef IN6ADDR_LOOPBACK_INIT
#define	IN6ADDR_LOOPBACK_INIT	{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}
#endif

static struct in6_addr v6any = IN6ADDR_ANY_INIT;
static struct in6_addr v6loop = IN6ADDR_LOOPBACK_INIT;

/*
 - anyaddr - initialize to the any-address value
 */
err_t				/* NULL for success, else string literal */
anyaddr(af, dst)
int af;				/* address family */
ip_address *dst;
{
	uint32_t v4any = htonl(INADDR_ANY);

	switch (af) {
	case AF_INET:
		return initaddr((unsigned char *)&v4any, sizeof(v4any), af, dst);
		break;
	case AF_INET6:
		return initaddr((unsigned char *)&v6any, sizeof(v6any), af, dst);
		break;
	default:
		return "unknown address family in anyaddr/unspecaddr";
		break;
	}
}

/*
 - unspecaddr - initialize to the unspecified-address value
 */
err_t				/* NULL for success, else string literal */
unspecaddr(af, dst)
int af;				/* address family */
ip_address *dst;
{
	return anyaddr(af, dst);
}

/*
 - loopbackaddr - initialize to the loopback-address value
 */
err_t				/* NULL for success, else string literal */
loopbackaddr(af, dst)
int af;				/* address family */
ip_address *dst;
{
	uint32_t v4loop = htonl(INADDR_LOOPBACK);

	switch (af) {
	case AF_INET:
		return initaddr((unsigned char *)&v4loop, sizeof(v4loop), af, dst);
		break;
	case AF_INET6:
		return initaddr((unsigned char *)&v6loop, sizeof(v6loop), af, dst);
		break;
	default:
		return "unknown address family in loopbackaddr";
		break;
	}
}

/*
 - isanyaddr - test for the any-address value
 */
int
isanyaddr(src)
const ip_address *src;
{
	uint32_t v4any = htonl(INADDR_ANY);
	int cmp;

	switch (src->u.v4.sin_family) {
	case AF_INET:
		cmp = memcmp(&src->u.v4.sin_addr.s_addr, &v4any, sizeof(v4any));
		break;
	case AF_INET6:
		cmp = memcmp(&src->u.v6.sin6_addr, &v6any, sizeof(v6any));
		break;
	default:
		return 0;
		break;
	}

	return (cmp == 0) ? 1 : 0;
}

/*
 - isunspecaddr - test for the unspecified-address value
 */
int
isunspecaddr(src)
const ip_address *src;
{
	return isanyaddr(src);
}

/*
 - isloopbackaddr - test for the loopback-address value
 */
int
isloopbackaddr(src)
const ip_address *src;
{
	uint32_t v4loop = htonl(INADDR_LOOPBACK);
	int cmp;

	switch (src->u.v4.sin_family) {
	case AF_INET:
		cmp = memcmp(&src->u.v4.sin_addr.s_addr, &v4loop, sizeof(v4loop));
		break;
	case AF_INET6:
		cmp = memcmp(&src->u.v6.sin6_addr, &v6loop, sizeof(v6loop));
		break;
	default:
		return 0;
		break;
	}

	return (cmp == 0) ? 1 : 0;
}
