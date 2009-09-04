/*
 * low-level ip_address ugliness
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
 */
#include <sys/socket.h>

#include "internal.h"
#include "freeswan.h"

/*
 - portof - get the port field of an ip_address
 */
int				/* network order */
portof(src)
const ip_address *src;
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return src->u.v4.sin_port;
		break;
	case AF_INET6:
		return src->u.v6.sin6_port;
		break;
	default:
		return -1;	/* "can't happen" */
		break;
	}
}

/*
 - setportof - set the port field of an ip_address
 */
void
setportof(port, dst)
int port;			/* network order */
ip_address *dst;
{
	switch (dst->u.v4.sin_family) {
	case AF_INET:
		dst->u.v4.sin_port = port;
		break;
	case AF_INET6:
		dst->u.v6.sin6_port = port;
		break;
	}
}

/*
 - sockaddrof - get a pointer to the sockaddr hiding inside an ip_address
 */
struct sockaddr *
sockaddrof(src)
ip_address *src;
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return (struct sockaddr *)&src->u.v4;
		break;
	case AF_INET6:
		return (struct sockaddr *)&src->u.v6;
		break;
	default:
		return NULL;	/* "can't happen" */
		break;
	}
}

/*
 - sockaddrlenof - get length of the sockaddr hiding inside an ip_address
 */
size_t				/* 0 for error */
sockaddrlenof(src)
const ip_address *src;
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return sizeof(src->u.v4);
		break;
	case AF_INET6:
		return sizeof(src->u.v6);
		break;
	default:
		return 0;
		break;
	}
}
