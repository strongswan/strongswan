/*
 * internal definitions for use within the library; do not export!
 * Copyright (C) 1998, 1999  Henry Spencer.
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

#ifndef ABITS
#define	ABITS	32	/* bits in an IPv4 address */
#endif

/* case-independent ASCII character equality comparison */
#define	CIEQ(c1, c2)	( ((c1)&~040) == ((c2)&~040) )

/* syntax for passthrough SA */
#ifndef PASSTHROUGHNAME
#define	PASSTHROUGHNAME	"%passthrough"
#define	PASSTHROUGH4NAME	"%passthrough4"
#define	PASSTHROUGH6NAME	"%passthrough6"
#define	PASSTHROUGHIS	"tun0@0.0.0.0"
#define	PASSTHROUGH4IS	"tun0@0.0.0.0"
#define	PASSTHROUGH6IS	"tun0@::"
#define	PASSTHROUGHTYPE	"tun"
#define	PASSTHROUGHSPI	0
#define	PASSTHROUGHDST	0
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#define	MALLOC(n)	malloc(n)
#define	FREE(p)		free(p)

