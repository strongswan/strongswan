/*
 * convert binary form of address range to ASCII
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
 */
#include "internal.h"
#include "freeswan.h"

/*
 - rangetoa - convert address range to ASCII
 */
size_t				/* space needed for full conversion */
rangetoa(addrs, format, dst, dstlen)
struct in_addr addrs[2];
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len;
	size_t rest;
	int n;
	char *p;

	switch (format) {
	case 0:
		break;
	default:
		return 0;
		break;
	}

	len = addrtoa(addrs[0], 0, dst, dstlen);
	if (len < dstlen)
		for (p = dst + len - 1, n = 3; len < dstlen && n > 0;
								p++, len++, n--)
			*p = '.';
	else
		p = NULL;
	if (len < dstlen)
		rest = dstlen - len;
	else {
		if (dstlen > 0)
			*(dst + dstlen - 1) = '\0';
		rest = 0;
	}

	len += addrtoa(addrs[1], 0, p, rest);

	return len;
}
