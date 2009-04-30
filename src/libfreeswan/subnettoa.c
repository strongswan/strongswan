/*
 * convert binary form of subnet description to ASCII
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
 - subnettoa - convert address and mask to ASCII "addr/mask"
 * Output expresses the mask as a bit count if possible, else dotted decimal.
 */
size_t				/* space needed for full conversion */
subnettoa(addr, mask, format, dst, dstlen)
struct in_addr addr;
struct in_addr mask;
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

	len = addrtoa(addr, 0, dst, dstlen);
	if (len < dstlen) {
		dst[len - 1] = '/';
		p = dst + len;
		rest = dstlen - len;
	} else {
		p = NULL;
		rest = 0;
	}

	n = masktobits(mask);
	if (n >= 0)
		len += ultoa((unsigned long)n, 10, p, rest);
	else
		len += addrtoa(mask, 0, p, rest);

	return len;
}
