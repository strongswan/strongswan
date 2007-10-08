/*
 * convert binary form of subnet description to text
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
#include "internal.h"
#include "freeswan.h"

/*
 - subnettot - convert subnet to text "addr/bitcount"
 */
size_t				/* space needed for full conversion */
subnettot(sub, format, dst, dstlen)
const ip_subnet *sub;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len;
	size_t rest;
	char *p;

	switch (format) {
	case 0:
		break;
	default:
		return 0;
		break;
	}

	len = addrtot(&sub->addr, format, dst, dstlen);
	if (len < dstlen) {
		dst[len - 1] = '/';
		p = dst + len;
		rest = dstlen - len;
	} else {
		p = NULL;
		rest = 0;
	}


	len += ultoa((unsigned long)sub->maskbits, 10, p, rest);

	return len;
}
